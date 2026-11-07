//! `relayer start`'s HTTP endpoints for an uptime monitor: GET /healthz, and GET /logs behind
//! KEEP_LOGS_TOKEN. Hand rolled HTTP/1.1, one request per connection, so no web framework dep.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::logs::LOGS;

const LOGS_DEFAULT: usize = 200;
const LOGS_MAX: usize = 2000;
/// Request line plus headers. A monitor's GET fits easily.
const MAX_HEAD: usize = 8192;
/// Per request, so a slow or idle client can't hold a connection open.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// What the keeper loop last saw. Written by the loop, read by /healthz, never held across await.
pub struct Health {
    pub started: Instant,
    /// end of the last tick that returned Ok
    pub last_ok: Option<Instant>,
    pub last_error: Option<String>,
    pub frozen: bool,
    pub client_level: Option<u64>,
    pub head_level: Option<i32>,
    /// trusted state age in seconds, and when it was measured
    pub age: Option<(u64, Instant)>,
}

impl Health {
    pub fn new(now: Instant) -> Self {
        Self {
            started: now,
            last_ok: None,
            last_error: None,
            frozen: false,
            client_level: None,
            head_level: None,
            age: None,
        }
    }
}

pub struct Limits {
    /// KEEP_HEALTH_MAX_AGE
    pub max_age: Duration,
    /// KEEP_HEALTH_STALE
    pub stale: Duration,
}

/// Why the keeper is unhealthy at `now`. Empty means healthy.
pub fn unhealthy(h: &Health, now: Instant, lim: &Limits) -> Vec<String> {
    let mut reasons = vec![];
    if h.last_ok.is_none() {
        reasons.push("starting".to_string());
    }
    // Also catches a hung tick, since last_ok then stops moving.
    let since = now.saturating_duration_since(h.last_ok.unwrap_or(h.started));
    if since > lim.stale {
        reasons.push(format!("no successful tick for {}s", since.as_secs()));
    }
    if h.frozen {
        reasons.push("client frozen".to_string());
    }
    if let Some(age) = trusted_age(h, now) {
        if age > lim.max_age.as_secs() {
            reasons.push(format!(
                "trusted state age {age}s over {}s",
                lim.max_age.as_secs()
            ));
        }
    }
    reasons
}

/// Trusted state age now, extrapolated from the last measurement.
fn trusted_age(h: &Health, now: Instant) -> Option<u64> {
    h.age
        .map(|(age, at)| age + now.saturating_duration_since(at).as_secs())
}

/// True if header is `Bearer <token>`. Constant time in the token's content.
pub fn token_ok(header: Option<&str>, token: &str) -> bool {
    let Some(got) = header.and_then(|h| h.strip_prefix("Bearer ")) else {
        return false;
    };
    let (a, b) = (got.as_bytes(), token.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub struct Server {
    pub health: Arc<Mutex<Health>>,
    pub limits: Limits,
    /// KEEP_LOGS_TOKEN, None disables /logs
    pub token: Option<String>,
}

/// A parsed request head.
struct Request<'a> {
    method: &'a str,
    target: &'a str,
    auth: Option<&'a str>,
}

/// Status, content type and body for a request.
fn respond(s: &Server, r: &Request, now: Instant) -> (u16, &'static str, String) {
    let not_found = (404, "text/plain", "not found\n".to_string());
    if r.method != "GET" {
        return (405, "text/plain", "method not allowed\n".to_string());
    }
    let (path, query) = r.target.split_once('?').unwrap_or((r.target, ""));
    match path {
        "/healthz" => {
            let h = s.health.lock().unwrap_or_else(|e| e.into_inner());
            let reasons = unhealthy(&h, now, &s.limits);
            let body = serde_json::json!({
                "ok": reasons.is_empty(),
                "reasons": reasons,
                "client_level": h.client_level,
                "head_level": h.head_level,
                "trusted_age_secs": trusted_age(&h, now),
                "frozen": h.frozen,
                "last_ok_tick_secs_ago": h.last_ok.map(|t| now.saturating_duration_since(t).as_secs()),
                "last_error": h.last_error,
            });
            let code = if reasons.is_empty() { 200 } else { 503 };
            (code, "application/json", format!("{body}\n"))
        }
        "/logs" => {
            let Some(token) = &s.token else {
                return not_found;
            };
            if !token_ok(r.auth, token) {
                return (401, "text/plain", "unauthorized\n".to_string());
            }
            let n = match query.split('&').find_map(|kv| kv.strip_prefix("n=")) {
                None => LOGS_DEFAULT,
                Some(v) => match v.parse::<usize>() {
                    Ok(n) => n.min(LOGS_MAX),
                    Err(_) => return (400, "text/plain", "bad n\n".to_string()),
                },
            };
            let lines = LOGS.lock().unwrap_or_else(|e| e.into_inner()).last(n);
            let mut body = lines.join("\n");
            body.push('\n');
            (200, "text/plain; charset=utf-8", body)
        }
        _ => not_found,
    }
}

/// Binds addr up front so a taken port fails startup, then serves until the task is aborted.
pub async fn start(addr: &str, s: Server) -> Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind KEEP_HTTP_ADDR {addr}"))?;
    let s = Arc::new(s);
    Ok(tokio::spawn(async move {
        loop {
            let sock = match listener.accept().await {
                Ok((sock, _)) => sock,
                Err(e) => {
                    // Usually out of fds. Back off rather than spin.
                    tracing::warn!("http accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let s = s.clone();
            tokio::spawn(async move {
                // Errors here are the client's problem (timeout, junk, hangup), not worth logging.
                let _ = tokio::time::timeout(IO_TIMEOUT, handle(sock, &s)).await;
            });
        }
    }))
}

async fn handle(mut sock: TcpStream, s: &Server) -> std::io::Result<()> {
    let mut buf = vec![0u8; MAX_HEAD];
    let mut len = 0;
    let end = loop {
        if let Some(i) = buf[..len].windows(4).position(|w| w == b"\r\n\r\n") {
            break Some(i);
        }
        if len == buf.len() {
            break None;
        }
        let n = sock.read(&mut buf[len..]).await?;
        if n == 0 {
            return Ok(());
        }
        len += n;
    };
    let (code, ctype, body) = match end.map(|i| std::str::from_utf8(&buf[..i])) {
        Some(Ok(head)) => match parse(head) {
            Some(r) => respond(s, &r, Instant::now()),
            None => (400, "text/plain", "bad request\n".to_string()),
        },
        Some(Err(_)) => (400, "text/plain", "bad request\n".to_string()),
        None => (431, "text/plain", "request head too large\n".to_string()),
    };
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        _ => "Service Unavailable",
    };
    let mut out = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        body.len()
    );
    if code == 401 {
        out.push_str("WWW-Authenticate: Bearer\r\n");
    }
    out.push_str("\r\n");
    out.push_str(&body);
    sock.write_all(out.as_bytes()).await?;
    sock.shutdown().await
}

fn parse(head: &str) -> Option<Request<'_>> {
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target, version) = (first.next()?, first.next()?, first.next()?);
    if !version.starts_with("HTTP/1.") || first.next().is_some() {
        return None;
    }
    let auth = lines.find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case("authorization").then(|| v.trim())
    });
    Some(Request {
        method,
        target,
        auth,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unhealthy_cases() {
        let t0 = Instant::now();
        let lim = Limits {
            max_age: Duration::from_secs(100),
            stale: Duration::from_secs(60),
        };
        let s = Duration::from_secs;
        let ok = |last_ok: u64, age: u64| Health {
            last_ok: Some(t0 + s(last_ok)),
            age: Some((age, t0 + s(last_ok))),
            client_level: Some(10),
            ..Health::new(t0)
        };
        let cases: Vec<(&str, Health, u64, Vec<&str>)> = vec![
            ("starting", Health::new(t0), 5, vec!["starting"]),
            (
                "never ticked ok",
                Health::new(t0),
                61,
                vec!["starting", "no successful tick for 61s"],
            ),
            ("healthy", ok(10, 20), 30, vec![]),
            (
                "stale tick",
                ok(10, 20),
                71,
                vec!["no successful tick for 61s"],
            ),
            // measured at 50s old, 51s later it's over 100
            (
                "age grows",
                ok(10, 50),
                61,
                vec!["trusted state age 101s over 100s"],
            ),
            (
                "frozen",
                Health {
                    frozen: true,
                    ..ok(10, 20)
                },
                20,
                vec!["client frozen"],
            ),
        ];
        for (name, h, at, want) in cases {
            assert_eq!(unhealthy(&h, t0 + s(at), &lim), want, "{name}");
        }
    }

    #[test]
    fn token_cases() {
        let cases = [
            (Some("Bearer s3cret"), true),
            (Some("Bearer s3cres"), false),
            (Some("Bearer s3cret2"), false),
            (Some("Bearer "), false),
            (Some("bearer s3cret"), false),
            (Some("s3cret"), false),
            (None, false),
        ];
        for (h, want) in cases {
            assert_eq!(token_ok(h, "s3cret"), want, "{h:?}");
        }
    }

    #[test]
    fn respond_cases() {
        let s = Server {
            health: Arc::new(Mutex::new(Health::new(Instant::now()))),
            limits: Limits {
                max_age: Duration::from_secs(100),
                stale: Duration::from_secs(60),
            },
            token: Some("tok".into()),
        };
        let no_token = Server { token: None, ..s };
        let get = |target, auth| Request {
            method: "GET",
            target,
            auth,
        };
        let cases = [
            (&no_token, get("/logs", Some("Bearer tok")), 404),
            (&no_token, get("/healthz", None), 503),
            (&no_token, get("/", None), 404),
            (
                &no_token,
                Request {
                    method: "POST",
                    target: "/healthz",
                    auth: None,
                },
                405,
            ),
        ];
        for (i, (srv, r, want)) in cases.iter().enumerate() {
            assert_eq!(respond(srv, r, Instant::now()).0, *want, "case {i}");
        }
        let s = Server {
            token: Some("tok".into()),
            ..no_token
        };
        let cases = [
            (get("/logs", None), 401),
            (get("/logs", Some("Bearer nope")), 401),
            (get("/logs?n=5", Some("Bearer tok")), 200),
            (get("/logs?n=x", Some("Bearer tok")), 400),
        ];
        for (i, (r, want)) in cases.iter().enumerate() {
            assert_eq!(respond(&s, r, Instant::now()).0, *want, "case {i}");
        }
    }

    #[test]
    fn parse_cases() {
        let r = parse("GET /logs?n=3 HTTP/1.1\r\nHost: x\r\nauthorization:  Bearer t ").unwrap();
        assert_eq!(
            (r.method, r.target, r.auth),
            ("GET", "/logs?n=3", Some("Bearer t"))
        );
        assert!(parse("GET /\r\n").is_none());
        assert!(parse("GET / SPDY/3").is_none());
    }
}
