//! Every log line, ours or a dependency's, goes through tracing to one place: formatted as
//! `<time> <LEVEL> <message>`, RPC URLs redacted, printed to stderr, and kept for `start`'s /logs.

use std::collections::VecDeque;
use std::fmt;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, MakeWriter};
use tracing_subscriber::registry::LookupSpan;

/// Lines kept for /logs.
const LOG_CAP: usize = 5000;
const REDACTED: &str = "***";

/// Fixed size ring of recent log lines.
pub struct LogRing {
    lines: VecDeque<String>,
    cap: usize,
}

impl LogRing {
    pub const fn new(cap: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            cap,
        }
    }

    pub fn push(&mut self, line: String) {
        if self.lines.len() == self.cap {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }

    /// The newest n lines, oldest first.
    pub fn last(&self, n: usize) -> Vec<String> {
        let skip = self.lines.len().saturating_sub(n);
        self.lines.iter().skip(skip).cloned().collect()
    }
}

pub static LOGS: Mutex<LogRing> = Mutex::new(LogRing::new(LOG_CAP));

/// Strings to blank out of every line, longest first. Set once at startup.
static SECRETS: OnceLock<Vec<String>> = OnceLock::new();

/// What to redact for these RPC URLs: each whole URL, and its path plus query, since that's
/// where hosted RPCs put the API key and errors may print a normalized host.
pub fn secrets(urls: &[String]) -> Vec<String> {
    let mut out = vec![];
    for u in urls {
        let u = u.trim().trim_end_matches('/');
        if u.is_empty() {
            continue;
        }
        out.push(u.to_string());
        let after_scheme = u.find("://").map_or(0, |i| i + 3);
        if let Some(i) = u[after_scheme..].find(['/', '?']) {
            let pq = &u[after_scheme + i..];
            // A bare "/" would blank every slash.
            if pq.len() > 1 {
                out.push(pq.to_string());
            }
        }
    }
    out.sort_by_key(|s| std::cmp::Reverse(s.len()));
    out.dedup();
    out
}

fn redact(line: &str, secrets: &[String]) -> String {
    secrets
        .iter()
        .fold(line.to_string(), |l, s| l.replace(s.as_str(), REDACTED))
}

/// Installs the global subscriber. RUST_LOG picks levels, our own lines always stay at info.
pub fn init(rpc_urls: &[String]) {
    let _ = SECRETS.set(secrets(rpc_urls));
    let mut filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "sp1_sdk=info".into());
    if !filter.contains("relayer") {
        filter.push_str(",relayer=info");
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_ansi(false)
        .event_format(Line)
        .with_writer(Tee)
        .init();
}

/// `<time> <LEVEL> <message> [fields]`, no target or spans.
struct Line;

impl<S, N> FormatEvent<S, N> for Line
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut w: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S");
        write!(w, "{ts} {} ", event.metadata().level())?;
        ctx.field_format().format_fields(w.by_ref(), event)?;
        writeln!(w)
    }
}

/// stderr and LOGS. stdout is left for data scripts parse (vkey, anchor, PV/PROOF).
struct Tee;

impl<'a> MakeWriter<'a> for Tee {
    type Writer = Tee;

    fn make_writer(&'a self) -> Tee {
        Tee
    }
}

impl Write for Tee {
    // tracing's fmt layer hands over one whole formatted event per write.
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = redact(
            &String::from_utf8_lossy(buf),
            SECRETS.get().map_or(&[], |v| v),
        );
        std::io::stderr().write_all(text.as_bytes())?;
        // A panic while holding the lock only loses log lines, so keep going.
        let mut logs = LOGS.lock().unwrap_or_else(|e| e.into_inner());
        for l in text.lines() {
            logs.push(l.to_string());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_cases() {
        let mut r = LogRing::new(3);
        assert!(r.last(5).is_empty());
        for i in 1..=5 {
            r.push(i.to_string());
        }
        let cases = [
            (0, vec![]),
            (2, vec!["4", "5"]),
            (3, vec!["3", "4", "5"]),
            (10, vec!["3", "4", "5"]),
        ];
        for (n, want) in cases {
            assert_eq!(r.last(n), want, "n={n}");
        }
    }

    #[test]
    fn redact_cases() {
        let s = secrets(&[
            "https://eth.example.com/v2/KEY123".into(),
            "http://localhost:8732/".into(),
            "https://tz.example.com?apikey=KEY456".into(),
            "".into(),
        ]);
        let cases = [
            (
                "error sending request for url (https://eth.example.com/v2/KEY123): timed out",
                "error sending request for url (***): timed out",
            ),
            // normalized or proxied host, key still in the path
            (
                "url (https://ETH.example.com:443/v2/KEY123)",
                "url (https://ETH.example.com:443***)",
            ),
            (
                "GET http://localhost:8732/chains/main/blocks/head/header: 504",
                "GET ***/chains/main/blocks/head/header: 504",
            ),
            (
                "GET https://tz.example.com/?apikey=KEY456 failed",
                "GET https://tz.example.com/*** failed",
            ),
            ("keep: client level 5", "keep: client level 5"),
        ];
        for (line, want) in cases {
            let got = redact(line, &s);
            assert_eq!(got, want);
            assert!(!got.contains("KEY"), "{got}");
        }
    }
}
