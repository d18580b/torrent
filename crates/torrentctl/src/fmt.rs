//! Numbers and times as an operator reads them.

/// `1.5 GiB`: bytes in binary units, one decimal past KiB.
pub fn bytes(n: i64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    let n = n.max(0) as f64;
    let mut value = n;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", n as i64, UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// `12.3 MiB/s`, or `—` for nothing moving.
pub fn rate(bytes_per_sec: i64) -> String {
    if bytes_per_sec <= 0 {
        "—".to_owned()
    } else {
        format!("{}/s", bytes(bytes_per_sec))
    }
}

/// `87.5%` from a 0..1 fraction.
pub fn percent(fraction: f64) -> String {
    format!("{:.1}%", (fraction.clamp(0.0, 1.0) * 100.0))
}

/// `1,234,567`.
pub fn count(n: i64) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 {
        format!("-{out}")
    } else {
        out
    }
}

/// `3h 12m`, `45s`: a duration in the two largest units that matter.
pub fn duration(secs: i64) -> String {
    let secs = secs.max(0);
    let (d, h, m, s) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    match (d, h, m) {
        (0, 0, 0) => format!("{s}s"),
        (0, 0, _) => format!("{m}m {s}s"),
        (0, _, _) => format!("{h}h {m}m"),
        _ => format!("{d}d {h}h"),
    }
}

/// A timestamp relative to `now`: `in 4m 10s`, `2h 3m ago`.
pub fn relative(at: time::OffsetDateTime, now: time::OffsetDateTime) -> String {
    let delta = (at - now).whole_seconds();
    if delta >= 0 {
        format!("in {}", duration(delta))
    } else {
        format!("{} ago", duration(-delta))
    }
}

/// An infohash shortened for a table: the first 12 hex digits.
pub fn short_hash(hex: &str) -> &str {
    &hex[..hex.len().min(12)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_read_the_way_an_operator_expects() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
        assert_eq!(rate(0), "—");
        assert_eq!(rate(2048), "2.0 KiB/s");
        assert_eq!(percent(0.875), "87.5%");
        assert_eq!(percent(2.0), "100.0%");
        assert_eq!(count(1_234_567), "1,234,567");
        assert_eq!(count(-1000), "-1,000");
        assert_eq!(count(12), "12");
        assert_eq!(duration(45), "45s");
        assert_eq!(duration(125), "2m 5s");
        assert_eq!(duration(3 * 3600 + 720), "3h 12m");
        assert_eq!(duration(2 * 86_400 + 3600), "2d 1h");
        assert_eq!(short_hash("0123456789abcdef0123"), "0123456789ab");
    }
}
