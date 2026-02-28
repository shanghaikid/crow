//! Utility functions for formatting network data in the TUI.

/// Format bytes per second into a human-readable rate string.
pub fn format_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1.0 {
        "0 B/s".to_string()
    } else if bytes_per_sec < 1024.0 {
        format!("{:.0} B/s", bytes_per_sec)
    } else if bytes_per_sec < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", bytes_per_sec / 1024.0)
    } else if bytes_per_sec < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} MB/s", bytes_per_sec / (1024.0 * 1024.0))
    } else {
        format!(
            "{:.1} GB/s",
            bytes_per_sec / (1024.0 * 1024.0 * 1024.0)
        )
    }
}

/// Format a byte count into a human-readable string.
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Format a duration since an instant into a human-readable "ago" string.
pub fn format_age(secs: u64) -> String {
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else {
        format!("{}h ago", secs / 3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_rate() {
        assert_eq!(format_rate(0.0), "0 B/s");
        assert_eq!(format_rate(512.0), "512 B/s");
        assert_eq!(format_rate(1536.0), "1.5 KB/s");
        assert_eq!(format_rate(2.5 * 1024.0 * 1024.0), "2.5 MB/s");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
    }

    #[test]
    fn test_format_age() {
        assert_eq!(format_age(5), "5s ago");
        assert_eq!(format_age(120), "2m ago");
        assert_eq!(format_age(7200), "2h ago");
    }
}
