use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Entry in the DNS cache with TTL-based expiration.
struct DnsEntry {
    hostname: String,
    inserted_at: Instant,
    ttl: Duration,
}

/// Passive DNS cache built from captured DNS response packets.
/// Maps IP addresses to hostnames observed in DNS A/AAAA responses.
pub struct DnsCache {
    entries: HashMap<IpAddr, DnsEntry>,
    default_ttl: Duration,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            default_ttl: Duration::from_secs(300), // 5 minute default TTL
        }
    }

    /// Insert a DNS mapping from a captured DNS response.
    pub fn insert(&mut self, ip: IpAddr, hostname: String, ttl_secs: Option<u32>) {
        let ttl = ttl_secs
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(self.default_ttl);
        self.entries.insert(
            ip,
            DnsEntry {
                hostname,
                inserted_at: Instant::now(),
                ttl,
            },
        );
    }

    /// Look up a hostname for an IP address. Returns None if not cached or expired.
    pub fn lookup(&self, ip: &IpAddr) -> Option<&str> {
        self.entries.get(ip).and_then(|entry| {
            if entry.inserted_at.elapsed() <= entry.ttl {
                Some(entry.hostname.as_str())
            } else {
                None
            }
        })
    }

    /// Remove expired entries.
    pub fn prune_expired(&mut self) {
        self.entries
            .retain(|_, entry| entry.inserted_at.elapsed() <= entry.ttl);
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_insert_and_lookup() {
        let mut cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(142, 250, 80, 14));
        cache.insert(ip, "google.com".to_string(), Some(60));
        assert_eq!(cache.lookup(&ip), Some("google.com"));
    }

    #[test]
    fn test_lookup_missing() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(cache.lookup(&ip), None);
    }

    #[test]
    fn test_overwrite() {
        let mut cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        cache.insert(ip, "old.example.com".to_string(), None);
        cache.insert(ip, "new.example.com".to_string(), None);
        assert_eq!(cache.lookup(&ip), Some("new.example.com"));
    }
}
