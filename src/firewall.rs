use std::collections::HashSet;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const ANCHOR_NAME: &str = "com.crow.block";

pub struct Firewall {
    blocked_ips: HashSet<IpAddr>,
    file_path: PathBuf,
}

impl Firewall {
    /// Load blocklist from disk and apply existing rules.
    pub fn load() -> Self {
        let file_path = home_dir()
            .join(".crow")
            .join("blocklist.json");

        let blocked_ips = if file_path.exists() {
            std::fs::read_to_string(&file_path)
                .ok()
                .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
                .map(|v| {
                    v.into_iter()
                        .filter_map(|s| s.parse::<IpAddr>().ok())
                        .collect()
                })
                .unwrap_or_default()
        } else {
            HashSet::new()
        };

        let fw = Firewall { blocked_ips, file_path };
        if !fw.blocked_ips.is_empty() {
            fw.apply_rules();
        }
        fw
    }

    pub fn block_ip(&mut self, ip: IpAddr) {
        if self.blocked_ips.insert(ip) {
            self.apply_rules();
            self.save();
        }
    }

    pub fn unblock_ip(&mut self, ip: IpAddr) {
        if self.blocked_ips.remove(&ip) {
            if self.blocked_ips.is_empty() {
                self.flush_rules();
            } else {
                self.apply_rules();
            }
            self.save();
        }
    }

    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        self.blocked_ips.contains(ip)
    }

    pub fn blocked_ips(&self) -> &HashSet<IpAddr> {
        &self.blocked_ips
    }

    /// Flush crow's pf anchor rules (call on exit).
    pub fn cleanup(&self) {
        self.flush_rules();
    }

    fn apply_rules(&self) {
        let mut rules = String::new();
        for ip in &self.blocked_ips {
            rules.push_str(&format!("block drop quick from any to {ip}\n"));
            rules.push_str(&format!("block drop quick from {ip} to any\n"));
        }

        let Ok(mut child) = Command::new("pfctl")
            .args(["-a", ANCHOR_NAME, "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return;
        };

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(rules.as_bytes());
        }
        let _ = child.wait();
    }

    fn flush_rules(&self) {
        let _ = Command::new("pfctl")
            .args(["-a", ANCHOR_NAME, "-F", "rules"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output();
    }

    fn save(&self) {
        if let Some(dir) = self.file_path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let ips: Vec<String> = self.blocked_ips.iter().map(|ip| ip.to_string()).collect();
        if let Ok(json) = serde_json::to_string_pretty(&ips) {
            let _ = std::fs::write(&self.file_path, json);
        }
    }
}

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}
