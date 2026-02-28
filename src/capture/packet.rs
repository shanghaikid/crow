//! Packet parsing: raw pcap data → PacketEvent.
//!
//! Supports two modes:
//! 1. PKTAP mode: PKTAP header provides PID/process name, then IP parsing
//! 2. Raw IP mode: Parse IP directly, PID=0 (resolved later via socket matching)

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;

use crate::aggregate::{Direction, DnsInfo, PacketEvent, Protocol};
use crate::capture::pktap::PktapInfo;

/// AF_INET on macOS
const AF_INET: u32 = 2;
/// AF_INET6 on macOS
const AF_INET6: u32 = 30;

/// DLT_RAW (raw IP, no link-layer header)
const DLT_RAW: u32 = 12;

/// Parse a captured packet (with PKTAP header already stripped) into a PacketEvent.
pub fn parse_packet(pktap: &PktapInfo, inner_data: &[u8], now: Instant) -> Option<PacketEvent> {
    let direction = if pktap.is_inbound() {
        Direction::Inbound
    } else {
        Direction::Outbound
    };

    // Skip link-layer header if present
    let ip_data = if pktap.inner_dlt == DLT_RAW {
        inner_data
    } else {
        let skip = pktap.frame_pre_length as usize;
        if skip >= inner_data.len() {
            return None;
        }
        &inner_data[skip..]
    };

    if ip_data.is_empty() {
        return None;
    }

    let (src_ip, dst_ip, next_proto, payload) = match pktap.protocol_family {
        AF_INET => parse_ip4_header(ip_data)?,
        AF_INET6 => parse_ip6_header(ip_data)?,
        _ => return None,
    };

    build_event(
        next_proto,
        payload,
        src_ip,
        dst_ip,
        pktap.pid,
        pktap.proc_name.clone(),
        direction,
        now,
    )
}

/// Parse a raw IP packet (DLT_RAW mode, no PKTAP header).
/// PID and process name are unknown (set to 0/""), to be resolved later.
pub fn parse_raw_ip(data: &[u8], now: Instant) -> Option<PacketEvent> {
    if data.is_empty() {
        return None;
    }

    let version = data[0] >> 4;
    let (src_ip, dst_ip, next_proto, payload) = match version {
        4 => parse_ip4_header(data)?,
        6 => parse_ip6_header(data)?,
        _ => return None,
    };

    // Direction is unknown in raw mode — will be determined by socket matching
    build_event(
        next_proto,
        payload,
        src_ip,
        dst_ip,
        0,
        String::new(),
        Direction::Outbound, // placeholder, resolved by aggregator
        now,
    )
}

/// Extract IP header fields from an IPv4 packet.
fn parse_ip4_header(data: &[u8]) -> Option<(IpAddr, IpAddr, pnet_packet::ip::IpNextHeaderProtocol, &[u8])> {
    let ipv4 = Ipv4Packet::new(data)?;
    let hdr_len = ipv4.get_header_length() as usize * 4;
    if hdr_len > data.len() {
        return None;
    }
    Some((
        IpAddr::V4(ipv4.get_source()),
        IpAddr::V4(ipv4.get_destination()),
        ipv4.get_next_level_protocol(),
        &data[hdr_len..],
    ))
}

/// Extract IP header fields from an IPv6 packet.
fn parse_ip6_header(data: &[u8]) -> Option<(IpAddr, IpAddr, pnet_packet::ip::IpNextHeaderProtocol, &[u8])> {
    let ipv6 = Ipv6Packet::new(data)?;
    if data.len() < 40 {
        return None;
    }
    Some((
        IpAddr::V6(ipv6.get_source()),
        IpAddr::V6(ipv6.get_destination()),
        ipv6.get_next_header(),
        &data[40..],
    ))
}

fn build_event(
    proto: pnet_packet::ip::IpNextHeaderProtocol,
    payload: &[u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    pid: u32,
    proc_name: String,
    direction: Direction,
    now: Instant,
) -> Option<PacketEvent> {
    let (protocol, src_port, dst_port, transport_payload_len, dns_info, protocol_info) = match proto {
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(payload)?;
            let tcp_payload = tcp.payload();
            let plen = tcp_payload.len() as u32;
            let info = parse_tls_sni(tcp_payload)
                .map(|sni| format!("TLS -> {}", sni))
                .or_else(|| parse_http_request(tcp_payload));
            (Protocol::Tcp, tcp.get_source(), tcp.get_destination(), plen, None, info)
        }
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(payload)?;
            let plen = udp.payload().len() as u32;
            let dns = parse_dns_if_applicable(
                udp.get_source(),
                udp.get_destination(),
                udp.payload(),
            );
            let info = dns.as_ref().map(|d| format!("DNS {} -> {} addr", d.query_name, d.resolved_ips.len()));
            (Protocol::Udp, udp.get_source(), udp.get_destination(), plen, dns, info)
        }
        IpNextHeaderProtocols::Icmp | IpNextHeaderProtocols::Icmpv6 => {
            (Protocol::Icmp, 0, 0, payload.len() as u32, None, None)
        }
        other => (Protocol::Other(other.0), 0, 0, payload.len() as u32, None, None),
    };

    Some(PacketEvent {
        timestamp: now,
        pid,
        proc_name,
        direction,
        protocol,
        src: SocketAddr::new(src_ip, src_port),
        dst: SocketAddr::new(dst_ip, dst_port),
        payload_len: transport_payload_len,
        dns_info,
        protocol_info,
    })
}

/// Parse TLS ClientHello to extract SNI hostname.
fn parse_tls_sni(data: &[u8]) -> Option<String> {
    // Minimum TLS record: type(1) + version(2) + length(2) + handshake_type(1) = 6
    if data.len() < 6 {
        return None;
    }
    // Content type 0x16 = Handshake
    if data[0] != 0x16 {
        return None;
    }
    // Handshake type 0x01 = ClientHello
    if data[5] != 0x01 {
        return None;
    }
    // Skip: record header(5) + handshake header(4) + client version(2) + random(32) = 43
    if data.len() < 43 {
        return None;
    }
    let mut pos = 43;
    // Session ID
    if pos >= data.len() { return None; }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;
    // Cipher suites
    if pos + 2 > data.len() { return None; }
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cs_len;
    // Compression methods
    if pos >= data.len() { return None; }
    let cm_len = data[pos] as usize;
    pos += 1 + cm_len;
    // Extensions length
    if pos + 2 > data.len() { return None; }
    let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    // Walk extensions
    while pos + 4 <= ext_end && pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0x0000 {
            // SNI extension
            // SNI list length(2) + type(1) + name length(2) = 5
            if ext_data_len >= 5 && pos + 5 <= data.len() {
                let name_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
                let name_start = pos + 5;
                if name_start + name_len <= data.len() {
                    return std::str::from_utf8(&data[name_start..name_start + name_len])
                        .ok()
                        .map(|s| s.to_string());
                }
            }
            return None;
        }
        pos += ext_data_len;
    }
    None
}

/// Parse HTTP request first line (e.g. "GET /path HTTP/1.1").
fn parse_http_request(data: &[u8]) -> Option<String> {
    // Quick check for common methods
    let prefixes: &[&[u8]] = &[b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"PATCH ", b"OPTIONS ", b"CONNECT "];
    if !prefixes.iter().any(|p| data.starts_with(p)) {
        return None;
    }
    // Find end of first line
    let end = data.iter().position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(data.len().min(256));
    let line = std::str::from_utf8(&data[..end]).ok()?;
    // Strip " HTTP/1.x" suffix for brevity
    let line = line.strip_suffix(" HTTP/1.1")
        .or_else(|| line.strip_suffix(" HTTP/1.0"))
        .or_else(|| line.strip_suffix(" HTTP/2"))
        .unwrap_or(line);
    Some(line.to_string())
}

/// If a UDP packet is from port 53, try to parse it as a DNS response.
fn parse_dns_if_applicable(src_port: u16, _dst_port: u16, payload: &[u8]) -> Option<DnsInfo> {
    if src_port != 53 {
        return None;
    }
    parse_dns_response(payload)
}

/// Parse a DNS response payload to extract hostname → IP mappings.
fn parse_dns_response(data: &[u8]) -> Option<DnsInfo> {
    let packet = dns_parser::Packet::parse(data).ok()?;

    if packet.answers.is_empty() {
        return None;
    }

    let query_name = packet
        .questions
        .first()
        .map(|q| q.qname.to_string())
        .unwrap_or_default();

    let mut resolved_ips = Vec::new();
    let mut min_ttl = None;

    for answer in &packet.answers {
        match &answer.data {
            dns_parser::RData::A(dns_parser::rdata::a::Record(ip)) => {
                resolved_ips.push(IpAddr::V4(*ip));
            }
            dns_parser::RData::AAAA(dns_parser::rdata::aaaa::Record(ip)) => {
                resolved_ips.push(IpAddr::V6(*ip));
            }
            _ => {}
        }
        let ttl = answer.ttl;
        min_ttl = Some(min_ttl.map_or(ttl, |current: u32| current.min(ttl)));
    }

    if resolved_ips.is_empty() {
        return None;
    }

    Some(DnsInfo {
        query_name,
        resolved_ips,
        ttl: min_ttl,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_response_empty() {
        assert!(parse_dns_response(&[]).is_none());
        assert!(parse_dns_response(&[0, 1, 2, 3]).is_none());
    }

    #[test]
    fn test_parse_raw_ip_empty() {
        assert!(parse_raw_ip(&[], Instant::now()).is_none());
    }

    #[test]
    fn test_parse_raw_ip_invalid_version() {
        // Version 0 is invalid
        assert!(parse_raw_ip(&[0x00, 0x00], Instant::now()).is_none());
    }
}
