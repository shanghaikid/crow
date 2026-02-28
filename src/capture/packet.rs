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
use crate::capture::pktap::{PktapInfo, PTH_FLAG_DIR_IN};

/// AF_INET on macOS
const AF_INET: u32 = 2;
/// AF_INET6 on macOS
const AF_INET6: u32 = 30;

/// DLT_RAW (raw IP, no link-layer header)
const DLT_RAW: u32 = 12;

/// Parse a captured packet (with PKTAP header already stripped) into a PacketEvent.
pub fn parse_packet(pktap: &PktapInfo, inner_data: &[u8], now: Instant) -> Option<PacketEvent> {
    let direction = if pktap.flags & PTH_FLAG_DIR_IN != 0 {
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
    Some((
        IpAddr::V4(ipv4.get_source()),
        IpAddr::V4(ipv4.get_destination()),
        ipv4.get_next_level_protocol(),
        // Return a sub-slice from the original data for the payload
        // Ipv4Packet::payload() returns the correct slice
        &data[ipv4.get_header_length() as usize * 4..],
    ))
}

/// Extract IP header fields from an IPv6 packet.
fn parse_ip6_header(data: &[u8]) -> Option<(IpAddr, IpAddr, pnet_packet::ip::IpNextHeaderProtocol, &[u8])> {
    let ipv6 = Ipv6Packet::new(data)?;
    Some((
        IpAddr::V6(ipv6.get_source()),
        IpAddr::V6(ipv6.get_destination()),
        ipv6.get_next_header(),
        // IPv6 fixed header is 40 bytes
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
    let (protocol, src_port, dst_port, transport_payload_len, dns_info) = match proto {
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(payload)?;
            let plen = tcp.payload().len() as u32;
            (Protocol::Tcp, tcp.get_source(), tcp.get_destination(), plen, None)
        }
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(payload)?;
            let plen = udp.payload().len() as u32;
            let dns = parse_dns_if_applicable(
                udp.get_source(),
                udp.get_destination(),
                udp.payload(),
            );
            (Protocol::Udp, udp.get_source(), udp.get_destination(), plen, dns)
        }
        IpNextHeaderProtocols::Icmp | IpNextHeaderProtocols::Icmpv6 => {
            (Protocol::Icmp, 0, 0, payload.len() as u32, None)
        }
        other => (Protocol::Other(other.0), 0, 0, payload.len() as u32, None),
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
    })
}

/// If a UDP packet is from port 53, try to parse it as a DNS response.
fn parse_dns_if_applicable(src_port: u16, dst_port: u16, payload: &[u8]) -> Option<DnsInfo> {
    if src_port != 53 && dst_port != 53 {
        return None;
    }
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
