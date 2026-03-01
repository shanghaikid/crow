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

use ring::aead::{self, Aad, Nonce, UnboundKey, LessSafeKey};
use ring::hkdf::{Salt, Prk, HKDF_SHA256, KeyType};

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
            let udp_payload = udp.payload();
            let plen = udp_payload.len() as u32;
            // Try QUIC first
            if let Some(sni) = parse_quic_sni(udp_payload) {
                (Protocol::Quic, udp.get_source(), udp.get_destination(), plen, None, Some(format!("QUIC -> {}", sni)))
            } else if is_quic_packet(udp_payload) {
                (Protocol::Quic, udp.get_source(), udp.get_destination(), plen, None, Some("QUIC".to_string()))
            } else {
                let dns = parse_dns_if_applicable(
                    udp.get_source(),
                    udp.get_destination(),
                    udp_payload,
                );
                let info = dns.as_ref().map(|d| format!("DNS {} -> {} addr", d.query_name, d.resolved_ips.len()));
                (Protocol::Udp, udp.get_source(), udp.get_destination(), plen, dns, info)
            }
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

/// Parse TLS ClientHello to extract SNI hostname (with TLS record header).
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
    // Strip TLS record header (5 bytes) and pass raw handshake to helper
    parse_client_hello_sni(&data[5..])
}

/// Parse a raw TLS ClientHello handshake message (starting at handshake type byte)
/// to extract the SNI hostname. Used by both TLS and QUIC paths.
fn parse_client_hello_sni(data: &[u8]) -> Option<String> {
    // handshake_type(1) + length(3) + client version(2) + random(32) = 38
    if data.len() < 38 {
        return None;
    }
    if data[0] != 0x01 {
        return None;
    }
    let mut pos = 38;
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

// --- QUIC Initial packet decryption and SNI extraction ---

/// QUIC v1 initial salt (RFC 9001 §5.2)
const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC v2 initial salt (RFC 9369)
const QUIC_V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
];

/// Known QUIC versions
fn is_known_quic_version(v: u32) -> bool {
    matches!(v, 0x00000001 | 0x6b3343cf | 0xff000000..=0xffffffff)
}

/// Read a QUIC variable-length integer (RFC 9000 §16)
fn read_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos >= data.len() {
        return None;
    }
    let first = data[*pos];
    let len = 1 << (first >> 6);
    if *pos + len > data.len() {
        return None;
    }
    let mut val = (first & 0x3f) as u64;
    for i in 1..len {
        val = (val << 8) | data[*pos + i] as u64;
    }
    *pos += len;
    Some(val)
}

/// Check if a UDP payload looks like a QUIC packet (long header with known version).
fn is_quic_packet(payload: &[u8]) -> bool {
    if payload.len() < 5 {
        return false;
    }
    // Long header: form bit (bit 7) = 1
    if payload[0] & 0x80 == 0 {
        // Short header — could still be QUIC but we can't easily identify it
        // without connection context. Check for common short header patterns:
        // fixed bit (bit 6) should be 1 for QUIC v1
        return payload[0] & 0x40 != 0 && payload.len() >= 20;
    }
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    is_known_quic_version(version)
}

/// Helper for HKDF-Expand-Label (TLS 1.3 style, used by QUIC).
struct HkdfLabel;

impl HkdfLabel {
    fn expand(prk: &Prk, label: &[u8], length: usize) -> Option<Vec<u8>> {
        // Build the HkdfLabel structure:
        // uint16 length
        // opaque label<7..255> = "tls13 " + label
        // opaque context<0..255> = ""
        let tls_label = [b"tls13 ", label].concat();
        let mut hkdf_label = Vec::with_capacity(2 + 1 + tls_label.len() + 1);
        hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
        hkdf_label.push(tls_label.len() as u8);
        hkdf_label.extend_from_slice(&tls_label);
        hkdf_label.push(0); // empty context

        struct MyKeyType(usize);
        impl KeyType for MyKeyType {
            fn len(&self) -> usize { self.0 }
        }

        let info = [&hkdf_label[..]];
        let okm = prk.expand(&info, MyKeyType(length)).ok()?;
        let mut out = vec![0u8; length];
        okm.fill(&mut out).ok()?;
        Some(out)
    }
}

/// Try to parse a QUIC Initial packet and extract the SNI from the ClientHello.
fn parse_quic_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 5 {
        return None;
    }

    let first_byte = payload[0];
    // Must be long header (form bit=1) and fixed bit=1
    if first_byte & 0xc0 != 0xc0 {
        return None;
    }
    // Packet type: Initial = 0b00 for v1, 0b01 for v2
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);

    let (salt, expected_type_bits) = match version {
        0x00000001 => (&QUIC_V1_SALT, 0u8),
        0x6b3343cf => (&QUIC_V2_SALT, 1u8),
        _ => return None,
    };

    let packet_type = (first_byte & 0x30) >> 4;
    if packet_type != expected_type_bits {
        return None;
    }

    let mut pos = 5;

    // DCID length + DCID
    if pos >= payload.len() { return None; }
    let dcid_len = payload[pos] as usize;
    pos += 1;
    if pos + dcid_len > payload.len() { return None; }
    let dcid = &payload[pos..pos + dcid_len];
    pos += dcid_len;

    // SCID length + SCID
    if pos >= payload.len() { return None; }
    let scid_len = payload[pos] as usize;
    pos += 1;
    pos += scid_len;
    if pos > payload.len() { return None; }

    // Token length (varint) + token
    let token_len = read_varint(payload, &mut pos)? as usize;
    pos += token_len;
    if pos > payload.len() { return None; }

    // Payload length (varint)
    let pkt_payload_len = read_varint(payload, &mut pos)? as usize;
    if pos + pkt_payload_len > payload.len() { return None; }

    // Remember the packet number offset
    let pn_offset = pos;

    // --- Derive initial keys from DCID ---
    let salt = Salt::new(HKDF_SHA256, salt);
    let initial_secret = salt.extract(dcid);

    let client_secret = HkdfLabel::expand(&initial_secret, b"client in", 32)?;
    let client_prk = Prk::new_less_safe(HKDF_SHA256, &client_secret);

    let key_bytes = HkdfLabel::expand(&client_prk, b"quic key", 16)?;
    let iv_bytes = HkdfLabel::expand(&client_prk, b"quic iv", 12)?;
    let hp_key_bytes = HkdfLabel::expand(&client_prk, b"quic hp", 16)?;

    // --- Remove header protection ---
    // Sample starts at pn_offset + 4 (assuming 4-byte packet number initially)
    let sample_offset = pn_offset + 4;
    if sample_offset + 16 > payload.len() { return None; }
    let sample = &payload[sample_offset..sample_offset + 16];

    // AES-ECB encrypt the sample with hp_key to get mask
    let hp_key = ring::aead::quic::HeaderProtectionKey::new(
        &ring::aead::quic::AES_128,
        &hp_key_bytes,
    ).ok()?;
    let mask = hp_key.new_mask(sample.try_into().ok()?).ok()?;

    // Apply mask to first byte and packet number bytes
    let mut header = payload[..pos + pkt_payload_len].to_vec();
    // Unmask the first byte to determine packet number length
    header[0] ^= mask[0] & 0x0f; // long header: lower 4 bits
    let pn_len = (header[0] & 0x03) as usize + 1;

    // Unmask packet number bytes
    for i in 0..pn_len {
        if pn_offset + i >= header.len() { return None; }
        header[pn_offset + i] ^= mask[1 + i];
    }

    // Read packet number
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        pn = (pn << 8) | header[pn_offset + i] as u64;
    }

    // --- Decrypt payload ---
    // Build nonce: iv XOR padded packet number
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&iv_bytes);
    let pn_be = pn.to_be_bytes(); // 8 bytes
    for i in 0..8 {
        nonce_bytes[12 - 8 + i] ^= pn_be[i];
    }
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // The ciphertext starts after the packet number
    let ciphertext_start = pn_offset + pn_len;
    let ciphertext_end = pn_offset + pkt_payload_len;
    if ciphertext_start >= ciphertext_end { return None; }

    let mut ciphertext = header[ciphertext_start..ciphertext_end].to_vec();

    // AAD is the header up to (but not including) the ciphertext
    let aad = &header[..ciphertext_start];

    let aead_key = UnboundKey::new(&aead::AES_128_GCM, &key_bytes).ok()?;
    let opening_key = LessSafeKey::new(aead_key);
    let plaintext = opening_key.open_in_place(nonce, Aad::from(aad), &mut ciphertext).ok()?;

    // --- Find CRYPTO frame (type 0x06) ---
    extract_sni_from_crypto_frames(plaintext)
}

/// Search decrypted QUIC payload for CRYPTO frames and extract SNI.
fn extract_sni_from_crypto_frames(plaintext: &[u8]) -> Option<String> {
    let mut fpos = 0;
    while fpos < plaintext.len() {
        let frame_type = read_varint(plaintext, &mut fpos)?;
        match frame_type {
            0x00 => {
                // PADDING frame, skip
                continue;
            }
            0x01 => {
                // PING frame, no payload
                continue;
            }
            0x06 => {
                // CRYPTO frame: offset(varint) + length(varint) + data
                let _offset = read_varint(plaintext, &mut fpos)?;
                let crypto_len = read_varint(plaintext, &mut fpos)? as usize;
                if fpos + crypto_len > plaintext.len() { return None; }
                let crypto_data = &plaintext[fpos..fpos + crypto_len];
                // crypto_data is a TLS handshake message (ClientHello)
                if let Some(sni) = parse_client_hello_sni(crypto_data) {
                    return Some(sni);
                }
                fpos += crypto_len;
            }
            0x02 | 0x03 => {
                // ACK frame — skip
                // Largest Acknowledged (varint) + ACK Delay (varint) + ACK Range Count (varint) + First ACK Range (varint)
                let _largest = read_varint(plaintext, &mut fpos)?;
                let _delay = read_varint(plaintext, &mut fpos)?;
                let range_count = read_varint(plaintext, &mut fpos)? as usize;
                let _first_range = read_varint(plaintext, &mut fpos)?;
                for _ in 0..range_count {
                    let _gap = read_varint(plaintext, &mut fpos)?;
                    let _ack_range = read_varint(plaintext, &mut fpos)?;
                }
                if frame_type == 0x03 {
                    // ACK_ECN: ECT(0), ECT(1), ECN-CE counts
                    let _ect0 = read_varint(plaintext, &mut fpos)?;
                    let _ect1 = read_varint(plaintext, &mut fpos)?;
                    let _ecn_ce = read_varint(plaintext, &mut fpos)?;
                }
            }
            _ => {
                // Unknown frame type, can't parse further
                return None;
            }
        }
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

    #[test]
    fn test_read_varint_1byte() {
        let data = [0x25]; // 0x25 = 37
        let mut pos = 0;
        assert_eq!(read_varint(&data, &mut pos), Some(37));
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_read_varint_2byte() {
        let data = [0x7b, 0xbd]; // 2-byte encoding: 0x3bbd = 15293
        let mut pos = 0;
        assert_eq!(read_varint(&data, &mut pos), Some(15293));
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_read_varint_empty() {
        let data = [];
        let mut pos = 0;
        assert_eq!(read_varint(&data, &mut pos), None);
    }

    #[test]
    fn test_is_quic_packet_too_short() {
        assert!(!is_quic_packet(&[]));
        assert!(!is_quic_packet(&[0xc0, 0x00, 0x00]));
    }

    #[test]
    fn test_is_quic_packet_valid_v1() {
        // Long header with QUIC v1 version
        let mut pkt = vec![0xc0]; // form=1, fixed=1
        pkt.extend_from_slice(&0x00000001u32.to_be_bytes()); // version
        pkt.extend_from_slice(&[0; 50]); // padding
        assert!(is_quic_packet(&pkt));
    }

    #[test]
    fn test_is_quic_packet_not_quic() {
        // Long header with unknown version
        let mut pkt = vec![0xc0];
        pkt.extend_from_slice(&0x12345678u32.to_be_bytes());
        pkt.extend_from_slice(&[0; 50]);
        assert!(!is_quic_packet(&pkt));
    }

    #[test]
    fn test_parse_quic_sni_too_short() {
        assert!(parse_quic_sni(&[]).is_none());
        assert!(parse_quic_sni(&[0xc0, 0x00]).is_none());
    }

    #[test]
    fn test_parse_quic_sni_not_initial() {
        // Long header, v1, but type = Handshake (0b10) not Initial (0b00)
        let mut pkt = vec![0xe0]; // 0b1110_0000: form=1, fixed=1, type=0b10
        pkt.extend_from_slice(&0x00000001u32.to_be_bytes());
        pkt.extend_from_slice(&[0; 50]);
        assert!(parse_quic_sni(&pkt).is_none());
    }

    #[test]
    fn test_parse_client_hello_sni_extracts_hostname() {
        // Build a minimal ClientHello handshake message
        let hostname = b"example.com";
        // SNI extension data
        let mut sni_ext = Vec::new();
        let sni_list_len = (hostname.len() + 3) as u16;
        sni_ext.extend_from_slice(&sni_list_len.to_be_bytes()); // SNI list length
        sni_ext.push(0x00); // host name type
        sni_ext.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(hostname);

        // Extensions
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // SNI extension type
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        // ClientHello body (after handshake header)
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session ID length = 0
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(1); // compression methods length
        body.push(0); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        // Handshake message: type(1) + length(3) + body
        let mut ch = Vec::new();
        ch.push(0x01); // ClientHello
        let body_len = body.len() as u32;
        ch.push((body_len >> 16) as u8);
        ch.push((body_len >> 8) as u8);
        ch.push(body_len as u8);
        ch.extend_from_slice(&body);

        assert_eq!(parse_client_hello_sni(&ch), Some("example.com".to_string()));
    }

    #[test]
    fn test_protocols_compatible() {
        // This tests the logic used in aggregate/mod.rs
        assert!(Protocol::Quic != Protocol::Udp); // They're different variants
        assert!(Protocol::Tcp != Protocol::Udp);
    }
}
