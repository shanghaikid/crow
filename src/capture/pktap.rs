//! PKTAP header definition and parsing for macOS.
//!
//! macOS's pktap pseudo-interface tags every captured packet with PID and
//! process name directly in the packet header, enabling per-packet process
//! attribution without lsof or proc_pidinfo lookups.

use std::ffi::CStr;

/// Interface name size: IF_NAMESIZE(16) + 8
const PKTAP_IFXNAMESIZE: usize = 24;

/// Max process name length (MAXCOMLEN on macOS) + null terminator
const PKTAP_COMM_SIZE: usize = 17;

/// DLT_PKTAP on macOS (equals DLT_USER2 = 149)
pub const DLT_PKTAP: i32 = 149;

/// Packet data follows the header.
pub const PTH_TYPE_PACKET: u32 = 1;

// Direction flags
const PTH_FLAG_DIR_IN: u32 = 0x01;
#[cfg(test)]
const PTH_FLAG_DIR_OUT: u32 = 0x02;

/// Parsed information from a PKTAP header.
#[derive(Debug)]
#[allow(dead_code)]
pub struct PktapInfo {
    /// Total header length (variable, use this to find the inner packet)
    pub header_len: u32,
    /// DLT of the encapsulated packet (e.g. DLT_EN10MB=1, DLT_RAW=12)
    pub inner_dlt: u32,
    /// Interface name (e.g. "en0")
    pub ifname: String,
    /// Direction flags
    pub flags: u32,
    /// Protocol family (AF_INET=2, AF_INET6=30)
    pub protocol_family: u32,
    /// Link-layer header bytes before the network header
    pub frame_pre_length: u32,
    /// Process ID
    pub pid: u32,
    /// Process name
    pub proc_name: String,
}

impl PktapInfo {
    /// Whether this packet is inbound.
    pub fn is_inbound(&self) -> bool {
        self.flags & PTH_FLAG_DIR_IN != 0
    }
}

/// Parse a PKTAP header from raw bytes captured via libpcap on a pktap interface.
///
/// Returns None if the data is too short or the header type indicates no packet follows.
pub fn parse_pktap_header(data: &[u8]) -> Option<PktapInfo> {
    // Minimum header: we need at least the fixed fields up through pth_comm
    // pth_length(4) + pth_type_next(4) + pth_dlt(4) + pth_ifname(24) +
    // pth_flags(4) + pth_protocol_family(4) + pth_frame_pre_length(4) +
    // pth_frame_post_length(4) + pth_pid(4) + pth_comm(17) = 73 bytes minimum
    if data.len() < 73 {
        return None;
    }

    let header_len = u32::from_ne_bytes(data[0..4].try_into().ok()?);
    let type_next = u32::from_ne_bytes(data[4..8].try_into().ok()?);
    let inner_dlt = u32::from_ne_bytes(data[8..12].try_into().ok()?);

    // Only process if actual packet data follows
    if type_next != PTH_TYPE_PACKET {
        return None;
    }

    if (header_len as usize) > data.len() {
        return None;
    }

    let ifname = extract_cstr(&data[12..12 + PKTAP_IFXNAMESIZE]);
    let flags = u32::from_ne_bytes(data[36..40].try_into().ok()?);
    let protocol_family = u32::from_ne_bytes(data[40..44].try_into().ok()?);
    let frame_pre_length = u32::from_ne_bytes(data[44..48].try_into().ok()?);
    // pth_frame_post_length at 48..52 (skip)
    let pid = i32::from_ne_bytes(data[52..56].try_into().ok()?) as u32;
    let proc_name = extract_cstr(&data[56..56 + PKTAP_COMM_SIZE]);

    Some(PktapInfo {
        header_len,
        inner_dlt,
        ifname,
        flags,
        protocol_family,
        frame_pre_length,
        pid,
        proc_name,
    })
}

/// Extract a C string from a fixed-size buffer.
fn extract_cstr(buf: &[u8]) -> String {
    CStr::from_bytes_until_nul(buf)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pktap_header(pid: i32, name: &str, flags: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 108]; // typical v1 header size

        // pth_length
        buf[0..4].copy_from_slice(&108u32.to_ne_bytes());
        // pth_type_next = PTH_TYPE_PACKET
        buf[4..8].copy_from_slice(&PTH_TYPE_PACKET.to_ne_bytes());
        // pth_dlt = 1 (DLT_EN10MB)
        buf[8..12].copy_from_slice(&1u32.to_ne_bytes());
        // pth_ifname = "en0"
        buf[12] = b'e';
        buf[13] = b'n';
        buf[14] = b'0';
        // pth_flags
        buf[36..40].copy_from_slice(&flags.to_ne_bytes());
        // pth_protocol_family = AF_INET (2)
        buf[40..44].copy_from_slice(&2u32.to_ne_bytes());
        // pth_frame_pre_length = 14 (ethernet)
        buf[44..48].copy_from_slice(&14u32.to_ne_bytes());
        // pth_pid
        buf[52..56].copy_from_slice(&pid.to_ne_bytes());
        // pth_comm
        let name_bytes = name.as_bytes();
        let len = name_bytes.len().min(PKTAP_COMM_SIZE - 1);
        buf[56..56 + len].copy_from_slice(&name_bytes[..len]);

        buf
    }

    #[test]
    fn test_parse_valid_header() {
        let data = make_pktap_header(1234, "curl", PTH_FLAG_DIR_OUT);
        let info = parse_pktap_header(&data).unwrap();
        assert_eq!(info.pid, 1234);
        assert_eq!(info.proc_name, "curl");
        assert!(!info.is_inbound());
        assert_eq!(info.ifname, "en0");
        assert_eq!(info.header_len, 108);
        assert_eq!(info.protocol_family, 2); // AF_INET
    }

    #[test]
    fn test_parse_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_pktap_header(&data).is_none());
    }

    #[test]
    fn test_parse_no_packet() {
        let mut data = make_pktap_header(1, "test", 0);
        // Set type_next to PTH_TYPE_NONE (0)
        data[4..8].copy_from_slice(&0u32.to_ne_bytes());
        assert!(parse_pktap_header(&data).is_none());
    }
}
