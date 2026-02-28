pub mod packet;
pub mod pktap;

use std::sync::mpsc;
use std::time::Instant;

use anyhow::{Context, Result};
use pcap::Capture;

use crate::aggregate::PacketEvent;
use pktap::parse_pktap_header;

/// The datalink mode that the capture is operating in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    /// PKTAP headers available — PID attribution per-packet.
    Pktap,
    /// Raw IP — need socket-matching for PID attribution.
    RawIp,
}

/// Open a capture on pktap,all. Tries to enable PKTAP headers for PID
/// attribution, falls back to raw IP if not supported.
pub fn open_pktap_capture() -> Result<(Capture<pcap::Active>, CaptureMode)> {
    let mut cap = Capture::from_device("pktap,all")
        .context("Failed to open pktap device. Run with: sudo crow")?
        .immediate_mode(true)
        .snaplen(65535)
        .open()
        .context("Failed to activate pktap capture. Ensure BPF access.")?;

    // Try to enable PKTAP datalink for PID attribution
    let mode = if cap.set_datalink(pcap::Linktype(pktap::DLT_PKTAP as i32)).is_ok() {
        CaptureMode::Pktap
    } else {
        // Fall back to raw IP — will use socket-matching for PID attribution
        CaptureMode::RawIp
    };

    Ok((cap, mode))
}

/// Run the capture loop, sending PacketEvents through the channel.
/// This function blocks and should be called from a dedicated thread.
pub fn capture_loop(
    mut cap: Capture<pcap::Active>,
    mode: CaptureMode,
    tx: mpsc::Sender<PacketEvent>,
) -> Result<()> {
    loop {
        match cap.next_packet() {
            Ok(pkt) => {
                let now = Instant::now();
                let data = pkt.data;

                let event = match mode {
                    CaptureMode::Pktap => parse_pktap_packet(data, now),
                    CaptureMode::RawIp => packet::parse_raw_ip(data, now),
                };

                if let Some(event) = event {
                    if tx.send(event).is_err() {
                        break;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Parse a packet with PKTAP header (PID info included).
fn parse_pktap_packet(data: &[u8], now: Instant) -> Option<PacketEvent> {
    let pktap_info = parse_pktap_header(data)?;
    let inner_start = pktap_info.header_len as usize;
    if inner_start >= data.len() {
        return None;
    }
    packet::parse_packet(&pktap_info, &data[inner_start..], now)
}
