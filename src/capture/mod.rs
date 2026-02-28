pub mod packet;
pub mod pktap;

use std::sync::mpsc;
use std::time::Instant;

use anyhow::{Context, Result};
use pcap::Capture;

use crate::aggregate::PacketEvent;
use pktap::parse_pktap_header;

/// Open a PKTAP capture on all interfaces and return a handle.
pub fn open_pktap_capture() -> Result<Capture<pcap::Active>> {
    // On macOS, opening "pktap,all" captures on a virtual pktap interface
    // that aggregates traffic from all real interfaces with PID attribution.
    let cap = Capture::from_device("pktap,all")
        .context("Failed to open pktap device. Run with: sudo crow")?
        .immediate_mode(true)
        .snaplen(65535)
        .open()
        .context("Failed to activate pktap capture. Ensure BPF access.")?;

    Ok(cap)
}

/// Run the capture loop, sending PacketEvents through the channel.
/// This function blocks and should be called from a dedicated thread.
pub fn capture_loop(
    mut cap: Capture<pcap::Active>,
    tx: mpsc::Sender<PacketEvent>,
) -> Result<()> {
    loop {
        match cap.next_packet() {
            Ok(pkt) => {
                let now = Instant::now();
                let data = pkt.data;

                // Parse PKTAP header
                let pktap_info = match parse_pktap_header(data) {
                    Some(info) => info,
                    None => continue,
                };

                // Inner packet data starts after the PKTAP header
                let inner_start = pktap_info.header_len as usize;
                if inner_start >= data.len() {
                    continue;
                }
                let inner_data = &data[inner_start..];

                // Parse into PacketEvent
                if let Some(event) = packet::parse_packet(&pktap_info, inner_data, now) {
                    // If receiver hung up, exit gracefully
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
