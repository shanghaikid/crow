mod aggregate;
mod capture;
mod process;
mod tui;

use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::thread;

use anyhow::{bail, Context, Result};
use clap::Parser;

use aggregate::AppState;
use capture::CaptureMode;

/// crow — real-time per-process network monitor for macOS
#[derive(Parser)]
#[command(name = "crow", version, about)]
struct Cli {
    /// Interface to capture on (default: pktap,all for all interfaces)
    #[arg(short, long, default_value = "pktap,all")]
    interface: String,

    /// Filter by process name (fuzzy, case-insensitive). e.g. `crow google`
    #[arg(value_name = "PROCESS")]
    process_filter: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Check BPF access
    check_bpf_access()?;

    // Shared state — apply CLI process filter if provided
    let mut app_state = AppState::new();
    if let Some(ref filter) = cli.process_filter {
        app_state.filter = Some(filter.clone());
    }
    let state = Arc::new(RwLock::new(app_state));

    // Open capture
    let (cap, mode) = if cli.interface == "pktap,all" {
        capture::open_pktap_capture()
            .context("Failed to open pktap capture")?
    } else {
        let c = pcap::Capture::from_device(cli.interface.as_str())
            .context("Failed to open capture device")?
            .immediate_mode(true)
            .snaplen(65535)
            .open()
            .context("Failed to activate capture")?;
        (c, CaptureMode::RawIp)
    };

    eprintln!("crow: capture mode = {:?}", mode);

    // Channel for PacketEvents
    let (tx, rx) = mpsc::channel();

    // Spawn capture thread
    let capture_handle = thread::Builder::new()
        .name("capture".into())
        .spawn(move || {
            if let Err(e) = capture::capture_loop(cap, mode, tx) {
                eprintln!("Capture thread error: {}", e);
            }
        })
        .context("Failed to spawn capture thread")?;

    // Spawn aggregator thread
    let agg_state = Arc::clone(&state);
    let aggregator_handle = thread::Builder::new()
        .name("aggregator".into())
        .spawn(move || {
            aggregate::aggregator_loop(rx, agg_state, mode);
        })
        .context("Failed to spawn aggregator thread")?;

    // Run TUI on the main thread (blocks until quit)
    let tui_result = tui::run_tui(state);

    // TUI exited — threads will stop when channels disconnect
    drop(capture_handle);
    drop(aggregator_handle);

    tui_result
}

/// Check if we have BPF access by trying to open /dev/bpf0.
fn check_bpf_access() -> Result<()> {
    use std::fs::File;
    match File::open("/dev/bpf0") {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            bail!(
                "crow requires BPF access to capture network traffic.\n\
                 Run with: sudo crow\n\
                 Or add your user to the 'access_bpf' group for sudo-free usage."
            );
        }
        Err(_) => {
            // /dev/bpf0 might not exist but pcap may still work
            Ok(())
        }
    }
}
