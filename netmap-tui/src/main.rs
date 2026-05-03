//! netmap - network topology mapper

mod app;
mod scan;
mod ui;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ipnetwork::Ipv4Network;
use netmap_core::config::Config;
use netmap_core::daemon::change_detect;
use netmap_core::discovery::{arp, engine::{self, ScanConfig}};
use netmap_core::export;
use netmap_core::fingerprint::mac_vendor::OuiDatabase;
use netmap_core::model::events::{EventKind, EventLogEntry};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use app::{App, ScanStatus};
use scan::{ScanContext, ScanEvent};

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ExportFormat {
    Dot,
    Json,
}

#[derive(Parser)]
#[command(name = "netmap", about = "network topology mapper")]
struct Args {
    #[arg(short, long)]
    interface: Option<String>,

    #[arg(short, long)]
    cidr: Option<Ipv4Network>,

    #[arg(short, long, default_value = "3")]
    timeout: u64,

    #[arg(long)]
    oui: Option<PathBuf>,

    #[arg(short, long, help = "rescan continuously")]
    daemon: bool,

    #[arg(long, default_value = "30", help = "rescan interval in seconds (daemon mode)")]
    interval: u64,

    #[arg(long, help = "append events as json lines to this file")]
    log: Option<PathBuf>,

    #[arg(long, help = "load config from this toml file")]
    config: Option<PathBuf>,

    #[arg(long, help = "run a single scan and exit (no tui)")]
    once: bool,

    #[arg(long, help = "skip port scan and service id (faster)")]
    no_fingerprint: bool,

    #[arg(long, value_enum, help = "after scan write topology to file (use with --export-path)")]
    export: Option<ExportFormat>,

    #[arg(long, help = "where to write exported topology")]
    export_path: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let cfg = load_config(&args.config);

    let iface_name = args
        .interface
        .clone()
        .or_else(|| cfg.as_ref().and_then(|c| c.interface.clone()));

    let iface = match iface_name {
        Some(name) => arp::get_interface(&name)?,
        None => arp::get_default_interface()?,
    };

    let cidr = match args.cidr {
        Some(c) => c,
        None => {
            let cfg_cidr = cfg.as_ref().and_then(|c| c.cidr.clone());
            match cfg_cidr {
                Some(s) => s.parse().context("invalid cidr in config")?,
                None => iface
                    .ips
                    .iter()
                    .find_map(|net| match net {
                        ipnetwork::IpNetwork::V4(v4) => Some(*v4),
                        _ => None,
                    })
                    .context("no ipv4 network on interface")?,
            }
        }
    };

    let oui_path = args
        .oui
        .clone()
        .or_else(|| cfg.as_ref().and_then(|c| c.oui_path.as_ref().map(PathBuf::from)));
    let oui_db = load_oui(&oui_path).map(Arc::new);

    let targets: Vec<_> = cidr
        .iter()
        .filter(|ip| *ip != cidr.network() && *ip != cidr.broadcast())
        .collect();

    let mac_str = iface
        .mac
        .map(|m| m.to_string())
        .unwrap_or_else(|| "??".into());
    let iface_label = iface.name.clone();

    let mut scan_config = ScanConfig::default();
    scan_config.arp_timeout = Duration::from_secs(args.timeout);
    scan_config.icmp_timeout = Duration::from_secs(args.timeout);
    if args.no_fingerprint {
        scan_config.fingerprint = false;
    }
    if let Some(c) = cfg.as_ref() {
        if let Some(t) = c.traceroute_target.as_ref() {
            scan_config.traceroute_target = t.parse().ok();
        }
        if let Some(fp) = c.fingerprint {
            scan_config.fingerprint = fp;
        }
    }

    let ctx = Arc::new(ScanContext {
        interface: iface,
        targets,
        oui_db: oui_db.clone(),
        config: scan_config,
    });

    if args.once {
        return run_once(&ctx, &args);
    }

    let log_path = args
        .log
        .clone()
        .or_else(|| cfg.as_ref().and_then(|c| c.log_path.as_ref().map(PathBuf::from)));
    let mut log_writer = open_log(&log_path);

    let interval = if args.daemon {
        args.interval
    } else if let Some(c) = cfg.as_ref() {
        c.daemon_interval_secs.unwrap_or(args.interval)
    } else {
        args.interval
    };

    let (tx, rx) = mpsc::channel::<ScanEvent>();
    let mut app = App::new(iface_label, mac_str, cidr.to_string(), args.daemon, interval);

    scan::trigger(ctx.clone(), tx.clone());

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_tui(
        &mut terminal,
        &mut app,
        &ctx,
        &tx,
        &rx,
        log_writer.as_mut(),
        &args,
    );

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_once(ctx: &Arc<ScanContext>, args: &Args) -> Result<()> {
    let oui_ref = ctx.oui_db.as_deref();
    let result = engine::full_scan(&ctx.interface, &ctx.targets, oui_ref, &ctx.config)?;

    println!(
        "scanned {} hosts in {:.1}s  ·  arp: {}  ·  icmp: {}  ·  trace: {} hops",
        ctx.targets.len(),
        result.duration.as_secs_f64(),
        result.arp_found,
        result.icmp_found,
        result.trace_hops
    );

    println!();
    println!(
        "  {:<18} {:<20} {:<24} {:<8} {}",
        "IP", "MAC", "VENDOR", "RTT", "OS"
    );
    for d in &result.topology.devices {
        let mac = d
            .mac
            .map(|m| m.to_string())
            .unwrap_or_else(|| "—".into());
        let vendor = d.vendor.as_deref().unwrap_or("—");
        let rtt = d
            .rtt
            .map(|r| format!("{:.1}ms", r.as_secs_f64() * 1000.0))
            .unwrap_or_else(|| "—".into());
        let os = d
            .os
            .as_ref()
            .map(|o| o.family.as_str())
            .unwrap_or("—");
        println!(
            "  {:<18} {:<20} {:<24} {:<8} {}",
            d.ip, mac, vendor, rtt, os
        );
    }

    if let (Some(fmt), Some(path)) = (args.export, args.export_path.as_ref()) {
        let body = match fmt {
            ExportFormat::Dot => export::to_dot(&result.topology),
            ExportFormat::Json => export::to_json(&result.topology),
        };
        std::fs::write(path, body)?;
        println!("\nwrote {}", path.display());
    }

    Ok(())
}

fn run_tui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    ctx: &Arc<ScanContext>,
    tx: &mpsc::Sender<ScanEvent>,
    rx: &mpsc::Receiver<ScanEvent>,
    mut log: Option<&mut std::fs::File>,
    args: &Args,
) -> Result<()> {
    let mut last_scan_instant: Option<Instant> = None;

    loop {
        while let Ok(evt) = rx.try_recv() {
            match evt {
                ScanEvent::Started => app.status = ScanStatus::Scanning(chrono::Utc::now()),
                ScanEvent::Completed(result) => {
                    let events = if app.scan_count > 0 {
                        change_detect::diff(&app.topology, &result.topology)
                    } else {
                        result
                            .topology
                            .devices
                            .iter()
                            .map(|d| EventKind::DeviceAdded {
                                ip: d.ip,
                                vendor: d.vendor.clone(),
                            })
                            .collect()
                    };

                    for kind in events {
                        let entry = EventLogEntry::now(kind);
                        write_log(log.as_deref_mut(), &entry);
                        app.push_event(entry);
                    }

                    let scan_event = EventLogEntry::now(EventKind::ScanCompleted {
                        device_count: result.topology.devices.len(),
                        duration_ms: result.duration.as_millis() as u64,
                    });
                    write_log(log.as_deref_mut(), &scan_event);
                    app.push_event(scan_event);

                    if let (Some(fmt), Some(path)) = (args.export, args.export_path.as_ref()) {
                        let body = match fmt {
                            ExportFormat::Dot => export::to_dot(&result.topology),
                            ExportFormat::Json => export::to_json(&result.topology),
                        };
                        let _ = std::fs::write(path, body);
                    }

                    app.topology = result.topology;
                    app.last_scan = Some(chrono::Utc::now());
                    last_scan_instant = Some(Instant::now());
                    app.scan_count += 1;
                    app.status = ScanStatus::Idle;
                    let len = app.devices().len();
                    if len > 0 && app.selected >= len {
                        app.selected = len - 1;
                    }
                    app.error = None;
                }
                ScanEvent::Failed(e) => {
                    let entry = EventLogEntry::now(EventKind::Error {
                        message: e.clone(),
                    });
                    write_log(log.as_deref_mut(), &entry);
                    app.push_event(entry);
                    app.error = Some(e);
                    app.status = ScanStatus::Idle;
                    last_scan_instant = Some(Instant::now());
                }
            }
        }

        if app.daemon_mode && matches!(app.status, ScanStatus::Idle) {
            if let Some(last) = last_scan_instant {
                if last.elapsed() >= Duration::from_secs(app.daemon_interval_secs) {
                    scan::trigger(ctx.clone(), tx.clone());
                }
            }
        }

        terminal.draw(|f| ui::draw(f, app))?;

        if event::poll(Duration::from_millis(150))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.should_quit = true
                        }
                        KeyCode::Char('r') => {
                            if matches!(app.status, ScanStatus::Idle) {
                                scan::trigger(ctx.clone(), tx.clone());
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => app.select_next(),
                        KeyCode::Up | KeyCode::Char('k') => app.select_prev(),
                        KeyCode::Tab => app.toggle_view(),
                        _ => {}
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

fn load_config(custom: &Option<PathBuf>) -> Option<Config> {
    let path = custom.clone().or_else(Config::default_path)?;
    Config::load(&path).ok()
}

fn open_log(path: &Option<PathBuf>) -> Option<std::fs::File> {
    let p = path.as_ref()?;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)
        .ok()
}

fn write_log(file: Option<&mut std::fs::File>, entry: &EventLogEntry) {
    let Some(f) = file else { return };
    let line = format!(
        "{{\"ts\":\"{}\",\"tag\":\"{}\",\"msg\":\"{}\"}}",
        entry.timestamp.to_rfc3339(),
        entry.kind.tag(),
        entry.kind.message().replace('"', "\\\"")
    );
    let _ = writeln!(f, "{}", line);
}

fn load_oui(custom_path: &Option<PathBuf>) -> Option<OuiDatabase> {
    let candidates = match custom_path {
        Some(p) => vec![p.clone()],
        None => {
            let exe = std::env::current_exe().ok()?;
            let exe_dir = exe.parent()?;
            vec![
                PathBuf::from("data/oui.csv"),
                exe_dir.join("../../data/oui.csv"),
                exe_dir.join("data/oui.csv"),
            ]
        }
    };

    for path in &candidates {
        if let Ok(db) = OuiDatabase::load(path) {
            return Some(db);
        }
    }
    None
}
