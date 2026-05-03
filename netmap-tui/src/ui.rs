//! tui rendering

use crate::app::{App, ScanStatus, View};
use chrono::Utc;
use netmap_core::model::events::Severity;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Line as CanvasLine};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, TableState};
use ratatui::Frame;

pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(8),
            Constraint::Length(1),
        ])
        .split(f.area());

    draw_status(f, chunks[0], app);
    draw_main(f, chunks[1], app);
    draw_events(f, chunks[2], app);
    draw_footer(f, chunks[3], app);
}

fn draw_status(f: &mut Frame, area: Rect, app: &App) {
    let body = match &app.status {
        ScanStatus::Idle => match app.last_scan {
            Some(last) => {
                let mode = if app.daemon_mode {
                    format!("daemon ({}s)", app.daemon_interval_secs)
                } else {
                    "idle".to_string()
                };
                format!(
                    "{}  ·  last scan: {}  ·  scans: {}  ·  devices: {}",
                    mode,
                    last.format("%H:%M:%S"),
                    app.scan_count,
                    app.devices().len()
                )
            }
            None => "ready  ·  press 'r' to scan".to_string(),
        },
        ScanStatus::Scanning(start) => {
            let elapsed = (Utc::now() - *start).num_milliseconds() as f64 / 1000.0;
            format!("scanning...  ·  {:.1}s elapsed", elapsed)
        }
    };

    let title = format!(
        " netmap │ {} [{}] │ {} ",
        app.iface_name, app.iface_mac, app.cidr
    );

    let style = match &app.status {
        ScanStatus::Scanning(_) => Style::default().fg(Color::Yellow),
        ScanStatus::Idle => Style::default().fg(Color::Cyan),
    };

    let p = Paragraph::new(body)
        .block(Block::default().borders(Borders::ALL).title(title))
        .style(style);
    f.render_widget(p, area);
}

fn draw_main(f: &mut Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    match app.view {
        View::Table => draw_devices(f, chunks[0], app),
        View::Graph => draw_graph(f, chunks[0], app),
    }
    draw_detail(f, chunks[1], app);
}

fn draw_devices(f: &mut Frame, area: Rect, app: &mut App) {
    let header = Row::new(vec!["IP", "MAC", "VENDOR", "RTT"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .devices()
        .iter()
        .map(|d| {
            let mac = d
                .mac
                .map(|m| m.to_string())
                .unwrap_or_else(|| "—".into());
            let vendor = d.vendor.as_deref().unwrap_or("—").to_string();
            let rtt = d
                .rtt
                .map(|r| format!("{:.1}ms", r.as_secs_f64() * 1000.0))
                .unwrap_or_else(|| "—".into());
            Row::new(vec![d.ip.to_string(), mac, vendor, rtt])
        })
        .collect();

    let title = format!(" Devices ({}) ", app.devices().len());

    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(18),
            Constraint::Length(20),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title))
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    let mut state = TableState::default();
    if !app.devices().is_empty() {
        state.select(Some(app.selected));
    }
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_graph(f: &mut Frame, area: Rect, app: &App) {
    let topology = &app.topology;
    let selected_id = app.current_device().map(|d| d.id);
    let gateway_id = topology.gateway;

    let canvas = Canvas::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Topology ({} nodes) ", topology.devices.len())),
        )
        .marker(Marker::Braille)
        .x_bounds([-110.0, 110.0])
        .y_bounds([-110.0, 110.0])
        .paint(move |ctx| {
            for link in &topology.links {
                let p1 = topology.positions.get(&link.source);
                let p2 = topology.positions.get(&link.target);
                if let (Some(p1), Some(p2)) = (p1, p2) {
                    ctx.draw(&CanvasLine {
                        x1: p1.0,
                        y1: p1.1,
                        x2: p2.0,
                        y2: p2.1,
                        color: Color::DarkGray,
                    });
                }
            }

            ctx.layer();

            for d in &topology.devices {
                if let Some(pos) = topology.positions.get(&d.id) {
                    let is_gw = Some(d.id) == gateway_id;
                    let is_sel = Some(d.id) == selected_id;

                    let (color, marker) = if is_gw {
                        (Color::Yellow, "◆")
                    } else if is_sel {
                        (Color::Magenta, "●")
                    } else {
                        (Color::Cyan, "●")
                    };

                    ctx.print(
                        pos.0,
                        pos.1,
                        Span::styled(
                            marker,
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        ),
                    );

                    let label_color = if is_sel { Color::White } else { Color::Gray };
                    ctx.print(
                        pos.0 + 4.0,
                        pos.1,
                        Span::styled(d.ip.to_string(), Style::default().fg(label_color)),
                    );
                }
            }
        });

    f.render_widget(canvas, area);
}

fn draw_detail(f: &mut Frame, area: Rect, app: &App) {
    let lines = match app.current_device() {
        Some(d) => {
            let mac = d
                .mac
                .map(|m| m.to_string())
                .unwrap_or_else(|| "—".into());
            let vendor = d.vendor.as_deref().unwrap_or("—").to_string();
            let rtt = d
                .rtt
                .map(|r| format!("{:.1}ms", r.as_secs_f64() * 1000.0))
                .unwrap_or_else(|| "—".into());
            let host = d.hostname.as_deref().unwrap_or("—").to_string();

            let label = |s: &'static str| Span::styled(s, Style::default().fg(Color::Yellow));

            let os_str = d
                .os
                .as_ref()
                .map(|o| {
                    format!(
                        "{}  (TTL {}, {:.0}%)",
                        o.family,
                        o.ttl,
                        o.confidence * 100.0
                    )
                })
                .unwrap_or_else(|| "—".into());

            let mut lines = vec![
                Line::from(vec![label("IP:      "), Span::raw(d.ip.to_string())]),
                Line::from(vec![label("MAC:     "), Span::raw(mac)]),
                Line::from(vec![label("Vendor:  "), Span::raw(vendor)]),
                Line::from(vec![label("Host:    "), Span::raw(host)]),
                Line::from(vec![label("RTT:     "), Span::raw(rtt)]),
                Line::from(vec![label("OS:      "), Span::raw(os_str)]),
                Line::from(vec![
                    label("Type:    "),
                    Span::raw(format!("{:?}", d.device_type)),
                ]),
            ];

            if !d.open_ports.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("Open Ports ({})", d.open_ports.len()),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )));

                for p in &d.open_ports {
                    let svc = p
                        .service
                        .as_ref()
                        .map(|s| match &s.version {
                            Some(v) => format!("{}  {}", s.name, v),
                            None => s.name.clone(),
                        })
                        .unwrap_or_else(|| "—".into());
                    lines.push(Line::from(vec![
                        Span::styled(
                            format!("  {:>5}/tcp  ", p.port),
                            Style::default().fg(Color::Cyan),
                        ),
                        Span::raw(svc),
                    ]));
                }
            }

            lines
        }
        None => match &app.error {
            Some(err) => vec![
                Line::from(Span::styled(
                    "error",
                    Style::default()
                        .fg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(err.as_str()),
            ],
            None => vec![Line::from(Span::styled(
                "no device selected",
                Style::default().fg(Color::DarkGray),
            ))],
        },
    };

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Detail "),
    );
    f.render_widget(p, area);
}

fn severity_color(sev: Severity) -> Color {
    match sev {
        Severity::Info => Color::DarkGray,
        Severity::Notice => Color::Green,
        Severity::Warn => Color::Yellow,
        Severity::Error => Color::Red,
    }
}

fn draw_events(f: &mut Frame, area: Rect, app: &App) {
    let visible = (area.height.saturating_sub(2)) as usize;
    let lines: Vec<Line> = app
        .events
        .iter()
        .take(visible)
        .map(|e| {
            let color = severity_color(e.kind.severity());
            Line::from(vec![
                Span::styled(
                    e.timestamp.format("%H:%M:%S").to_string(),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw("  "),
                Span::styled(
                    e.kind.tag(),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::raw(e.kind.message()),
            ])
        })
        .collect();

    let title = format!(" Events ({}) ", app.events.len());
    let p = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(p, area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let view_label = match app.view {
        View::Table => "table",
        View::Graph => "graph",
    };
    let daemon = if app.daemon_mode { " · DAEMON" } else { "" };
    let text = format!(
        " q:quit  r:rescan  tab:view ({}){}  ↑↓/jk:select",
        view_label, daemon
    );
    let p = Paragraph::new(text).style(Style::default().fg(Color::DarkGray));
    f.render_widget(p, area);
}
