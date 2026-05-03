//! topology export (graphviz DOT and minimal JSON)

use crate::model::link::LinkType;
use crate::model::topology::Topology;
use std::fmt::Write;

pub fn to_dot(topology: &Topology) -> String {
    let mut out = String::new();
    out.push_str("digraph netmap {\n");
    out.push_str("  rankdir=TB;\n");
    out.push_str("  node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\"];\n");
    out.push_str("  edge [color=\"#666\"];\n\n");

    for d in &topology.devices {
        let mac = d.mac.map(|m| m.to_string()).unwrap_or_default();
        let vendor = d.vendor.as_deref().unwrap_or("");
        let host = d.hostname.as_deref().unwrap_or("");
        let mut label = format!("{}\\n{}", d.ip, mac);
        if !vendor.is_empty() {
            label.push_str(&format!("\\n{}", vendor));
        }
        if !host.is_empty() {
            label.push_str(&format!("\\n{}", host));
        }

        let fill = if Some(d.id) == topology.gateway {
            "#ffe066"
        } else {
            "#cce5ff"
        };

        let _ = writeln!(
            out,
            "  \"{}\" [label=\"{}\", fillcolor=\"{}\"];",
            d.id, label, fill
        );
    }

    out.push('\n');

    for link in &topology.links {
        let style = match link.link_type {
            LinkType::Direct => "solid",
            LinkType::Routed => "dashed",
            LinkType::Wireless => "dotted",
        };
        let _ = writeln!(
            out,
            "  \"{}\" -> \"{}\" [style={}, dir=none];",
            link.source, link.target, style
        );
    }

    out.push_str("}\n");
    out
}

pub fn to_json(topology: &Topology) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"devices\": [\n");

    for (i, d) in topology.devices.iter().enumerate() {
        let mac = d.mac.map(|m| m.to_string()).unwrap_or_default();
        let vendor = d.vendor.as_deref().unwrap_or("");
        let host = d.hostname.as_deref().unwrap_or("");
        let os = d
            .os
            .as_ref()
            .map(|o| o.family.as_str())
            .unwrap_or("");

        let _ = writeln!(
            out,
            "    {{\"ip\":\"{}\",\"mac\":\"{}\",\"vendor\":\"{}\",\"hostname\":\"{}\",\"os\":\"{}\",\"ports\":[{}]}}{}",
            d.ip,
            mac,
            escape(vendor),
            escape(host),
            escape(os),
            d.open_ports
                .iter()
                .map(|p| p.port.to_string())
                .collect::<Vec<_>>()
                .join(","),
            if i + 1 < topology.devices.len() { "," } else { "" }
        );
    }

    out.push_str("  ],\n");
    out.push_str("  \"links\": [\n");

    for (i, link) in topology.links.iter().enumerate() {
        let kind = match link.link_type {
            LinkType::Direct => "direct",
            LinkType::Routed => "routed",
            LinkType::Wireless => "wireless",
        };
        let _ = writeln!(
            out,
            "    {{\"source\":\"{}\",\"target\":\"{}\",\"type\":\"{}\"}}{}",
            link.source,
            link.target,
            kind,
            if i + 1 < topology.links.len() { "," } else { "" }
        );
    }

    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
