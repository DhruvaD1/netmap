//! tui application state

use chrono::{DateTime, Utc};
use netmap_core::model::device::Device;
use netmap_core::model::events::EventLogEntry;
use netmap_core::model::topology::Topology;
use std::collections::VecDeque;

const MAX_EVENTS: usize = 200;

pub struct App {
    pub topology: Topology,
    pub selected: usize,
    pub view: View,
    pub status: ScanStatus,
    pub last_scan: Option<DateTime<Utc>>,
    pub scan_count: usize,
    pub error: Option<String>,
    pub events: VecDeque<EventLogEntry>,
    pub iface_name: String,
    pub iface_mac: String,
    pub cidr: String,
    pub daemon_mode: bool,
    pub daemon_interval_secs: u64,
    pub should_quit: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum View {
    Table,
    Graph,
}

pub enum ScanStatus {
    Idle,
    Scanning(DateTime<Utc>),
}

impl App {
    pub fn new(
        iface_name: String,
        iface_mac: String,
        cidr: String,
        daemon_mode: bool,
        daemon_interval_secs: u64,
    ) -> Self {
        Self {
            topology: Topology::empty(),
            selected: 0,
            view: View::Table,
            status: ScanStatus::Idle,
            last_scan: None,
            scan_count: 0,
            error: None,
            events: VecDeque::new(),
            iface_name,
            iface_mac,
            cidr,
            daemon_mode,
            daemon_interval_secs,
            should_quit: false,
        }
    }

    pub fn devices(&self) -> &[Device] {
        &self.topology.devices
    }

    pub fn select_next(&mut self) {
        let len = self.devices().len();
        if len == 0 {
            return;
        }
        self.selected = (self.selected + 1) % len;
    }

    pub fn select_prev(&mut self) {
        let len = self.devices().len();
        if len == 0 {
            return;
        }
        self.selected = if self.selected == 0 {
            len - 1
        } else {
            self.selected - 1
        };
    }

    pub fn current_device(&self) -> Option<&Device> {
        self.devices().get(self.selected)
    }

    pub fn toggle_view(&mut self) {
        self.view = match self.view {
            View::Table => View::Graph,
            View::Graph => View::Table,
        };
    }

    pub fn push_event(&mut self, entry: EventLogEntry) {
        self.events.push_front(entry);
        while self.events.len() > MAX_EVENTS {
            self.events.pop_back();
        }
    }
}
