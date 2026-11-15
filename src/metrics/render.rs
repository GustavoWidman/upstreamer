//! The text exposition format. `SERIES` is the one list of metric names, types and help
//! texts: rendering iterates it, and a test checks a scrape against it.

pub(super) struct Family {
    pub name: &'static str,
    pub kind: Kind,
    pub help: &'static str,
}

pub(super) enum Kind {
    Counter,
    Gauge,
    Histogram,
}

pub(super) const SERIES: &[Family] = &[];
