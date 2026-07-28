//! API call counter. Threaded through every phase so the report can show
//! exactly how many CloudTrail events the assessment generated.

use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct Counter {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    by_action: BTreeMap<String, u32>,
    total: u32,
}

impl Counter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc(&self, action: &str) {
        let mut g = self.inner.lock().expect("counter poisoned");
        *g.by_action.entry(action.to_string()).or_insert(0) += 1;
        g.total += 1;
    }

    pub fn snapshot(&self) -> CounterSnapshot {
        let g = self.inner.lock().expect("counter poisoned");
        CounterSnapshot {
            total: g.total,
            by_action: g.by_action.clone(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CounterSnapshot {
    pub total: u32,
    pub by_action: BTreeMap<String, u32>,
}
