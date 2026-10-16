//! Optional wall-clock spans and exact wire-byte accounting. No transcript data
//! is added by profiling. Exclusive measurements subtract direct child spans.
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct Profile {
    pub measurements: Vec<Measurement>,
    stack: Vec<Active>,
}

#[derive(Debug)]
pub struct Measurement {
    pub path: String,
    pub inclusive: Duration,
    pub exclusive: Duration,
    pub inclusive_bytes: usize,
    pub exclusive_bytes: usize,
}

#[derive(Debug)]
struct Active {
    id: usize,
    start: Instant,
    position: usize,
    child_time: Duration,
    child_bytes: usize,
}

impl Profile {
    pub fn start(&mut self, name: &str, position: usize) -> usize {
        let start = Instant::now();
        let path = self.stack.last().map_or_else(
            || name.to_owned(),
            |parent| format!("{}/{name}", self.measurements[parent.id].path),
        );
        let id = self.measurements.len();
        self.measurements.push(Measurement {
            path,
            inclusive: Duration::ZERO,
            exclusive: Duration::ZERO,
            inclusive_bytes: 0,
            exclusive_bytes: 0,
        });
        self.stack.push(Active {
            id,
            start,
            position,
            child_time: Duration::ZERO,
            child_bytes: 0,
        });
        id
    }

    pub fn end(&mut self, id: usize, position: usize) {
        let active = self.stack.pop().expect("profile span must be open");
        assert_eq!(active.id, id, "profile spans must be nested");
        let elapsed = active.start.elapsed();
        let bytes = position - active.position;
        let row = &mut self.measurements[id];
        row.inclusive = elapsed;
        row.exclusive = elapsed - active.child_time;
        row.inclusive_bytes = bytes;
        row.exclusive_bytes = bytes - active.child_bytes;
        if let Some(parent) = self.stack.last_mut() {
            parent.child_time += elapsed;
            parent.child_bytes += bytes;
        }
    }

    pub fn assert_complete(&self, proof_bytes: usize) {
        assert!(self.stack.is_empty(), "unclosed profile spans");
        if !self.measurements.is_empty() {
            assert_eq!(
                self.measurements
                    .iter()
                    .map(|m| m.exclusive_bytes)
                    .sum::<usize>(),
                proof_bytes,
                "every serialized byte must be accounted for"
            );
        }
    }
}
