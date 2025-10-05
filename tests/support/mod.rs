use std::collections::HashMap;
use std::convert::TryInto;

use pete::{Pid, Stop, Tracee};
use pretty_assertions::assert_eq;

#[allow(unused)]
macro_rules! pid {
    ($raw: expr) => {
        pete::Pid::from_raw($raw)
    };
}

/// Construct a tracee stop event with a readable, integration test-friendly syntax.
macro_rules! event {
    ($raw_pid: expr, $stop: expr) => {{
        use pete::Stop::*;

        let pid = pete::Pid::from_raw($raw_pid);

        pete::Tracee::new(pid, None, $stop)
    }};
    ($raw_pid: expr, $stop: expr, $signal: expr) => {{
        use pete::Signal::*;
        use pete::Stop::*;

        let pid = pete::Pid::from_raw($raw_pid);

        pete::Tracee::new(pid, $signal, $stop)
    }};
}

/// Assert that two event traces are equivalent modulo PID normalization.
pub fn assert_equivalent(left: &[Tracee], right: &[Tracee]) {
    let normed_left = Normalizer::normalize(left);
    let normed_right = Normalizer::normalize(right);
    assert_eq!(normed_left, normed_right)
}

/// Normalizes an event trace by substituting each concrete raw PID value with one that
/// matches its ordinal of appearance in the trace.
#[derive(Default)]
struct Normalizer {
    map: HashMap<Pid, Pid>,
}

impl Normalizer {
    pub fn normalize(trace: &[Tracee]) -> Vec<Tracee> {
        Normalizer::default().normalize_trace(trace)
    }

    fn normalize_trace(&mut self, trace: &[Tracee]) -> Vec<Tracee> {
        let mut normed_trace = vec![];

        for tracee in trace {
            let normed = self.normalize_tracee(tracee);
            normed_trace.push(normed);
        }

        normed_trace
    }

    fn normalize_tracee(&mut self, tracee: &Tracee) -> Tracee {
        let normed_pid = self.normalize_pid(tracee.pid);
        let normed_stop = self.normalize_stop(tracee.stop);
        Tracee::new(normed_pid, tracee.pending, normed_stop)
    }

    fn normalize_stop(&mut self, stop: Stop) -> Stop {
        match stop {
            Stop::Attach => stop,
            Stop::SignalDelivery { signal: _ } => stop,
            Stop::Group { signal: _ } => stop,
            Stop::SyscallEnter => stop,
            Stop::SyscallExit => stop,
            Stop::Clone { new } =>  {
                let normed_new = self.normalize_pid(new);
                Stop::Clone { new: normed_new }
            },
            Stop::Fork { new } => {
                let normed_new = self.normalize_pid(new);
                Stop::Fork { new: normed_new }
            },
            Stop::Exec { old } => {
                let normed_old = self.normalize_pid(old);
                Stop::Exec { old: normed_old }
            },
            Stop::Exiting { exit_code: _ } => stop,
            Stop::Signaling { signal: _, core_dumped: _ } => stop,
            Stop::Vfork { new } => {
                let normed_new = self.normalize_pid(new);
                Stop::Vfork { new: normed_new }
            },
            Stop::VforkDone { new } => {
                let normed_new = self.normalize_pid(new);
                Stop::VforkDone { new: normed_new }
            },
            Stop::Seccomp { data: _ } => stop,
        }
    }

    fn normalize_pid(&mut self, pid: Pid) -> Pid {
        // Avoid borrowck error in `default` fn.
        let next_free = self.map.len();

        let entry = self.map.entry(pid).or_insert_with(|| {
            let raw: i32 = next_free.try_into().expect("exhausted free test PIDs");
            Pid::from_raw(raw)
        });

        *entry
    }
}
