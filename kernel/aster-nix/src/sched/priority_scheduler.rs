// SPDX-License-Identifier: MPL-2.0

use ostd::{
    cpu::{num_cpus, this_cpu},
    task::{
        scheduler::{inject_scheduler, EnqueueFlags, LocalRunQueue, Scheduler, UpdateFlags},
        AtomicCpuId, Priority, Task,
    },
};

use crate::prelude::*;

pub fn init() {
    let preempt_scheduler = Box::new(PreemptScheduler::default());
    let scheduler = Box::<PreemptScheduler<Task>>::leak(preempt_scheduler);
    inject_scheduler(scheduler);
}

/// The preempt scheduler.
///
/// Real-time tasks are placed in the `real_time_entities` queue and
/// are always prioritized during scheduling.
/// Normal tasks are placed in the `normal_entities` queue and are only
/// scheduled for execution when there are no real-time tasks.
struct PreemptScheduler<T: PreemptSchedInfo> {
    rq: Vec<SpinLock<PreemptRunQueue<T>>>,
}

impl<T: PreemptSchedInfo> PreemptScheduler<T> {
    fn new(nr_cpus: u32) -> Self {
        let mut rq = Vec::with_capacity(nr_cpus as usize);
        for _ in 0..nr_cpus {
            rq.push(SpinLock::new(PreemptRunQueue::new()));
        }
        Self { rq }
    }

    /// Selects a cpu for task to run on.
    fn select_cpu(&self, _runnable: &Arc<T>) -> u32 {
        // FIXME: adopt more reasonable policy once we fully enable SMP.
        0
    }
}

impl<T: Sync + Send + PreemptSchedInfo> Scheduler<T> for PreemptScheduler<T> {
    fn enqueue(&self, runnable: Arc<T>, flags: EnqueueFlags) -> Option<u32> {
        let mut still_in_rq = false;
        let target_cpu = {
            let mut cpu_id = self.select_cpu(&runnable);
            if let Err(task_cpu_id) = runnable.cpu().set_if_is_none(cpu_id) {
                debug_assert!(flags != EnqueueFlags::Spawn);
                still_in_rq = true;
                cpu_id = task_cpu_id;
            }

            cpu_id
        };

        let mut rq = self.rq[target_cpu as usize].lock_irq_disabled();
        if still_in_rq && let Err(_) = runnable.cpu().set_if_is_none(target_cpu) {
            return None;
        }
        let entity = PreemptSchedEntity::new(runnable);
        if entity.is_real_time() {
            rq.real_time_entities.push_back(entity);
        } else {
            rq.normal_entities.push_back(entity);
        }

        Some(target_cpu)
    }

    fn local_rq_with(&self, f: &mut dyn FnMut(&dyn LocalRunQueue<T>)) {
        let local_rq: &PreemptRunQueue<T> = &self.rq[this_cpu() as usize].lock_irq_disabled();
        f(local_rq);
    }

    fn local_mut_rq_with(&self, f: &mut dyn FnMut(&mut dyn LocalRunQueue<T>)) {
        let local_rq: &mut PreemptRunQueue<T> =
            &mut self.rq[this_cpu() as usize].lock_irq_disabled();
        f(local_rq);
    }
}

impl Default for PreemptScheduler<Task> {
    fn default() -> Self {
        Self::new(num_cpus())
    }
}

struct PreemptRunQueue<T: PreemptSchedInfo> {
    current: Option<PreemptSchedEntity<T>>,
    real_time_entities: VecDeque<PreemptSchedEntity<T>>,
    normal_entities: VecDeque<PreemptSchedEntity<T>>,
}

impl<T: PreemptSchedInfo> PreemptRunQueue<T> {
    pub fn new() -> Self {
        Self {
            current: None,
            real_time_entities: VecDeque::new(),
            normal_entities: VecDeque::new(),
        }
    }
}

impl<T: Sync + Send + PreemptSchedInfo> LocalRunQueue<T> for PreemptRunQueue<T> {
    fn current(&self) -> Option<&Arc<T>> {
        self.current.as_ref().map(|entity| &entity.runnable)
    }

    fn update_current(&mut self, flags: UpdateFlags) -> bool {
        match flags {
            UpdateFlags::Tick => {
                let Some(ref mut current_entity) = self.current else {
                    return false;
                };
                current_entity.tick()
                    || (!current_entity.is_real_time() && !self.real_time_entities.is_empty())
            }
            _ => true,
        }
    }

    fn pick_next_current(&mut self) -> Option<&Arc<T>> {
        let next_entity = if !self.real_time_entities.is_empty() {
            self.real_time_entities.pop_front()
        } else {
            self.normal_entities.pop_front()
        }?;
        if let Some(prev_entity) = self.current.replace(next_entity) {
            if prev_entity.is_real_time() {
                self.real_time_entities.push_back(prev_entity);
            } else {
                self.normal_entities.push_back(prev_entity);
            }
        }

        Some(&self.current.as_ref().unwrap().runnable)
    }

    fn dequeue_current(&mut self) -> Option<Arc<T>> {
        self.current.take().map(|entity| {
            let runnable = entity.runnable;
            runnable.cpu().set_to_none();

            runnable
        })
    }
}

struct PreemptSchedEntity<T: PreemptSchedInfo> {
    runnable: Arc<T>,
    time_slice: TimeSlice,
}

impl<T: PreemptSchedInfo> PreemptSchedEntity<T> {
    fn new(runnable: Arc<T>) -> Self {
        Self {
            runnable,
            time_slice: TimeSlice::default(),
        }
    }

    fn is_real_time(&self) -> bool {
        self.runnable.is_real_time()
    }

    fn tick(&mut self) -> bool {
        self.time_slice.elapse()
    }
}

impl<T: PreemptSchedInfo> Clone for PreemptSchedEntity<T> {
    fn clone(&self) -> Self {
        Self {
            runnable: self.runnable.clone(),
            time_slice: self.time_slice,
        }
    }
}

#[derive(Clone, Copy)]
pub struct TimeSlice {
    elapsed_ticks: u32,
}

impl TimeSlice {
    const DEFAULT_TIME_SLICE: u32 = 100;

    pub const fn new() -> Self {
        TimeSlice { elapsed_ticks: 0 }
    }

    pub fn elapse(&mut self) -> bool {
        self.elapsed_ticks = (self.elapsed_ticks + 1) % Self::DEFAULT_TIME_SLICE;

        self.elapsed_ticks == 0
    }
}

impl Default for TimeSlice {
    fn default() -> Self {
        Self::new()
    }
}

impl PreemptSchedInfo for Task {
    type PRIORITY = Priority;

    const REAL_TIME_TASK_PRIORITY: Self::PRIORITY = Priority::new(100);

    fn priority(&self) -> Self::PRIORITY {
        self.priority()
    }

    fn cpu(&self) -> &AtomicCpuId {
        self.cpu()
    }
}

trait PreemptSchedInfo {
    type PRIORITY: Ord + PartialOrd + Eq + PartialEq;

    const REAL_TIME_TASK_PRIORITY: Self::PRIORITY;

    fn priority(&self) -> Self::PRIORITY;

    fn cpu(&self) -> &AtomicCpuId;

    fn is_real_time(&self) -> bool {
        self.priority() < Self::REAL_TIME_TASK_PRIORITY
    }
}
