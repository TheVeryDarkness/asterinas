// SPDX-License-Identifier: MPL-2.0

//! Dynamically attached observers for compiler-generated function hooks.
//!
//! Instrumented functions declare a [`Hook`] with [`crate::function_hook!`].
//! The linker collects the declarations into a discoverable [`catalog`].
//! Each function invocation remembers the return observer's generation without retaining its code.
//! A return event is emitted only if the same observer is still attached when the function returns.
//! The invocation owns no argument references, native program, or CPU guards
//! while the original function runs.
//!
//! Observers receive seven `u64` slots: hook ID, [`Phase`], invocation ID, and
//! four payload values described by the hook's fields.
//! Return events describe normal returns only; dropping an invocation does not emit an event.
//! The native execution trust boundary is the existing `RsmProgram` loader.
//! Builds without the `ostd` feature expose only descriptors and discovery.

#![deny(unsafe_code)]

#[cfg(any(feature = "ostd", test))]
use alloc::sync::Arc;
#[cfg(feature = "ostd")]
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

#[cfg(feature = "ostd")]
use ostd::{
    irq::{self, InterruptLevel},
    sync::RwLock,
    task::{self, Task, atomic_mode},
};

#[cfg(feature = "ostd")]
use crate::RsmProgram;

/// The maximum number of scalar values carried by one event.
pub const MAX_PAYLOAD_VALUES: usize = 4;

/// Stack retained for dispatch frames between the headroom check and native entry.
#[cfg(feature = "ostd")]
const NATIVE_DISPATCH_RESERVE_BYTES: usize = 16 * 1024;

/// A copied scalar's name and source-level type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Field {
    name: &'static str,
    type_name: &'static str,
}

impl Field {
    /// Creates a field descriptor.
    pub const fn new(name: &'static str, type_name: &'static str) -> Self {
        Self { name, type_name }
    }

    /// Returns the source parameter or result field's name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the source-level scalar type.
    pub fn type_name(&self) -> &'static str {
        self.type_name
    }
}

/// The point within a function invocation observed by an event.
#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Entry = 0,
    Return = 1,
}

impl Phase {
    /// Decodes a phase from its syscall and event representation.
    pub const fn from_raw(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Entry),
            1 => Some(Self::Return),
            _ => None,
        }
    }

    /// Returns the phase's display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::Return => "return",
        }
    }

    #[cfg(feature = "ostd")]
    const fn mask(self) -> u8 {
        1 << (self as u8)
    }
}

/// A link-time function descriptor with independently attached observers.
pub struct Hook {
    id: u64,
    name: &'static str,
    entry_fields: &'static [Field],
    return_fields: &'static [Field],
    #[cfg(feature = "ostd")]
    state: RwLock<Attachments<RsmProgram>>,
    #[cfg(feature = "ostd")]
    enabled: AtomicU8,
    #[cfg(feature = "ostd")]
    stats: [Counters; 2],
}

impl Hook {
    /// Creates a function hook with at most four scalar fields per phase.
    ///
    /// The name must identify a unique function in the running kernel. IDs are
    /// deterministic hashes of names, but are not a cross-build ABI: users
    /// discover descriptors again after boot. Ambiguous IDs fail lookup.
    pub const fn new(
        name: &'static str,
        entry_fields: &'static [Field],
        return_fields: &'static [Field],
    ) -> Self {
        assert!(entry_fields.len() <= MAX_PAYLOAD_VALUES);
        assert!(return_fields.len() <= MAX_PAYLOAD_VALUES);
        Self {
            id: hook_id(name),
            name,
            entry_fields,
            return_fields,
            #[cfg(feature = "ostd")]
            state: RwLock::new(Attachments::new()),
            #[cfg(feature = "ostd")]
            enabled: AtomicU8::new(0),
            #[cfg(feature = "ostd")]
            stats: [Counters::new(), Counters::new()],
        }
    }

    /// Returns the ID carried by this hook's events.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns the fully qualified function name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the fields carried by the requested phase.
    pub const fn fields(&self, phase: Phase) -> &'static [Field] {
        match phase {
            Phase::Entry => self.entry_fields,
            Phase::Return => self.return_fields,
        }
    }
}

/// A hook registered by generated code.
#[doc(hidden)]
pub struct Registration(pub &'static Hook);

inventory::collect!(Registration);

#[doc(hidden)]
pub use inventory::submit;

/// Declares and discovers a function hook without changing item visibility.
///
/// The suffix is a function or method name. The expansion prefixes it with
/// `module_path!`, and keeps its descriptor local to the instrumented function.
/// Registrations inherit that function's conditional compilation conditions.
#[macro_export]
macro_rules! function_hook {
    ($suffix:literal, $entry_fields:expr, $return_fields:expr) => {{
        static HOOK: $crate::hooks::Hook = $crate::hooks::Hook::new(
            concat!(module_path!(), "::", $suffix),
            $entry_fields,
            $return_fields,
        );
        $crate::hooks::submit! { $crate::hooks::Registration(&HOOK) }
        &HOOK
    }};
}

/// Returns the hooks compiled into this kernel, in unspecified order.
pub fn catalog() -> impl Iterator<Item = &'static Hook> {
    inventory::iter::<Registration>
        .into_iter()
        .map(|registration| registration.0)
}

/// Finds an unambiguous hook ID in the compiled catalog.
pub fn find(id: u64) -> Result<&'static Hook, HookError> {
    let mut matches = catalog().filter(|hook| hook.id() == id);
    let hook = matches.next().ok_or(HookError::NotFound)?;
    if matches.next().is_some() {
        return Err(HookError::Ambiguous);
    }
    Ok(hook)
}

/// A rejected hook lookup or attachment operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookError {
    NotFound,
    Ambiguous,
    AlreadyAttached,
    NotAttached,
    GenerationExhausted,
}

/// Returns the FNV-1a identifier for a fully qualified function name.
const fn hook_id(name: &str) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let bytes = name.as_bytes();
    let mut hash = OFFSET_BASIS;
    let mut index = 0;
    while index < bytes.len() {
        hash = (hash ^ bytes[index] as u64).wrapping_mul(PRIME);
        index += 1;
    }
    hash
}

#[cfg(any(feature = "ostd", test))]
struct Attachments<P> {
    phases: [Option<Attachment<P>>; 2],
    last_generation: u64,
}

#[cfg(any(feature = "ostd", test))]
struct Attachment<P> {
    program: Arc<P>,
    generation: u64,
}

#[cfg(any(feature = "ostd", test))]
impl<P> Attachments<P> {
    const fn new() -> Self {
        Self {
            phases: [None, None],
            last_generation: 0,
        }
    }

    fn attach(&mut self, phase: Phase, program: &Arc<P>) -> Result<(), HookError> {
        if self.phases[phase as usize].is_some() {
            return Err(HookError::AlreadyAttached);
        }
        let generation = self
            .last_generation
            .checked_add(1)
            .ok_or(HookError::GenerationExhausted)?;
        self.last_generation = generation;
        self.phases[phase as usize] = Some(Attachment {
            program: Arc::clone(program),
            generation,
        });
        Ok(())
    }

    fn detach(&mut self, phase: Phase) -> Result<Arc<P>, HookError> {
        self.phases[phase as usize]
            .take()
            .map(|attachment| attachment.program)
            .ok_or(HookError::NotAttached)
    }

    fn entry_snapshot(&self) -> (Option<Arc<P>>, Option<u64>) {
        let entry = self.phases[Phase::Entry as usize]
            .as_ref()
            .map(|attachment| Arc::clone(&attachment.program));
        let return_generation = self.phases[Phase::Return as usize]
            .as_ref()
            .map(|attachment| attachment.generation);
        (entry, return_generation)
    }

    fn return_snapshot(&self, generation: u64) -> Option<Arc<P>> {
        self.phases[Phase::Return as usize]
            .as_ref()
            .filter(|attachment| attachment.generation == generation)
            .map(|attachment| Arc::clone(&attachment.program))
    }
}

#[cfg(feature = "ostd")]
struct Counters {
    invocations: AtomicU64,
    skipped: AtomicU64,
    traps: AtomicU64,
}

#[cfg(feature = "ostd")]
impl Counters {
    const fn new() -> Self {
        Self {
            invocations: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
            traps: AtomicU64::new(0),
        }
    }
}

/// Lifetime counters for one hook phase.
///
/// Counters are independent, approximate observations under concurrent dispatch.
/// They are not reset by attach/detach, so in-flight calls cannot update a new
/// attachment generation's reset counters. All counters wrap on overflow.
#[cfg(feature = "ostd")]
#[derive(Clone, Copy, Debug)]
pub struct HookStats {
    /// Whether this phase currently has an attached observer.
    pub attached: bool,
    /// Native observer calls started for this phase.
    pub invocations: u64,
    /// Rejected admissions and suppressed return attempts for this phase.
    ///
    /// Rejecting a function's entry admission counts each enabled phase once,
    /// including a return phase even if the function subsequently unwinds.
    pub skipped: u64,
    /// Native observer calls that returned a trap status.
    pub traps: u64,
}

#[cfg(feature = "ostd")]
static NEXT_INVOCATION_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(feature = "ostd")]
impl Hook {
    /// Attaches a program to a vacant phase.
    pub fn attach(&self, phase: Phase, program: Arc<RsmProgram>) -> Result<(), HookError> {
        let mut state = self.state.write();
        state.attach(phase, &program)?;
        self.enabled.fetch_or(phase.mask(), Ordering::Release);
        Ok(())
    }

    /// Detaches a phase from future callback snapshots.
    ///
    /// A callback whose program has already been captured can complete after
    /// detach. Function bodies do not retain programs: pending returns are
    /// skipped if their original attachment was detached or replaced.
    pub fn detach(&self, phase: Phase) -> Result<(), HookError> {
        let program = {
            let mut state = self.state.write();
            let program = state.detach(phase)?;
            self.enabled.fetch_and(!phase.mask(), Ordering::Release);
            program
        };
        // Dropping the last program can reclaim executable mappings. Never do
        // that while holding the registry lock or its preemption guard.
        drop(program);
        Ok(())
    }

    /// Returns lifetime counters and the current attachment state of a phase.
    pub fn stats(&self, phase: Phase) -> HookStats {
        let counters = &self.stats[phase as usize];
        HookStats {
            attached: self.enabled.load(Ordering::Acquire) & phase.mask() != 0,
            invocations: counters.invocations.load(Ordering::Relaxed),
            skipped: counters.skipped.load(Ordering::Relaxed),
            traps: counters.traps.load(Ordering::Relaxed),
        }
    }

    /// Captures an entry observer and emits this function call's entry event.
    ///
    /// Disabled hooks require only an atomic load. Enabled hooks skip callbacks
    /// in bootstrap, interrupt or atomic contexts, and skip contended attachment
    /// snapshots. A skipped admission suppresses both phases of this call.
    /// No lock or CPU guard is held after this method returns.
    pub fn enter(&'static self, payload: [u64; MAX_PAYLOAD_VALUES]) -> Invocation {
        let enabled = self.enabled.load(Ordering::Acquire);
        if enabled == 0 {
            return Invocation::disabled();
        }
        if !can_invoke() {
            self.skip_mask(enabled);
            return Invocation::disabled();
        }
        let Some(state) = self.state.try_read() else {
            self.skip_mask(enabled);
            return Invocation::disabled();
        };
        let (entry, return_generation) = state.entry_snapshot();
        drop(state);

        let Ok(id) =
            NEXT_INVOCATION_ID.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
        else {
            self.skip_mask(enabled);
            return Invocation::disabled();
        };

        if let Some(program) = entry {
            self.invoke(Phase::Entry, id, &program, payload);
        }
        Invocation {
            hook: Some(self),
            id,
            return_generation,
        }
    }

    fn finish(&self, invocation_id: u64, generation: u64, payload: [u64; MAX_PAYLOAD_VALUES]) {
        let counters = &self.stats[Phase::Return as usize];
        // Check before cloning a program: even dropping a program can reclaim
        // executable mappings and must not happen under a caller's CPU guard.
        if !can_invoke() {
            counters.skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Some(state) = self.state.try_read() else {
            counters.skipped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let program = state.return_snapshot(generation);
        drop(state);
        let Some(program) = program else {
            counters.skipped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.invoke(Phase::Return, invocation_id, &program, payload);
    }

    fn invoke(
        &self,
        phase: Phase,
        invocation_id: u64,
        program: &RsmProgram,
        payload: [u64; MAX_PAYLOAD_VALUES],
    ) {
        let counters = &self.stats[phase as usize];
        if !can_invoke() {
            counters.skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Pin the callback to this CPU and prevent interrupt frames from using
        // the checked stack headroom. Nested hooks observe atomic mode and
        // skip invocation. Both guards end before the original kernel function
        // resumes, and before a captured program can be reclaimed.
        let _preempt_guard = task::disable_preempt();
        let _irq_guard = irq::disable_local();
        let Some(required_stack_bytes) = program
            .native_stack_bytes()
            .checked_add(NATIVE_DISPATCH_RESERVE_BYTES)
        else {
            counters.skipped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if Task::kernel_stack_available_bytes()
            .is_none_or(|available| available < required_stack_bytes)
        {
            counters.skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let args = [
            phase as u64,
            invocation_id,
            payload[0],
            payload[1],
            payload[2],
            payload[3],
        ];
        counters.invocations.fetch_add(1, Ordering::Relaxed);
        if program.observe(self.id, &args) != 0 {
            counters.traps.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn skip_mask(&self, mask: u8) {
        for phase in [Phase::Entry, Phase::Return] {
            if mask & phase.mask() != 0 {
                self.stats[phase as usize]
                    .skipped
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(feature = "ostd")]
fn can_invoke() -> bool {
    !atomic_mode::is_atomic_mode()
        && InterruptLevel::current().is_task_context()
        && Task::current().is_some()
}

/// A function call's return attachment generation and correlation ID.
///
/// This value owns no argument borrow or program. Dropping it without calling
/// [`Self::finish`] does nothing. In particular, returning a CPU guard from an
/// instrumented function cannot trigger program reclamation through this token.
#[cfg(feature = "ostd")]
#[must_use]
pub struct Invocation {
    hook: Option<&'static Hook>,
    id: u64,
    return_generation: Option<u64>,
}

#[cfg(feature = "ostd")]
impl Invocation {
    const fn disabled() -> Self {
        Self {
            hook: None,
            id: 0,
            return_generation: None,
        }
    }

    /// Emits a normal-return event if the captured generation remains attached.
    pub fn finish(self, payload: [u64; MAX_PAYLOAD_VALUES]) {
        if let (Some(hook), Some(generation)) = (self.hook, self.return_generation) {
            hook.finish(self.id, generation, payload);
        }
    }
}

/// Attaches a program to an unambiguous catalog entry.
#[cfg(feature = "ostd")]
pub fn attach(id: u64, phase: Phase, program: Arc<RsmProgram>) -> Result<(), HookError> {
    find(id)?.attach(phase, program)
}

/// Detaches a phase from an unambiguous catalog entry.
#[cfg(feature = "ostd")]
pub fn detach(id: u64, phase: Phase) -> Result<(), HookError> {
    find(id)?.detach(phase)
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::{Attachments, Field, Hook, HookError, Phase, catalog, find, hook_id};

    fn instrumented_function() -> &'static Hook {
        crate::function_hook!(
            "instrumented_function",
            &[Field::new("length", "usize")],
            &[Field::new("is_error", "bool")]
        )
    }

    #[test]
    fn discovers_hook_before_function_runs() {
        let name = concat!(module_path!(), "::instrumented_function");
        let discovered = find(hook_id(name)).expect("function hook is in the link-time catalog");
        assert_eq!(discovered.name(), name);
        assert_eq!(
            discovered.fields(Phase::Entry),
            &[Field::new("length", "usize")]
        );
        assert_eq!(
            discovered.fields(Phase::Return),
            &[Field::new("is_error", "bool")]
        );
        assert!(core::ptr::eq(discovered, instrumented_function()));
        assert!(catalog().any(|hook| core::ptr::eq(hook, discovered)));
    }

    #[test]
    fn validates_phase_encoding() {
        assert_eq!(Phase::from_raw(0), Some(Phase::Entry));
        assert_eq!(Phase::from_raw(1), Some(Phase::Return));
        assert_eq!(Phase::from_raw(2), None);
        assert_eq!(Phase::from_raw(u64::MAX), None);
    }

    #[test]
    fn rejects_unknown_and_ambiguous_ids() {
        static FIRST: Hook = Hook::new("test::duplicate", &[], &[]);
        static SECOND: Hook = Hook::new("test::duplicate", &[], &[]);
        super::submit! { super::Registration(&FIRST) }
        super::submit! { super::Registration(&SECOND) }

        assert!(matches!(
            find(hook_id("test::missing")),
            Err(HookError::NotFound)
        ));
        assert!(matches!(find(FIRST.id()), Err(HookError::Ambiguous)));
    }

    #[test]
    fn identifiers_match_fnv1a_vectors() {
        assert_eq!(hook_id(""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(hook_id("a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[should_panic]
    #[test]
    fn rejects_payloads_larger_than_the_event_abi() {
        static FIELDS: [Field; 5] = [Field::new("value", "u64"); 5];
        let _ = Hook::new("test::too_many_fields", &FIELDS, &[]);
    }

    #[test]
    fn captured_callbacks_keep_detached_code_alive() {
        let program = Arc::new(42);
        let mut attachments = Attachments::new();
        attachments.attach(Phase::Entry, &program).unwrap();
        let (snapshot, _) = attachments.entry_snapshot();
        drop(attachments.detach(Phase::Entry).unwrap());
        assert_eq!(Arc::strong_count(&program), 2);
        assert_eq!(*snapshot.as_ref().unwrap().as_ref(), 42);
        drop(snapshot);
        assert_eq!(Arc::strong_count(&program), 1);
    }

    #[test]
    fn pending_returns_do_not_retain_or_retarget_programs() {
        let original = Arc::new(1);
        let mut attachments = Attachments::new();
        attachments.attach(Phase::Return, &original).unwrap();
        let (entry, generation) = attachments.entry_snapshot();
        assert!(entry.is_none());
        let generation = generation.unwrap();
        assert_eq!(Arc::strong_count(&original), 2);
        drop(attachments.detach(Phase::Return).unwrap());
        assert_eq!(Arc::strong_count(&original), 1);
        assert!(attachments.return_snapshot(generation).is_none());

        attachments.attach(Phase::Return, &Arc::new(2)).unwrap();
        assert!(attachments.return_snapshot(generation).is_none());
        let (_, new_generation) = attachments.entry_snapshot();
        assert_eq!(
            *attachments
                .return_snapshot(new_generation.unwrap())
                .unwrap(),
            2
        );
    }

    #[test]
    fn exhausted_generations_do_not_reuse_identity() {
        let mut attachments = Attachments::new();
        attachments.last_generation = u64::MAX;
        assert_eq!(
            attachments.attach(Phase::Return, &Arc::new(1)),
            Err(HookError::GenerationExhausted)
        );
        assert!(attachments.entry_snapshot().1.is_none());
    }
}
