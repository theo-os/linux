use super::OutputFormatter;
use std::io::Write;
use crate::extractor::{SocketStateSpec, ProtocolBehaviorSpec, AddrFamilySpec, BufferSpec, AsyncSpec, CapabilitySpec,
    ParamSpec, ReturnSpec, ErrorSpec, SignalSpec, SignalMaskSpec, SideEffectSpec, StateTransitionSpec, ConstraintSpec, LockSpec};

pub struct ShallFormatter {
    api_name: Option<String>,
    in_list: bool,
}

impl ShallFormatter {
    pub fn new() -> Self {
        ShallFormatter {
            api_name: None,
            in_list: false,
        }
    }

}

impl OutputFormatter for ShallFormatter {
    fn begin_document(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn end_document(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_api_list(&mut self, w: &mut dyn Write, title: &str) -> std::io::Result<()> {
        self.in_list = true;
        writeln!(w, "\n{} API Behavioral Requirements:", title)?;
        writeln!(w)
    }

    fn api_item(&mut self, w: &mut dyn Write, name: &str, _api_type: &str) -> std::io::Result<()> {
        writeln!(w, "- {} shall be available for {}", name, name.replace('_', " "))
    }

    fn end_api_list(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        self.in_list = false;
        Ok(())
    }

    fn total_specs(&mut self, w: &mut dyn Write, count: usize) -> std::io::Result<()> {
        writeln!(w, "\nTotal: {} kernel API specifications shall be enforced.", count)
    }

    fn begin_api_details(&mut self, w: &mut dyn Write, name: &str) -> std::io::Result<()> {
        self.api_name = Some(name.to_string());
        writeln!(w, "\nBehavioral Requirements for {}:", name)?;
        writeln!(w)
    }

    fn end_api_details(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        self.api_name = None;
        Ok(())
    }

    fn description(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        if let Some(api_name) = &self.api_name {
            writeln!(w, "- {} shall {}.", api_name, desc.trim_end_matches('.'))
        } else {
            writeln!(w, "- The API shall {}.", desc.trim_end_matches('.'))
        }
    }

    fn long_description(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        writeln!(w)?;
        for line in desc.lines() {
            if !line.trim().is_empty() {
                writeln!(w, "{}", line)?;
            }
        }
        writeln!(w)
    }

    fn begin_context_flags(&mut self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w, "\nExecution Context Requirements:")?;
        writeln!(w)
    }

    fn context_flag(&mut self, w: &mut dyn Write, flag: &str) -> std::io::Result<()> {
        // Parse context flags and make them readable with specific requirements
        match flag {
            "Process context" => {
                writeln!(w, "- The function shall be callable from process context.")?;
                writeln!(w, "  Process context allows the function to sleep, allocate memory with GFP_KERNEL, and access user space.")
            }
            "Softirq context" => {
                writeln!(w, "- The function shall be callable from softirq context.")?;
                writeln!(w, "  In softirq context, the function shall not sleep and shall use GFP_ATOMIC for memory allocations.")
            }
            "Hardirq context" => {
                writeln!(w, "- The function shall be callable from hardirq (interrupt) context.")?;
                writeln!(w, "  In hardirq context, the function shall not sleep, shall minimize execution time, and shall use GFP_ATOMIC for allocations.")
            }
            "NMI context" => {
                writeln!(w, "- The function shall be callable from NMI (Non-Maskable Interrupt) context.")?;
                writeln!(w, "  In NMI context, the function shall not take any locks that might be held by interrupted code.")
            }
            "User mode" => {
                writeln!(w, "- The function shall be callable when the CPU is in user mode.")?;
                writeln!(w, "  This typically applies to system call entry points.")
            }
            "Kernel mode" => {
                writeln!(w, "- The function shall be callable when the CPU is in kernel mode.")
            }
            "May sleep" => {
                writeln!(w, "- The function may sleep (block) during execution.")?;
                writeln!(w, "  Callers shall ensure they are in a context where sleeping is allowed (not in interrupt or atomic context).")
            }
            "Atomic context" => {
                writeln!(w, "- The function shall be callable from atomic context.")?;
                writeln!(w, "  In atomic context, the function shall not sleep and shall complete quickly.")
            }
            "Preemptible" => {
                writeln!(w, "- The function shall be callable when preemption is enabled.")?;
                writeln!(w, "  The function may be preempted by higher priority tasks.")
            }
            "Migration disabled" => {
                writeln!(w, "- The function shall be callable when CPU migration is disabled.")?;
                writeln!(w, "  The function shall not rely on being able to migrate between CPUs.")
            }
            _ => {
                // Fallback for unrecognized flags
                writeln!(w, "- The function shall be callable from {} context.", flag)
            }
        }
    }

    fn end_context_flags(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_parameters(&mut self, w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        writeln!(w, "\nParameter Requirements:")
    }

    fn parameter(&mut self, w: &mut dyn Write, param: &ParamSpec) -> std::io::Result<()> {
        writeln!(w)?;
        writeln!(w, "- If {} is provided, it shall be {}.",
            param.name, param.description.trim_end_matches('.'))?;

        // Only show meaningful numeric constraints
        if let Some(min) = param.min_value {
            if let Some(max) = param.max_value {
                if min != 0 || max != 0 {
                    writeln!(w, "\n- If {} is less than {} or greater than {}, the operation shall fail.",
                        param.name, min, max)?;
                }
            } else if min != 0 {
                writeln!(w, "\n- If {} is less than {}, the operation shall fail.",
                    param.name, min)?;
            }
        } else if let Some(max) = param.max_value {
            if max != 0 {
                writeln!(w, "\n- If {} is greater than {}, the operation shall fail.",
                    param.name, max)?;
            }
        }

        if let Some(constraint) = &param.constraint {
            if !constraint.is_empty() {
                let constraint_text = constraint.trim_end_matches('.');
                // Handle constraints that start with "Must be" or similar
                if constraint_text.to_lowercase().starts_with("must be ") {
                    let requirement = &constraint_text[8..]; // Skip "Must be "
                    writeln!(w, "\n- If {} is not {}, the operation shall fail.",
                        param.name, requirement)?;
                } else if constraint_text.to_lowercase().starts_with("must ") {
                    let requirement = &constraint_text[5..]; // Skip "Must "
                    writeln!(w, "\n- If {} does not {}, the operation shall fail.",
                        param.name, requirement)?;
                } else if constraint_text.contains(" must ") || constraint_text.contains(" should ") {
                    // Reformat constraints with must/should in the middle
                    writeln!(w, "\n- {} shall satisfy: {}.",
                        param.name, constraint_text)?;
                } else {
                    // Default format for other constraints
                    writeln!(w, "\n- If {} is not {}, the operation shall fail.",
                        param.name, constraint_text)?;
                }
            }
        }

        // Only show valid_mask if it's not 0
        if let Some(mask) = param.valid_mask {
            if mask != 0 {
                writeln!(w, "\n- If {} contains bits not set in 0x{:x}, the operation shall fail.",
                    param.name, mask)?;
            }
        }

        Ok(())
    }

    fn end_parameters(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn return_spec(&mut self, w: &mut dyn Write, ret: &ReturnSpec) -> std::io::Result<()> {
        writeln!(w, "\nReturn Value Behavior:")?;
        writeln!(w)?;

        if let Some(success) = ret.success_value {
            writeln!(w, "- If the operation succeeds, the function shall return {}.", success)?;
        } else if let Some(min) = ret.success_min {
            if let Some(max) = ret.success_max {
                writeln!(w, "- If the operation succeeds, the function shall return a value between {} and {} inclusive.", min, max)?;
            } else {
                writeln!(w, "- If the operation succeeds, the function shall return a value greater than or equal to {}.", min)?;
            }
        }

        if !ret.error_values.is_empty() {
            writeln!(w, "\n- If the operation fails, the function shall return one of the specified negative error values.")?;
        }

        Ok(())
    }

    fn begin_errors(&mut self, w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        writeln!(w, "\nError Handling:")?;
        Ok(())
    }

    fn error(&mut self, w: &mut dyn Write, error: &ErrorSpec) -> std::io::Result<()> {
        writeln!(w)?;
        let condition = if error.condition.is_empty() {
            error.description.to_lowercase().trim_end_matches('.').to_string()
        } else {
            error.condition.to_lowercase()
        };
        writeln!(w, "- If {condition}, the function shall return -{}.", error.name)?;

        // Add description if available and different from condition
        if !error.description.is_empty() && error.description != error.condition {
            writeln!(w, "  {}", error.description)?;
        }

        Ok(())
    }

    fn end_errors(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn examples(&mut self, w: &mut dyn Write, examples: &str) -> std::io::Result<()> {
        writeln!(w, "\nExample Usage:")?;
        writeln!(w)?;
        writeln!(w, "```")?;
        write!(w, "{}", examples)?;
        writeln!(w, "```")
    }

    fn notes(&mut self, w: &mut dyn Write, notes: &str) -> std::io::Result<()> {
        writeln!(w, "\nImplementation Notes:")?;
        writeln!(w)?;

        // Split notes into sentences and format each as a behavioral requirement
        let sentences: Vec<&str> = notes.split(". ")
            .filter(|s| !s.trim().is_empty())
            .collect();

        for sentence in sentences {
            let trimmed = sentence.trim().trim_end_matches('.');
            if trimmed.is_empty() {
                continue;
            }

            // Check if it already contains "shall" or similar
            if trimmed.contains("shall") || trimmed.contains("must") {
                writeln!(w, "- {}.", trimmed)?;
            } else if trimmed.starts_with("On ") || trimmed.starts_with("If ") || trimmed.starts_with("When ") {
                // These are already conditional, just add shall
                writeln!(w, "- {}, the behavior shall be as described.", trimmed)?;
            } else {
                // Convert to a shall statement
                writeln!(w, "- The implementation shall ensure that {}.",
                    trimmed.chars().next().unwrap().to_lowercase().collect::<String>() + &trimmed[1..])?;
            }
        }
        Ok(())
    }

    fn since_version(&mut self, w: &mut dyn Write, version: &str) -> std::io::Result<()> {
        writeln!(w, "\n- If kernel version is {} or later, this API shall be available.", version)
    }

    fn sysfs_subsystem(&mut self, w: &mut dyn Write, subsystem: &str) -> std::io::Result<()> {
        writeln!(w, "- If accessed through sysfs, the attribute shall be located in the {} subsystem.", subsystem)
    }

    fn sysfs_path(&mut self, w: &mut dyn Write, path: &str) -> std::io::Result<()> {
        writeln!(w, "\n- If the sysfs interface is mounted, the attribute shall be accessible at {}.", path)
    }

    fn sysfs_permissions(&mut self, w: &mut dyn Write, perms: &str) -> std::io::Result<()> {
        writeln!(w, "\n- If the attribute exists, its permissions shall be set to {}.", perms)
    }

    fn socket_state(&mut self, w: &mut dyn Write, state: &SocketStateSpec) -> std::io::Result<()> {
        writeln!(w, "\nSocket State Behavior:")?;
        writeln!(w)?;

        if !state.required_states.is_empty() {
            let states_str = state.required_states.join(" or ");
            writeln!(w, "- If the socket is not in {} state, the operation shall fail.", states_str)?;
        }

        if !state.forbidden_states.is_empty() {
            for s in &state.forbidden_states {
                writeln!(w, "\n- If the socket is in {} state, the operation shall fail.", s)?;
            }
        }

        if let Some(result) = &state.resulting_state {
            writeln!(w, "\n- If the operation succeeds, the socket state shall transition to {}.", result)?;
        }

        Ok(())
    }

    fn begin_protocol_behaviors(&mut self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w, "\nProtocol-Specific Behavior:")
    }

    fn protocol_behavior(&mut self, w: &mut dyn Write, behavior: &ProtocolBehaviorSpec) -> std::io::Result<()> {
        writeln!(w)?;
        writeln!(w, "- If protocol is {}, {}.",
            behavior.applicable_protocols, behavior.behavior)?;

        if let Some(flags) = &behavior.protocol_flags {
            writeln!(w, "\n- If protocol is {} and flags {} are set, the behavior shall be modified accordingly.",
                behavior.applicable_protocols, flags)?;
        }

        Ok(())
    }

    fn end_protocol_behaviors(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_addr_families(&mut self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w, "\nAddress Family Behavior:")
    }

    fn addr_family(&mut self, w: &mut dyn Write, family: &AddrFamilySpec) -> std::io::Result<()> {
        writeln!(w)?;
        writeln!(w, "- If address family is {} ({}), the address structure size shall be {} bytes.",
            family.family, family.family_name, family.addr_struct_size)?;

        writeln!(w, "\n- If address family is {} and address length is less than {} or greater than {}, the operation shall fail.",
            family.family, family.min_addr_len, family.max_addr_len)?;

        Ok(())
    }

    fn end_addr_families(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn buffer_spec(&mut self, w: &mut dyn Write, spec: &BufferSpec) -> std::io::Result<()> {
        writeln!(w, "\nBuffer Behavior:")?;
        writeln!(w)?;

        if let Some(min) = spec.min_buffer_size {
            writeln!(w, "- If the buffer size is less than {} bytes, the operation shall fail.", min)?;
        }

        if let Some(max) = spec.max_buffer_size {
            writeln!(w, "\n- If the buffer size exceeds {} bytes, the excess data shall be truncated.", max)?;
        }

        if let Some(behaviors) = &spec.buffer_behaviors {
            writeln!(w, "\n- When handling buffers, the following behavior shall apply: {}.", behaviors)?;
        }

        Ok(())
    }

    fn async_spec(&mut self, w: &mut dyn Write, spec: &AsyncSpec) -> std::io::Result<()> {
        writeln!(w, "\nAsynchronous Behavior:")?;
        writeln!(w)?;

        if let Some(_modes) = &spec.supported_modes {
            writeln!(w, "- If O_NONBLOCK is set and the operation would block, the function shall return -EAGAIN or -EWOULDBLOCK.")?;
        }

        if let Some(errno) = spec.nonblock_errno {
            writeln!(w, "\n- If the file descriptor is in non-blocking mode and no data is available, the function shall return -{}.", errno)?;
        }

        Ok(())
    }

    fn net_data_transfer(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        writeln!(w, "\nData Transfer Behavior:")?;
        writeln!(w)?;
        writeln!(w, "- When transferring data, the operation shall {}.", desc.trim_end_matches('.'))
    }

    fn begin_capabilities(&mut self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w, "\nCapability Requirements:")
    }

    fn capability(&mut self, w: &mut dyn Write, cap: &CapabilitySpec) -> std::io::Result<()> {
        writeln!(w)?;
        writeln!(w, "- If the process attempts to {}, {} capability shall be checked.",
            cap.action, cap.name)?;
        writeln!(w)?;
        writeln!(w, "- If {} is present, {}.", cap.name, cap.allows)?;
        writeln!(w)?;
        writeln!(w, "- If {} is not present, {}.", cap.name, cap.without_cap)?;

        Ok(())
    }

    fn end_capabilities(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_signals(&mut self, w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        writeln!(w, "\nSignal Behavior:")?;
        Ok(())
    }

    fn signal(&mut self, w: &mut dyn Write, signal: &SignalSpec) -> std::io::Result<()> {
        writeln!(w)?;

        // Skip signals with no meaningful description
        if let Some(desc) = &signal.description {
            if !desc.is_empty() {
                writeln!(w, "- {}: {}.", signal.signal_name, desc)?;
                return Ok(());
            }
        }

        // Default behavior based on direction
        if signal.direction == 1 { // Sends
            writeln!(w, "- If the conditions for {} are met, the signal shall be sent to the target process.",
                signal.signal_name)?;
        } else if signal.direction == 2 { // Receives
            writeln!(w, "- If {} is received and not blocked, the operation shall be interrupted.",
                signal.signal_name)?;

            if signal.restartable {
                writeln!(w, "\n- If {} is received and SA_RESTART is set, the operation shall be automatically restarted.",
                    signal.signal_name)?;
            }
        } else {
            // Direction 0 or other - just note the signal handling
            writeln!(w, "- {} shall be handled according to its default behavior.", signal.signal_name)?;
        }

        if let Some(errno) = signal.error_on_signal {
            if errno != 0 {
                writeln!(w, "\n- If interrupted by {}, the function shall return -{}.",
                    signal.signal_name, errno)?;
            }
        }

        Ok(())
    }

    fn end_signals(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_signal_masks(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {
        writeln!(w, "\n### Signal Mask Requirements")?;
        if count > 0 {
            writeln!(w, "The API SHALL support the following signal mask operations:")?;
        }
        Ok(())
    }

    fn signal_mask(&mut self, w: &mut dyn Write, mask: &SignalMaskSpec) -> std::io::Result<()> {
        writeln!(w, "\n- **{}**: {}", mask.name, mask.description)?;
        Ok(())
    }

    fn end_signal_masks(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_side_effects(&mut self, w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        writeln!(w, "\nSide Effects:")?;
        Ok(())
    }

    fn side_effect(&mut self, w: &mut dyn Write, effect: &SideEffectSpec) -> std::io::Result<()> {
        writeln!(w)?;
        if let Some(condition) = &effect.condition {
            writeln!(w, "- If {}, {} shall be {}.",
                condition, effect.target, effect.description.trim_end_matches('.'))?;
        } else {
            writeln!(w, "- When the operation executes, {} shall be {}.",
                effect.target, effect.description.trim_end_matches('.'))?;
        }

        if effect.reversible {
            writeln!(w, "\n- If the operation is rolled back, the effect on {} shall be reversed.",
                effect.target)?;
        }

        Ok(())
    }

    fn end_side_effects(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_state_transitions(&mut self, w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        writeln!(w, "\nState Transitions:")?;
        Ok(())
    }

    fn state_transition(&mut self, w: &mut dyn Write, trans: &StateTransitionSpec) -> std::io::Result<()> {
        writeln!(w)?;
        if let Some(condition) = &trans.condition {
            writeln!(w, "- If {} is in {} state and {}, it shall transition to {} state.",
                trans.object, trans.from_state, condition, trans.to_state)?;
        } else {
            writeln!(w, "- If {} is in {} state, it shall transition to {} state.",
                trans.object, trans.from_state, trans.to_state)?;
        }

        Ok(())
    }

    fn end_state_transitions(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_constraints(&mut self, w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        writeln!(w, "\nConstraints:")?;
        Ok(())
    }

    fn constraint(&mut self, w: &mut dyn Write, constraint: &ConstraintSpec) -> std::io::Result<()> {
        writeln!(w)?;
        if let Some(expr) = &constraint.expression {
            if expr.is_empty() {
                writeln!(w, "- {}: {}.", constraint.name, constraint.description)?;
            } else {
                writeln!(w, "- If {} is violated, the operation shall fail.", constraint.name)?;
                writeln!(w, "  Constraint: {}", expr)?;
            }
        } else {
            writeln!(w, "- {}: {}.", constraint.name, constraint.description)?;
        }

        Ok(())
    }

    fn end_constraints(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_locks(&mut self, w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        writeln!(w, "\nLocking Behavior:")?;
        Ok(())
    }

    fn lock(&mut self, w: &mut dyn Write, lock: &LockSpec) -> std::io::Result<()> {
        writeln!(w)?;

        // Always show lock information if we have a description
        if !lock.description.is_empty() {
            let lock_type_str = match lock.lock_type {
                1 => "mutex",
                2 => "spinlock",
                3 => "rwlock",
                4 => "semaphore",
                5 => "RCU",
                _ => "lock",
            };
            writeln!(w, "- The {} {} shall be used for: {}",
                lock.lock_name, lock_type_str, lock.description)?;
        }

        if lock.held_on_entry {
            writeln!(w, "- If {} is not held on entry, the operation shall fail.", lock.lock_name)?;
        }

        if lock.acquired && !lock.held_on_entry {
            writeln!(w, "- Before accessing the protected resource, {} shall be acquired.", lock.lock_name)?;
        }

        if lock.released && lock.held_on_exit {
            writeln!(w, "- If the operation succeeds and no error path is taken, {} shall remain held on exit.", lock.lock_name)?;
        } else if lock.released {
            writeln!(w, "- Before returning, {} shall be released.", lock.lock_name)?;
        }

        Ok(())
    }

    fn end_locks(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }
}