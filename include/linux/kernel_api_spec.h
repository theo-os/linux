/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kernel_api_spec.h - Kernel API Formal Specification Framework
 *
 * This framework provides structures and macros to formally specify kernel APIs
 * in both human and machine-readable formats. It supports comprehensive documentation
 * of function signatures, parameters, return values, error conditions, and constraints.
 */

#ifndef _LINUX_KERNEL_API_SPEC_H
#define _LINUX_KERNEL_API_SPEC_H

#include <linux/types.h>
#include <linux/stringify.h>
#include <linux/compiler.h>

#define KAPI_MAX_PARAMS		16
#define KAPI_MAX_ERRORS		32
#define KAPI_MAX_CONSTRAINTS	16
#define KAPI_MAX_SIGNALS	32
#define KAPI_MAX_NAME_LEN	128
#define KAPI_MAX_DESC_LEN	512

/**
 * enum kapi_param_type - Parameter type classification
 * @KAPI_TYPE_VOID: void type
 * @KAPI_TYPE_INT: Integer types (int, long, etc.)
 * @KAPI_TYPE_UINT: Unsigned integer types
 * @KAPI_TYPE_PTR: Pointer types
 * @KAPI_TYPE_STRUCT: Structure types
 * @KAPI_TYPE_UNION: Union types
 * @KAPI_TYPE_ENUM: Enumeration types
 * @KAPI_TYPE_FUNC_PTR: Function pointer types
 * @KAPI_TYPE_ARRAY: Array types
 * @KAPI_TYPE_FD: File descriptor - validated in process context
 * @KAPI_TYPE_USER_PTR: User space pointer - validated for access and size
 * @KAPI_TYPE_PATH: Pathname - validated for access and path limits
 * @KAPI_TYPE_CUSTOM: Custom/complex types
 */
enum kapi_param_type {
	KAPI_TYPE_VOID = 0,
	KAPI_TYPE_INT,
	KAPI_TYPE_UINT,
	KAPI_TYPE_PTR,
	KAPI_TYPE_STRUCT,
	KAPI_TYPE_UNION,
	KAPI_TYPE_ENUM,
	KAPI_TYPE_FUNC_PTR,
	KAPI_TYPE_ARRAY,
	KAPI_TYPE_FD,		/* File descriptor - validated in process context */
	KAPI_TYPE_USER_PTR,	/* User space pointer - validated for access and size */
	KAPI_TYPE_PATH,		/* Pathname - validated for access and path limits */
	KAPI_TYPE_CUSTOM,
};

/**
 * enum kapi_param_flags - Parameter attribute flags
 * @KAPI_PARAM_IN: Input parameter
 * @KAPI_PARAM_OUT: Output parameter
 * @KAPI_PARAM_INOUT: Input/output parameter
 * @KAPI_PARAM_OPTIONAL: Optional parameter (can be NULL)
 * @KAPI_PARAM_CONST: Const qualified parameter
 * @KAPI_PARAM_VOLATILE: Volatile qualified parameter
 * @KAPI_PARAM_USER: User space pointer
 * @KAPI_PARAM_DMA: DMA-capable memory required
 * @KAPI_PARAM_ALIGNED: Alignment requirements
 */
enum kapi_param_flags {
	KAPI_PARAM_IN		= (1 << 0),
	KAPI_PARAM_OUT		= (1 << 1),
	KAPI_PARAM_INOUT	= (1 << 2),
	KAPI_PARAM_OPTIONAL	= (1 << 3),
	KAPI_PARAM_CONST	= (1 << 4),
	KAPI_PARAM_VOLATILE	= (1 << 5),
	KAPI_PARAM_USER		= (1 << 6),
	KAPI_PARAM_DMA		= (1 << 7),
	KAPI_PARAM_ALIGNED	= (1 << 8),
};

/**
 * enum kapi_context_flags - Function execution context flags
 * @KAPI_CTX_PROCESS: Can be called from process context
 * @KAPI_CTX_SOFTIRQ: Can be called from softirq context
 * @KAPI_CTX_HARDIRQ: Can be called from hardirq context
 * @KAPI_CTX_NMI: Can be called from NMI context
 * @KAPI_CTX_ATOMIC: Must be called in atomic context
 * @KAPI_CTX_SLEEPABLE: May sleep
 * @KAPI_CTX_PREEMPT_DISABLED: Requires preemption disabled
 * @KAPI_CTX_IRQ_DISABLED: Requires interrupts disabled
 */
enum kapi_context_flags {
	KAPI_CTX_PROCESS	= (1 << 0),
	KAPI_CTX_SOFTIRQ	= (1 << 1),
	KAPI_CTX_HARDIRQ	= (1 << 2),
	KAPI_CTX_NMI		= (1 << 3),
	KAPI_CTX_ATOMIC		= (1 << 4),
	KAPI_CTX_SLEEPABLE	= (1 << 5),
	KAPI_CTX_PREEMPT_DISABLED = (1 << 6),
	KAPI_CTX_IRQ_DISABLED	= (1 << 7),
};

/**
 * enum kapi_lock_type - Lock types used/required by the function
 * @KAPI_LOCK_NONE: No locking requirements
 * @KAPI_LOCK_MUTEX: Mutex lock
 * @KAPI_LOCK_SPINLOCK: Spinlock
 * @KAPI_LOCK_RWLOCK: Read-write lock
 * @KAPI_LOCK_SEQLOCK: Sequence lock
 * @KAPI_LOCK_RCU: RCU lock
 * @KAPI_LOCK_SEMAPHORE: Semaphore
 * @KAPI_LOCK_CUSTOM: Custom locking mechanism
 */
enum kapi_lock_type {
	KAPI_LOCK_NONE = 0,
	KAPI_LOCK_MUTEX,
	KAPI_LOCK_SPINLOCK,
	KAPI_LOCK_RWLOCK,
	KAPI_LOCK_SEQLOCK,
	KAPI_LOCK_RCU,
	KAPI_LOCK_SEMAPHORE,
	KAPI_LOCK_CUSTOM,
};

/**
 * enum kapi_constraint_type - Types of parameter constraints
 * @KAPI_CONSTRAINT_NONE: No constraint
 * @KAPI_CONSTRAINT_RANGE: Numeric range constraint
 * @KAPI_CONSTRAINT_MASK: Bitmask constraint
 * @KAPI_CONSTRAINT_ENUM: Enumerated values constraint
 * @KAPI_CONSTRAINT_CUSTOM: Custom validation function
 */
enum kapi_constraint_type {
	KAPI_CONSTRAINT_NONE = 0,
	KAPI_CONSTRAINT_RANGE,
	KAPI_CONSTRAINT_MASK,
	KAPI_CONSTRAINT_ENUM,
	KAPI_CONSTRAINT_CUSTOM,
};

/**
 * struct kapi_param_spec - Parameter specification
 * @name: Parameter name
 * @type_name: Type name as string
 * @type: Parameter type classification
 * @flags: Parameter attribute flags
 * @size: Size in bytes (for arrays/buffers)
 * @alignment: Required alignment
 * @min_value: Minimum valid value (for numeric types)
 * @max_value: Maximum valid value (for numeric types)
 * @valid_mask: Valid bits mask (for flag parameters)
 * @enum_values: Array of valid enumerated values
 * @enum_count: Number of valid enumerated values
 * @constraint_type: Type of constraint applied
 * @validate: Custom validation function
 * @description: Human-readable description
 * @constraints: Additional constraints description
 * @size_param_idx: Index of parameter that determines size (-1 if fixed size)
 * @size_multiplier: Multiplier for size calculation (e.g., sizeof(struct))
 */
struct kapi_param_spec {
	char name[KAPI_MAX_NAME_LEN];
	char type_name[KAPI_MAX_NAME_LEN];
	enum kapi_param_type type;
	u32 flags;
	size_t size;
	size_t alignment;
	s64 min_value;
	s64 max_value;
	u64 valid_mask;
	const s64 *enum_values;
	u32 enum_count;
	enum kapi_constraint_type constraint_type;
	bool (*validate)(s64 value);
	char description[KAPI_MAX_DESC_LEN];
	char constraints[KAPI_MAX_DESC_LEN];
	int size_param_idx;	/* Index of param that determines size, -1 if N/A */
	size_t size_multiplier;	/* Size per unit (e.g., sizeof(struct epoll_event)) */
} __attribute__((packed));

/**
 * struct kapi_error_spec - Error condition specification
 * @error_code: Error code value
 * @name: Error code name (e.g., "EINVAL")
 * @condition: Condition that triggers this error
 * @description: Detailed error description
 */
struct kapi_error_spec {
	int error_code;
	char name[KAPI_MAX_NAME_LEN];
	char condition[KAPI_MAX_DESC_LEN];
	char description[KAPI_MAX_DESC_LEN];
} __attribute__((packed));

/**
 * enum kapi_return_check_type - Return value check types
 * @KAPI_RETURN_EXACT: Success is an exact value
 * @KAPI_RETURN_RANGE: Success is within a range
 * @KAPI_RETURN_ERROR_CHECK: Success is when NOT in error list
 * @KAPI_RETURN_FD: Return value is a file descriptor (>= 0 is success)
 * @KAPI_RETURN_CUSTOM: Custom validation function
 */
enum kapi_return_check_type {
	KAPI_RETURN_EXACT,
	KAPI_RETURN_RANGE,
	KAPI_RETURN_ERROR_CHECK,
	KAPI_RETURN_FD,
	KAPI_RETURN_CUSTOM,
};

/**
 * struct kapi_return_spec - Return value specification
 * @type_name: Return type name
 * @type: Return type classification
 * @check_type: Type of success check to perform
 * @success_value: Exact value indicating success (for EXACT)
 * @success_min: Minimum success value (for RANGE)
 * @success_max: Maximum success value (for RANGE)
 * @error_values: Array of error values (for ERROR_CHECK)
 * @error_count: Number of error values
 * @is_success: Custom function to check success
 * @description: Return value description
 */
struct kapi_return_spec {
	char type_name[KAPI_MAX_NAME_LEN];
	enum kapi_param_type type;
	enum kapi_return_check_type check_type;
	s64 success_value;
	s64 success_min;
	s64 success_max;
	const s64 *error_values;
	u32 error_count;
	bool (*is_success)(s64 retval);
	char description[KAPI_MAX_DESC_LEN];
} __attribute__((packed));

/**
 * struct kapi_lock_spec - Lock requirement specification
 * @lock_name: Name of the lock
 * @lock_type: Type of lock
 * @acquired: Whether function acquires this lock
 * @released: Whether function releases this lock
 * @held_on_entry: Whether lock must be held on entry
 * @held_on_exit: Whether lock is held on exit
 * @description: Additional lock requirements
 */
struct kapi_lock_spec {
	char lock_name[KAPI_MAX_NAME_LEN];
	enum kapi_lock_type lock_type;
	bool acquired;
	bool released;
	bool held_on_entry;
	bool held_on_exit;
	char description[KAPI_MAX_DESC_LEN];
} __attribute__((packed));

/**
 * struct kapi_constraint_spec - Additional constraint specification
 * @name: Constraint name
 * @description: Constraint description
 * @expression: Formal expression (if applicable)
 */
struct kapi_constraint_spec {
	char name[KAPI_MAX_NAME_LEN];
	char description[KAPI_MAX_DESC_LEN];
	char expression[KAPI_MAX_DESC_LEN];
} __attribute__((packed));

/**
 * enum kapi_signal_direction - Signal flow direction
 * @KAPI_SIGNAL_RECEIVE: Function may receive this signal
 * @KAPI_SIGNAL_SEND: Function may send this signal
 * @KAPI_SIGNAL_HANDLE: Function handles this signal specially
 * @KAPI_SIGNAL_BLOCK: Function blocks this signal
 * @KAPI_SIGNAL_IGNORE: Function ignores this signal
 */
enum kapi_signal_direction {
	KAPI_SIGNAL_RECEIVE	= (1 << 0),
	KAPI_SIGNAL_SEND	= (1 << 1),
	KAPI_SIGNAL_HANDLE	= (1 << 2),
	KAPI_SIGNAL_BLOCK	= (1 << 3),
	KAPI_SIGNAL_IGNORE	= (1 << 4),
};

/**
 * enum kapi_signal_action - What the function does with the signal
 * @KAPI_SIGNAL_ACTION_DEFAULT: Default signal action applies
 * @KAPI_SIGNAL_ACTION_TERMINATE: Causes termination
 * @KAPI_SIGNAL_ACTION_COREDUMP: Causes termination with core dump
 * @KAPI_SIGNAL_ACTION_STOP: Stops the process
 * @KAPI_SIGNAL_ACTION_CONTINUE: Continues a stopped process
 * @KAPI_SIGNAL_ACTION_CUSTOM: Custom handling described in notes
 * @KAPI_SIGNAL_ACTION_RETURN: Returns from syscall with EINTR
 * @KAPI_SIGNAL_ACTION_RESTART: Restarts the syscall
 */
enum kapi_signal_action {
	KAPI_SIGNAL_ACTION_DEFAULT = 0,
	KAPI_SIGNAL_ACTION_TERMINATE,
	KAPI_SIGNAL_ACTION_COREDUMP,
	KAPI_SIGNAL_ACTION_STOP,
	KAPI_SIGNAL_ACTION_CONTINUE,
	KAPI_SIGNAL_ACTION_CUSTOM,
	KAPI_SIGNAL_ACTION_RETURN,
	KAPI_SIGNAL_ACTION_RESTART,
};

/**
 * struct kapi_signal_spec - Signal specification
 * @signal_num: Signal number (e.g., SIGKILL, SIGTERM)
 * @signal_name: Signal name as string
 * @direction: Direction flags (OR of kapi_signal_direction)
 * @action: What happens when signal is received
 * @target: Description of target process/thread for sent signals
 * @condition: Condition under which signal is sent/received/handled
 * @description: Detailed description of signal handling
 * @restartable: Whether syscall is restartable after this signal
 */
struct kapi_signal_spec {
	int signal_num;
	char signal_name[32];
	u32 direction;
	enum kapi_signal_action action;
	char target[KAPI_MAX_DESC_LEN];
	char condition[KAPI_MAX_DESC_LEN];
	char description[KAPI_MAX_DESC_LEN];
	bool restartable;
} __attribute__((packed));

/**
 * struct kapi_signal_mask_spec - Signal mask specification
 * @mask_name: Name of the signal mask
 * @signals: Array of signal numbers in the mask
 * @signal_count: Number of signals in the mask
 * @description: Description of what this mask represents
 */
struct kapi_signal_mask_spec {
	char mask_name[KAPI_MAX_NAME_LEN];
	int signals[KAPI_MAX_SIGNALS];
	u32 signal_count;
	char description[KAPI_MAX_DESC_LEN];
} __attribute__((packed));

/**
 * struct kapi_struct_field - Structure field specification
 * @name: Field name
 * @type: Field type classification
 * @type_name: Type name as string
 * @offset: Offset within structure
 * @size: Size of field in bytes
 * @flags: Field attribute flags
 * @constraint_type: Type of constraint applied
 * @min_value: Minimum valid value (for numeric types)
 * @max_value: Maximum valid value (for numeric types)
 * @valid_mask: Valid bits mask (for flag fields)
 * @description: Field description
 */
struct kapi_struct_field {
	char name[KAPI_MAX_NAME_LEN];
	enum kapi_param_type type;
	char type_name[KAPI_MAX_NAME_LEN];
	size_t offset;
	size_t size;
	u32 flags;
	enum kapi_constraint_type constraint_type;
	s64 min_value;
	s64 max_value;
	u64 valid_mask;
	char description[KAPI_MAX_DESC_LEN];
} __attribute__((packed));

/**
 * struct kapi_struct_spec - Structure type specification
 * @name: Structure name
 * @size: Total size of structure
 * @alignment: Required alignment
 * @field_count: Number of fields
 * @fields: Field specifications
 * @description: Structure description
 */
struct kapi_struct_spec {
	char name[KAPI_MAX_NAME_LEN];
	size_t size;
	size_t alignment;
	u32 field_count;
	struct kapi_struct_field fields[KAPI_MAX_PARAMS];
	char description[KAPI_MAX_DESC_LEN];
} __attribute__((packed));

/**
 * enum kapi_side_effect_type - Types of side effects
 * @KAPI_EFFECT_NONE: No side effects
 * @KAPI_EFFECT_ALLOC_MEMORY: Allocates memory
 * @KAPI_EFFECT_FREE_MEMORY: Frees memory
 * @KAPI_EFFECT_MODIFY_STATE: Modifies global/shared state
 * @KAPI_EFFECT_SIGNAL_SEND: Sends signals
 * @KAPI_EFFECT_FILE_POSITION: Modifies file position
 * @KAPI_EFFECT_LOCK_ACQUIRE: Acquires locks
 * @KAPI_EFFECT_LOCK_RELEASE: Releases locks
 * @KAPI_EFFECT_RESOURCE_CREATE: Creates system resources (FDs, PIDs, etc)
 * @KAPI_EFFECT_RESOURCE_DESTROY: Destroys system resources
 * @KAPI_EFFECT_SCHEDULE: May cause scheduling/context switch
 * @KAPI_EFFECT_HARDWARE: Interacts with hardware
 * @KAPI_EFFECT_NETWORK: Network I/O operation
 * @KAPI_EFFECT_FILESYSTEM: Filesystem modification
 * @KAPI_EFFECT_PROCESS_STATE: Modifies process state
 */
enum kapi_side_effect_type {
	KAPI_EFFECT_NONE = 0,
	KAPI_EFFECT_ALLOC_MEMORY = (1 << 0),
	KAPI_EFFECT_FREE_MEMORY = (1 << 1),
	KAPI_EFFECT_MODIFY_STATE = (1 << 2),
	KAPI_EFFECT_SIGNAL_SEND = (1 << 3),
	KAPI_EFFECT_FILE_POSITION = (1 << 4),
	KAPI_EFFECT_LOCK_ACQUIRE = (1 << 5),
	KAPI_EFFECT_LOCK_RELEASE = (1 << 6),
	KAPI_EFFECT_RESOURCE_CREATE = (1 << 7),
	KAPI_EFFECT_RESOURCE_DESTROY = (1 << 8),
	KAPI_EFFECT_SCHEDULE = (1 << 9),
	KAPI_EFFECT_HARDWARE = (1 << 10),
	KAPI_EFFECT_NETWORK = (1 << 11),
	KAPI_EFFECT_FILESYSTEM = (1 << 12),
	KAPI_EFFECT_PROCESS_STATE = (1 << 13),
};

/**
 * struct kapi_side_effect - Side effect specification
 * @type: Bitmask of effect types
 * @target: What is affected (e.g., "process memory", "file descriptor table")
 * @condition: Condition under which effect occurs
 * @description: Detailed description of the effect
 * @reversible: Whether the effect can be undone
 */
struct kapi_side_effect {
	u32 type;
	char target[KAPI_MAX_NAME_LEN];
	char condition[KAPI_MAX_DESC_LEN];
	char description[KAPI_MAX_DESC_LEN];
	bool reversible;
} __attribute__((packed));

/**
 * struct kapi_state_transition - State transition specification
 * @from_state: Starting state description
 * @to_state: Ending state description
 * @condition: Condition for transition
 * @object: Object whose state changes
 * @description: Detailed description
 */
struct kapi_state_transition {
	char from_state[KAPI_MAX_NAME_LEN];
	char to_state[KAPI_MAX_NAME_LEN];
	char condition[KAPI_MAX_DESC_LEN];
	char object[KAPI_MAX_NAME_LEN];
	char description[KAPI_MAX_DESC_LEN];
} __attribute__((packed));

#define KAPI_MAX_STRUCT_SPECS	8
#define KAPI_MAX_SIDE_EFFECTS	16
#define KAPI_MAX_STATE_TRANS	8

/**
 * struct kernel_api_spec - Complete kernel API specification
 * @name: Function name
 * @version: API version
 * @description: Brief description
 * @long_description: Detailed description
 * @context_flags: Execution context flags
 * @param_count: Number of parameters
 * @params: Parameter specifications
 * @return_spec: Return value specification
 * @error_count: Number of possible errors
 * @errors: Error specifications
 * @lock_count: Number of lock specifications
 * @locks: Lock requirement specifications
 * @constraint_count: Number of additional constraints
 * @constraints: Additional constraint specifications
 * @examples: Usage examples
 * @notes: Additional notes
 * @since_version: Kernel version when introduced
 * @deprecated: Whether API is deprecated
 * @replacement: Replacement API if deprecated
 * @signal_count: Number of signal specifications
 * @signals: Signal handling specifications
 * @signal_mask_count: Number of signal mask specifications
 * @signal_masks: Signal mask specifications
 * @struct_spec_count: Number of structure specifications
 * @struct_specs: Structure type specifications
 * @side_effect_count: Number of side effect specifications
 * @side_effects: Side effect specifications
 * @state_trans_count: Number of state transition specifications
 * @state_transitions: State transition specifications
 */
struct kernel_api_spec {
	char name[KAPI_MAX_NAME_LEN];
	u32 version;
	char description[KAPI_MAX_DESC_LEN];
	char long_description[KAPI_MAX_DESC_LEN * 4];
	u32 context_flags;

	/* Parameters */
	u32 param_count;
	struct kapi_param_spec params[KAPI_MAX_PARAMS];

	/* Return value */
	struct kapi_return_spec return_spec;

	/* Errors */
	u32 error_count;
	struct kapi_error_spec errors[KAPI_MAX_ERRORS];

	/* Locking */
	u32 lock_count;
	struct kapi_lock_spec locks[KAPI_MAX_CONSTRAINTS];

	/* Constraints */
	u32 constraint_count;
	struct kapi_constraint_spec constraints[KAPI_MAX_CONSTRAINTS];

	/* Additional information */
	char examples[KAPI_MAX_DESC_LEN * 2];
	char notes[KAPI_MAX_DESC_LEN];
	char since_version[32];
	bool deprecated;
	char replacement[KAPI_MAX_NAME_LEN];

	/* Signal specifications */
	u32 signal_count;
	struct kapi_signal_spec signals[KAPI_MAX_SIGNALS];

	/* Signal mask specifications */
	u32 signal_mask_count;
	struct kapi_signal_mask_spec signal_masks[KAPI_MAX_SIGNALS];

	/* Structure specifications */
	u32 struct_spec_count;
	struct kapi_struct_spec struct_specs[KAPI_MAX_STRUCT_SPECS];

	/* Side effects */
	u32 side_effect_count;
	struct kapi_side_effect side_effects[KAPI_MAX_SIDE_EFFECTS];

	/* State transitions */
	u32 state_trans_count;
	struct kapi_state_transition state_transitions[KAPI_MAX_STATE_TRANS];
} __attribute__((packed));

/* Macros for defining API specifications */

/**
 * DEFINE_KERNEL_API_SPEC - Define a kernel API specification
 * @func_name: Function name to specify
 */
#define DEFINE_KERNEL_API_SPEC(func_name) \
	static struct kernel_api_spec __kapi_spec_##func_name \
	__used __section(".kapi_specs") = {	\
		.name = __stringify(func_name),	\
		.version = 1,

#define KAPI_END_SPEC };

/**
 * KAPI_DESCRIPTION - Set API description
 * @desc: Description string
 */
#define KAPI_DESCRIPTION(desc) \
	.description = desc,

/**
 * KAPI_LONG_DESC - Set detailed API description
 * @desc: Detailed description string
 */
#define KAPI_LONG_DESC(desc) \
	.long_description = desc,

/**
 * KAPI_CONTEXT - Set execution context flags
 * @flags: Context flags (OR'ed KAPI_CTX_* values)
 */
#define KAPI_CONTEXT(flags) \
	.context_flags = flags,

/**
 * KAPI_PARAM - Define a parameter specification
 * @idx: Parameter index (0-based)
 * @pname: Parameter name
 * @ptype: Type name string
 * @pdesc: Parameter description
 */
#define KAPI_PARAM(idx, pname, ptype, pdesc) \
	.params[idx] = {			\
		.name = pname,			\
		.type_name = ptype,		\
		.description = pdesc,		\
		.size_param_idx = -1,		/* Default: no dynamic sizing */

#define KAPI_PARAM_FLAGS(pflags) \
		.flags = pflags,

#define KAPI_PARAM_SIZE(psize) \
		.size = psize,

#define KAPI_PARAM_RANGE(pmin, pmax) \
		.min_value = pmin,	\
		.max_value = pmax,

#define KAPI_PARAM_END },

/**
 * KAPI_RETURN - Define return value specification
 * @rtype: Return type name
 * @rdesc: Return value description
 */
#define KAPI_RETURN(rtype, rdesc) \
	.return_spec = {		\
		.type_name = rtype,	\
		.description = rdesc,

#define KAPI_RETURN_SUCCESS(val) \
		.success_value = val,

#define KAPI_RETURN_END },

/**
 * KAPI_ERROR - Define an error condition
 * @idx: Error index
 * @ecode: Error code value
 * @ename: Error name
 * @econd: Error condition
 * @edesc: Error description
 */
#define KAPI_ERROR(idx, ecode, ename, econd, edesc) \
	.errors[idx] = {			\
		.error_code = ecode,		\
		.name = ename,			\
		.condition = econd,		\
		.description = edesc,		\
	},

/**
 * KAPI_LOCK - Define a lock requirement
 * @idx: Lock index
 * @lname: Lock name
 * @ltype: Lock type
 */
#define KAPI_LOCK(idx, lname, ltype) \
	.locks[idx] = {			\
		.lock_name = lname,	\
		.lock_type = ltype,

#define KAPI_LOCK_ACQUIRED \
		.acquired = true,

#define KAPI_LOCK_RELEASED \
		.released = true,

#define KAPI_LOCK_HELD_ENTRY \
		.held_on_entry = true,

#define KAPI_LOCK_HELD_EXIT \
		.held_on_exit = true,

#define KAPI_LOCK_DESC(ldesc) \
		.description = ldesc,

#define KAPI_LOCK_END },

/**
 * KAPI_CONSTRAINT - Define an additional constraint
 * @idx: Constraint index
 * @cname: Constraint name
 * @cdesc: Constraint description
 */
#define KAPI_CONSTRAINT(idx, cname, cdesc) \
	.constraints[idx] = {		\
		.name = cname,		\
		.description = cdesc,

#define KAPI_CONSTRAINT_EXPR(expr) \
		.expression = expr,

#define KAPI_CONSTRAINT_END },

/**
 * KAPI_SIGNAL - Define a signal specification
 * @idx: Signal index
 * @signum: Signal number (e.g., SIGKILL)
 * @signame: Signal name string
 * @dir: Direction flags
 * @act: Action taken
 */
#define KAPI_SIGNAL(idx, signum, signame, dir, act) \
	.signals[idx] = {			\
		.signal_num = signum,		\
		.signal_name = signame,		\
		.direction = dir,		\
		.action = act,

#define KAPI_SIGNAL_TARGET(tgt) \
		.target = tgt,

#define KAPI_SIGNAL_CONDITION(cond) \
		.condition = cond,

#define KAPI_SIGNAL_DESC(desc) \
		.description = desc,

#define KAPI_SIGNAL_RESTARTABLE \
		.restartable = true,

#define KAPI_SIGNAL_END },

/**
 * KAPI_SIGNAL_MASK - Define a signal mask specification
 * @idx: Mask index
 * @name: Mask name
 * @desc: Mask description
 */
#define KAPI_SIGNAL_MASK(idx, name, desc) \
	.signal_masks[idx] = {		\
		.mask_name = name,	\
		.description = desc,

#define KAPI_SIGNAL_MASK_ADD(signum) \
		.signals[.signal_count++] = signum,

#define KAPI_SIGNAL_MASK_END },

/**
 * KAPI_STRUCT_SPEC - Define a structure specification
 * @idx: Structure spec index
 * @sname: Structure name
 * @sdesc: Structure description
 */
#define KAPI_STRUCT_SPEC(idx, sname, sdesc) \
	.struct_specs[idx] = {		\
		.name = #sname,		\
		.description = sdesc,

#define KAPI_STRUCT_SIZE(ssize, salign) \
		.size = ssize,		\
		.alignment = salign,

#define KAPI_STRUCT_FIELD_COUNT(n) \
		.field_count = n,

/**
 * KAPI_STRUCT_FIELD - Define a structure field
 * @fidx: Field index
 * @fname: Field name
 * @ftype: Field type (KAPI_TYPE_*)
 * @ftype_name: Type name as string
 * @fdesc: Field description
 */
#define KAPI_STRUCT_FIELD(fidx, fname, ftype, ftype_name, fdesc) \
		.fields[fidx] = {	\
			.name = fname,	\
			.type = ftype,	\
			.type_name = ftype_name, \
			.description = fdesc,

#define KAPI_FIELD_OFFSET(foffset) \
			.offset = foffset,

#define KAPI_FIELD_SIZE(fsize) \
			.size = fsize,

#define KAPI_FIELD_FLAGS(fflags) \
			.flags = fflags,

#define KAPI_FIELD_CONSTRAINT_RANGE(min, max) \
			.constraint_type = KAPI_CONSTRAINT_RANGE, \
			.min_value = min, \
			.max_value = max,

#define KAPI_FIELD_CONSTRAINT_MASK(mask) \
			.constraint_type = KAPI_CONSTRAINT_MASK, \
			.valid_mask = mask,

#define KAPI_FIELD_CONSTRAINT_ENUM(values, count) \
			.constraint_type = KAPI_CONSTRAINT_ENUM, \
			.enum_values = values, \
			.enum_count = count,

#define KAPI_STRUCT_FIELD_END },

#define KAPI_STRUCT_SPEC_END },

/* Counter for structure specifications */
#define KAPI_STRUCT_SPEC_COUNT(n) \
	.struct_spec_count = n,

/**
 * KAPI_SIDE_EFFECT - Define a side effect
 * @idx: Side effect index
 * @etype: Effect type bitmask (OR'ed KAPI_EFFECT_* values)
 * @etarget: What is affected
 * @edesc: Effect description
 */
#define KAPI_SIDE_EFFECT(idx, etype, etarget, edesc) \
	.side_effects[idx] = {		\
		.type = etype,		\
		.target = etarget,	\
		.description = edesc,	\
		.reversible = false,	/* Default to non-reversible */

#define KAPI_EFFECT_CONDITION(cond) \
		.condition = cond,

#define KAPI_EFFECT_REVERSIBLE \
		.reversible = true,

#define KAPI_SIDE_EFFECT_END },

/**
 * KAPI_STATE_TRANS - Define a state transition
 * @idx: State transition index
 * @obj: Object whose state changes
 * @from: From state
 * @to: To state
 * @desc: Transition description
 */
#define KAPI_STATE_TRANS(idx, obj, from, to, desc) \
	.state_transitions[idx] = {	\
		.object = obj,		\
		.from_state = from,	\
		.to_state = to,		\
		.description = desc,

#define KAPI_STATE_TRANS_COND(cond) \
		.condition = cond,

#define KAPI_STATE_TRANS_END },

/* Counters for side effects and state transitions */
#define KAPI_SIDE_EFFECT_COUNT(n) \
	.side_effect_count = n,

#define KAPI_STATE_TRANS_COUNT(n) \
	.state_trans_count = n,

/* Helper macros for common side effect patterns */
#define KAPI_EFFECTS_MEMORY	(KAPI_EFFECT_ALLOC_MEMORY | KAPI_EFFECT_FREE_MEMORY)
#define KAPI_EFFECTS_LOCKING	(KAPI_EFFECT_LOCK_ACQUIRE | KAPI_EFFECT_LOCK_RELEASE)
#define KAPI_EFFECTS_RESOURCES	(KAPI_EFFECT_RESOURCE_CREATE | KAPI_EFFECT_RESOURCE_DESTROY)
#define KAPI_EFFECTS_IO		(KAPI_EFFECT_NETWORK | KAPI_EFFECT_FILESYSTEM)

/* Helper macros for common patterns */

#define KAPI_PARAM_IN		(KAPI_PARAM_IN)
#define KAPI_PARAM_OUT		(KAPI_PARAM_OUT)
#define KAPI_PARAM_INOUT	(KAPI_PARAM_IN | KAPI_PARAM_OUT)
#define KAPI_PARAM_OPTIONAL	(KAPI_PARAM_OPTIONAL)
#define KAPI_PARAM_USER_PTR	(KAPI_PARAM_USER | KAPI_PARAM_PTR)

/* Validation and runtime checking */

#ifdef CONFIG_KAPI_RUNTIME_CHECKS
bool kapi_validate_params(const struct kernel_api_spec *spec, ...);
bool kapi_validate_param(const struct kapi_param_spec *param_spec, s64 value);
bool kapi_validate_param_with_context(const struct kapi_param_spec *param_spec,
				       s64 value, const s64 *all_params, int param_count);
int kapi_validate_syscall_param(const struct kernel_api_spec *spec,
				int param_idx, s64 value);
int kapi_validate_syscall_params(const struct kernel_api_spec *spec,
				 const s64 *params, int param_count);
bool kapi_check_return_success(const struct kapi_return_spec *return_spec, s64 retval);
bool kapi_validate_return_value(const struct kernel_api_spec *spec, s64 retval);
int kapi_validate_syscall_return(const struct kernel_api_spec *spec, s64 retval);
void kapi_check_context(const struct kernel_api_spec *spec);
void kapi_check_locks(const struct kernel_api_spec *spec);
#else
static inline bool kapi_validate_params(const struct kernel_api_spec *spec, ...)
{
	return true;
}
static inline bool kapi_validate_param(const struct kapi_param_spec *param_spec, s64 value)
{
	return true;
}
static inline bool kapi_validate_param_with_context(const struct kapi_param_spec *param_spec,
						     s64 value, const s64 *all_params, int param_count)
{
	return true;
}
static inline int kapi_validate_syscall_param(const struct kernel_api_spec *spec,
					       int param_idx, s64 value)
{
	return 0;
}
static inline int kapi_validate_syscall_params(const struct kernel_api_spec *spec,
					       const s64 *params, int param_count)
{
	return 0;
}
static inline bool kapi_check_return_success(const struct kapi_return_spec *return_spec, s64 retval)
{
	return true;
}
static inline bool kapi_validate_return_value(const struct kernel_api_spec *spec, s64 retval)
{
	return true;
}
static inline int kapi_validate_syscall_return(const struct kernel_api_spec *spec, s64 retval)
{
	return 0;
}
static inline void kapi_check_context(const struct kernel_api_spec *spec) {}
static inline void kapi_check_locks(const struct kernel_api_spec *spec) {}
#endif

/* Export/query functions */
const struct kernel_api_spec *kapi_get_spec(const char *name);
int kapi_export_json(const struct kernel_api_spec *spec, char *buf, size_t size);
int kapi_export_xml(const struct kernel_api_spec *spec, char *buf, size_t size);
void kapi_print_spec(const struct kernel_api_spec *spec);

/* Registration for dynamic APIs */
int kapi_register_spec(struct kernel_api_spec *spec);
void kapi_unregister_spec(const char *name);

/* Helper to get parameter constraint info */
static inline bool kapi_get_param_constraint(const char *api_name, int param_idx,
					      enum kapi_constraint_type *type,
					      u64 *valid_mask, s64 *min_val, s64 *max_val)
{
	const struct kernel_api_spec *spec = kapi_get_spec(api_name);

	if (!spec || param_idx >= spec->param_count)
		return false;

	if (type)
		*type = spec->params[param_idx].constraint_type;
	if (valid_mask)
		*valid_mask = spec->params[param_idx].valid_mask;
	if (min_val)
		*min_val = spec->params[param_idx].min_value;
	if (max_val)
		*max_val = spec->params[param_idx].max_value;

	return true;
}

#endif /* _LINUX_KERNEL_API_SPEC_H */