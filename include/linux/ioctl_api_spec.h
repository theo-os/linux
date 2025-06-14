/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ioctl_api_spec.h - IOCTL API specification framework
 *
 * Extends the kernel API specification framework to support ioctl validation
 * and documentation.
 */

#ifndef _LINUX_IOCTL_API_SPEC_H
#define _LINUX_IOCTL_API_SPEC_H

#include <linux/kernel_api_spec.h>
#include <linux/ioctl.h>
#include <linux/types.h>

/* Forward declarations */
struct file;

/**
 * struct kapi_ioctl_spec - IOCTL-specific API specification
 * @api_spec: Base API specification
 * @cmd: IOCTL command number
 * @cmd_name: Human-readable command name
 * @input_size: Size of input structure (0 if none)
 * @output_size: Size of output structure (0 if none)
 * @file_ops_name: Name of the file_operations structure
 */
struct kapi_ioctl_spec {
	struct kernel_api_spec api_spec;
	unsigned int cmd;
	const char *cmd_name;
	size_t input_size;
	size_t output_size;
	const char *file_ops_name;
};

/* Registry functions for IOCTL specifications */
#ifdef CONFIG_KAPI_SPEC
int kapi_register_ioctl_spec(const struct kapi_ioctl_spec *spec);
void kapi_unregister_ioctl_spec(unsigned int cmd);
const struct kapi_ioctl_spec *kapi_get_ioctl_spec(unsigned int cmd);

/* IOCTL validation functions */
#ifdef CONFIG_KAPI_RUNTIME_CHECKS
int kapi_validate_ioctl(struct file *filp, unsigned int cmd, void __user *arg);
int kapi_validate_ioctl_struct(const struct kapi_ioctl_spec *spec,
			       const void *data, size_t size);
#else
static inline int kapi_validate_ioctl(struct file *filp, unsigned int cmd,
				      void __user *arg)
{
	return 0;
}
#endif /* CONFIG_KAPI_RUNTIME_CHECKS */

#else /* !CONFIG_KAPI_SPEC */
static inline int kapi_register_ioctl_spec(const struct kapi_ioctl_spec *spec)
{
	return 0;
}
static inline void kapi_unregister_ioctl_spec(unsigned int cmd) {}
static inline const struct kapi_ioctl_spec *kapi_get_ioctl_spec(unsigned int cmd)
{
	return NULL;
}
#endif /* CONFIG_KAPI_SPEC */

/* Helper macros for IOCTL specification */

/**
 * DEFINE_IOCTL_API_SPEC - Start an IOCTL API specification
 * @name: Unique identifier for the specification
 * @cmd: IOCTL command number
 * @cmd_name_str: String name of the command
 */
#define DEFINE_IOCTL_API_SPEC(name, cmd, cmd_name_str)			\
static const struct kapi_ioctl_spec name##_spec = {			\
	.cmd = cmd,							\
	.cmd_name = cmd_name_str,					\
	.api_spec = {							\
		.name = #name,

/**
 * KAPI_IOCTL_SIZE - Specify input/output structure sizes
 * @in_size: Size of input structure
 * @out_size: Size of output structure
 */
#define KAPI_IOCTL_SIZE(in_size, out_size)				\
	},								\
	.input_size = in_size,						\
	.output_size = out_size,

/**
 * KAPI_IOCTL_FILE_OPS - Specify the file_operations structure name
 * @ops_name: Name of the file_operations structure
 */
#define KAPI_IOCTL_FILE_OPS(ops_name)					\
	.file_ops_name = #ops_name,

/**
 * Common IOCTL parameter specifications
 */
#define KAPI_IOCTL_PARAM_SIZE							\
	KAPI_PARAM(0, "size", "__u32", "Size of the structure")		\
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN)					\
		.type = KAPI_TYPE_UINT,						\
		.constraint_type = KAPI_CONSTRAINT_CUSTOM,			\
		.constraints = "Must match sizeof(struct)",			\
	KAPI_PARAM_END

#define KAPI_IOCTL_PARAM_FLAGS							\
	KAPI_PARAM(1, "flags", "__u32", "Feature flags")			\
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN)					\
		.type = KAPI_TYPE_UINT,						\
		.constraint_type = KAPI_CONSTRAINT_MASK,			\
		.valid_mask = 0,	/* 0 means no flags currently */	\
	KAPI_PARAM_END

/**
 * KAPI_IOCTL_PARAM_USER_BUF - User buffer parameter
 * @idx: Parameter index
 * @name: Parameter name
 * @desc: Parameter description
 * @len_idx: Index of the length parameter
 */
#define KAPI_IOCTL_PARAM_USER_BUF(idx, name, desc, len_idx)		\
	KAPI_PARAM(idx, name, "__aligned_u64", desc)			\
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN | KAPI_PARAM_USER_PTR)	\
		.type = KAPI_TYPE_USER_PTR,				\
		.size_param_idx = len_idx,				\
	KAPI_PARAM_END

/**
 * KAPI_IOCTL_PARAM_USER_OUT_BUF - User output buffer parameter
 * @idx: Parameter index
 * @name: Parameter name
 * @desc: Parameter description
 * @len_idx: Index of the length parameter
 */
#define KAPI_IOCTL_PARAM_USER_OUT_BUF(idx, name, desc, len_idx)	\
	KAPI_PARAM(idx, name, "__aligned_u64", desc)			\
		KAPI_PARAM_FLAGS(KAPI_PARAM_OUT | KAPI_PARAM_USER_PTR)	\
		.type = KAPI_TYPE_USER_PTR,				\
		.size_param_idx = len_idx,				\
	KAPI_PARAM_END

/**
 * KAPI_IOCTL_PARAM_LEN - Buffer length parameter
 * @idx: Parameter index
 * @name: Parameter name
 * @desc: Parameter description
 * @max_size: Maximum allowed size
 */
#define KAPI_IOCTL_PARAM_LEN(idx, name, desc, max_size)		\
	KAPI_PARAM(idx, name, "__u32", desc)				\
		KAPI_PARAM_FLAGS(KAPI_PARAM_INOUT)			\
		.type = KAPI_TYPE_UINT,					\
		.constraint_type = KAPI_CONSTRAINT_RANGE,		\
		.min_value = 0,						\
		.max_value = max_size,					\
	KAPI_PARAM_END

/* End the IOCTL specification */
#define KAPI_IOCTL_END_SPEC						\
};									\
									\
static int __init name##_spec_init(void)				\
{									\
	return kapi_register_ioctl_spec(&name##_spec);			\
}									\
									\
static void __exit name##_spec_exit(void)				\
{									\
	kapi_unregister_ioctl_spec(name##_spec.cmd);			\
}									\
									\
module_init(name##_spec_init);						\
module_exit(name##_spec_exit);

/* Inline IOCTL specification support */

/* Forward declaration */
struct fwctl_ucmd;

/**
 * struct kapi_ioctl_handler - IOCTL handler with inline specification
 * @spec: IOCTL specification
 * @handler: Original IOCTL handler function
 */
struct kapi_ioctl_handler {
	struct kapi_ioctl_spec spec;
	int (*handler)(struct fwctl_ucmd *ucmd);
};

/**
 * DEFINE_IOCTL_HANDLER - Define an IOCTL handler with inline specification
 * @name: Handler name
 * @cmd: IOCTL command number
 * @handler_func: Handler function
 * @struct_type: Structure type for this IOCTL
 * @last_field: Last field in the structure
 */
#define DEFINE_IOCTL_HANDLER(name, cmd, handler_func, struct_type, last_field)	\
static const struct kapi_ioctl_handler name = {				\
	.spec = {							\
		.cmd = cmd,						\
		.cmd_name = #cmd,					\
		.input_size = sizeof(struct_type),			\
		.output_size = sizeof(struct_type),			\
		.api_spec = {						\
			.name = #name,

#define KAPI_IOCTL_HANDLER_END						\
		},							\
	},								\
	.handler = handler_func,					\
}

/**
 * kapi_ioctl_wrapper - Wrapper function for transparent IOCTL validation
 * @filp: File pointer
 * @cmd: IOCTL command
 * @arg: User argument
 * @real_ioctl: The real ioctl handler
 *
 * This wrapper performs validation before and after the actual IOCTL call
 */
static inline long kapi_ioctl_wrapper(struct file *filp, unsigned int cmd,
				      unsigned long arg,
				      long (*real_ioctl)(struct file *, unsigned int, unsigned long))
{
	long ret;

#ifdef CONFIG_KAPI_RUNTIME_CHECKS
	/* Pre-validation */
	ret = kapi_validate_ioctl(filp, cmd, (void __user *)arg);
	if (ret)
		return ret;
#endif

	/* Call the real IOCTL handler */
	ret = real_ioctl(filp, cmd, arg);

#ifdef CONFIG_KAPI_RUNTIME_CHECKS
	/* Post-validation could be added here if needed */
	/* For example, validating output parameters */
#endif

	return ret;
}

/**
 * KAPI_IOCTL_OPS - Define file_operations with transparent validation
 * @name: Name of the file_operations structure
 * @real_ioctl: The real ioctl handler function
 * @... : Other file operation handlers
 */
#define KAPI_IOCTL_OPS(name, real_ioctl, ...)				\
static long name##_validated_ioctl(struct file *filp, unsigned int cmd, \
				   unsigned long arg)			\
{									\
	return kapi_ioctl_wrapper(filp, cmd, arg, real_ioctl);		\
}									\
									\
static const struct file_operations name = {				\
	.unlocked_ioctl = name##_validated_ioctl,			\
	__VA_ARGS__							\
}

/**
 * KAPI_IOCTL_OP_ENTRY - Define an IOCTL operation table entry with spec
 * @_ioctl: IOCTL command macro
 * @_handler: Handler structure (defined with DEFINE_IOCTL_HANDLER)
 * @_struct: Structure type
 * @_last: Last field name
 */
#define KAPI_IOCTL_OP_ENTRY(_ioctl, _handler, _struct, _last)		\
	[_IOC_NR(_ioctl) - FWCTL_CMD_BASE] = {				\
		.size = sizeof(_struct) +				\
			BUILD_BUG_ON_ZERO(sizeof(union fwctl_ucmd_buffer) < \
					  sizeof(_struct)),		\
		.min_size = offsetofend(_struct, _last),		\
		.ioctl_num = _ioctl,					\
		.execute = _handler.handler,				\
	}

/* Helper to register all handlers in a module */
#define KAPI_REGISTER_IOCTL_HANDLERS(handlers, count)			\
static int __init kapi_ioctl_handlers_init(void)			\
{									\
	int i, ret;							\
	for (i = 0; i < count; i++) {					\
		ret = kapi_register_ioctl_spec(&handlers[i].spec);	\
		if (ret) {						\
			while (--i >= 0)				\
				kapi_unregister_ioctl_spec(handlers[i].spec.cmd); \
			return ret;					\
		}							\
	}								\
	return 0;							\
}									\
									\
static void __exit kapi_ioctl_handlers_exit(void)			\
{									\
	int i;								\
	for (i = 0; i < count; i++)					\
		kapi_unregister_ioctl_spec(handlers[i].spec.cmd);	\
}									\
									\
module_init(kapi_ioctl_handlers_init);					\
module_exit(kapi_ioctl_handlers_exit)

/**
 * KAPI_REGISTER_IOCTL_SPECS - Register an array of IOCTL specifications
 * @specs: Array of pointers to kapi_ioctl_spec
 * @count: Number of specifications
 *
 * This macro generates init/exit functions to register/unregister
 * the IOCTL specifications. The functions return 0 on success or
 * negative error code on failure.
 *
 * Usage:
 *   static const struct kapi_ioctl_spec *my_ioctl_specs[] = {
 *       &spec1, &spec2, &spec3,
 *   };
 *   KAPI_REGISTER_IOCTL_SPECS(my_ioctl_specs, ARRAY_SIZE(my_ioctl_specs))
 *
 * Then call the generated functions in your module init/exit:
 *   ret = kapi_register_##name();
 *   kapi_unregister_##name();
 */
#define KAPI_REGISTER_IOCTL_SPECS(name, specs)				\
static int kapi_register_##name(void)					\
{									\
	int i, ret;							\
	for (i = 0; i < ARRAY_SIZE(specs); i++) {			\
		ret = kapi_register_ioctl_spec(specs[i]);		\
		if (ret) {						\
			pr_warn("Failed to register IOCTL spec for %s: %d\n", \
				specs[i]->cmd_name, ret);		\
			while (--i >= 0)				\
				kapi_unregister_ioctl_spec(specs[i]->cmd); \
			return ret;					\
		}							\
	}								\
	pr_info("Registered %zu IOCTL specifications\n", 		\
		ARRAY_SIZE(specs));					\
	return 0;							\
}									\
									\
static void kapi_unregister_##name(void)				\
{									\
	int i;								\
	for (i = 0; i < ARRAY_SIZE(specs); i++)			\
		kapi_unregister_ioctl_spec(specs[i]->cmd);		\
}

/**
 * KAPI_DEFINE_IOCTL_SPEC - Define a single IOCTL specification
 * @name: Name of the specification variable
 * @cmd: IOCTL command number
 * @cmd_name: String name of the command
 * @in_size: Input structure size
 * @out_size: Output structure size
 * @fops_name: Name of the file_operations structure
 *
 * This macro starts the definition of an IOCTL specification.
 * It must be followed by the API specification details and
 * ended with KAPI_END_IOCTL_SPEC.
 *
 * Example:
 *   KAPI_DEFINE_IOCTL_SPEC(my_ioctl_spec, MY_IOCTL, "MY_IOCTL",
 *                          sizeof(struct my_input), sizeof(struct my_output),
 *                          "my_fops")
 *   KAPI_DESCRIPTION("Description here")
 *   ...
 *   KAPI_END_IOCTL_SPEC;
 */
#define KAPI_DEFINE_IOCTL_SPEC(name, cmd, cmd_name_str, in_size, out_size, fops) \
static const struct kapi_ioctl_spec name = {				\
	.cmd = (cmd),							\
	.cmd_name = cmd_name_str,					\
	.input_size = in_size,						\
	.output_size = out_size,					\
	.file_ops_name = fops,						\
	.api_spec = {							\
		.name = #name,

#define KAPI_END_IOCTL_SPEC						\
	},								\
}

/**
 * KAPI_IOCTL_SPEC_DRIVER - Complete IOCTL specification for a driver
 * @driver_name: Name of the driver (used for logging)
 * @specs_array: Name of the array containing IOCTL spec pointers
 *
 * This macro provides everything needed for IOCTL spec registration:
 * 1. Generates the specs array declaration
 * 2. Creates init/exit functions for registration
 * 3. Provides simple function names to call from module init/exit
 *
 * Usage:
 *   // Define individual specs
 *   KAPI_DEFINE_IOCTL_SPEC(spec1, ...) ... KAPI_END_IOCTL_SPEC;
 *   KAPI_DEFINE_IOCTL_SPEC(spec2, ...) ... KAPI_END_IOCTL_SPEC;
 *
 *   // Create the driver registration (at end of file)
 *   KAPI_IOCTL_SPEC_DRIVER("my_driver", {
 *       &spec1,
 *       &spec2,
 *   })
 *
 *   // In module init: ret = kapi_ioctl_specs_init();
 *   // In module exit: kapi_ioctl_specs_exit();
 */
#define KAPI_IOCTL_SPEC_DRIVER(driver_name, ...)			\
static const struct kapi_ioctl_spec *__kapi_ioctl_specs[] = __VA_ARGS__;									\
									\
static int __init kapi_ioctl_specs_init(void)				\
{									\
	int i, ret;							\
	for (i = 0; i < ARRAY_SIZE(__kapi_ioctl_specs); i++) {		\
		ret = kapi_register_ioctl_spec(__kapi_ioctl_specs[i]);	\
		if (ret) {						\
			pr_warn("%s: Failed to register %s: %d\n",	\
				driver_name,				\
				__kapi_ioctl_specs[i]->cmd_name, ret);	\
			while (--i >= 0)				\
				kapi_unregister_ioctl_spec(		\
					__kapi_ioctl_specs[i]->cmd);	\
			return ret;					\
		}							\
	}								\
	pr_info("%s: Registered %zu IOCTL specifications\n",		\
		driver_name, ARRAY_SIZE(__kapi_ioctl_specs));		\
	return 0;							\
}									\
									\
static void kapi_ioctl_specs_exit(void)				\
{									\
	int i;								\
	for (i = 0; i < ARRAY_SIZE(__kapi_ioctl_specs); i++)		\
		kapi_unregister_ioctl_spec(__kapi_ioctl_specs[i]->cmd);\
}

/* Transparent IOCTL validation wrapper support */

#ifdef CONFIG_KAPI_RUNTIME_CHECKS

/**
 * struct kapi_fops_wrapper - Wrapper for file_operations with validation
 * @real_fops: Original file_operations
 * @wrapped_fops: Modified file_operations with validation wrapper
 * @real_ioctl: Original unlocked_ioctl handler
 */
struct kapi_fops_wrapper {
	const struct file_operations *real_fops;
	const struct file_operations *wrapped_fops;
	long (*real_ioctl)(struct file *, unsigned int, unsigned long);
};

/* Forward declarations */
long kapi_ioctl_validation_wrapper(struct file *filp, unsigned int cmd,
				   unsigned long arg);
void kapi_register_wrapper(struct kapi_fops_wrapper *wrapper);

/**
 * kapi_wrap_file_operations - Wrap file_operations for transparent validation
 * @fops: Original file_operations to wrap
 *
 * This creates a wrapper that intercepts ioctl calls for validation.
 * The wrapper is stored in a static variable in the calling module.
 */
#define kapi_wrap_file_operations(fops)					\
({										\
	static struct kapi_fops_wrapper __kapi_wrapper = {		\
		.real_fops = &(fops),					\
	};								\
	if (__kapi_wrapper.real_fops->unlocked_ioctl) {		\
		__kapi_wrapper.wrapped_fops = (fops);			\
		__kapi_wrapper.real_ioctl = (fops).unlocked_ioctl;	\
		__kapi_wrapper.wrapped_fops.unlocked_ioctl = 		\
			kapi_ioctl_validation_wrapper;			\
		&__kapi_wrapper.wrapped_fops;				\
	} else {							\
		&(fops);						\
	}								\
})


/**
 * KAPI_DEFINE_FOPS - Define file_operations with automatic validation
 * @name: Name of the file_operations structure
 * @... : File operation handlers
 *
 * Usage:
 *   KAPI_DEFINE_FOPS(my_fops,
 *       .owner = THIS_MODULE,
 *       .open = my_open,
 *       .unlocked_ioctl = my_ioctl,
 *   );
 *
 * Then in your module init, call: kapi_init_fops_##name()
 */
#define KAPI_DEFINE_FOPS(name, ...)					\
static const struct file_operations __kapi_real_##name = {		\
	__VA_ARGS__							\
};									\
static struct file_operations __kapi_wrapped_##name;			\
static struct kapi_fops_wrapper __kapi_wrapper_##name;			\
static const struct file_operations *name;				\
static void kapi_init_fops_##name(void)				\
{									\
	if (__kapi_real_##name.unlocked_ioctl) {			\
		__kapi_wrapped_##name = __kapi_real_##name;		\
		__kapi_wrapper_##name.real_fops = &__kapi_real_##name;	\
		__kapi_wrapper_##name.wrapped_fops = &__kapi_wrapped_##name; \
		__kapi_wrapper_##name.real_ioctl = 			\
			__kapi_real_##name.unlocked_ioctl;		\
		__kapi_wrapped_##name.unlocked_ioctl = 		\
			kapi_ioctl_validation_wrapper;			\
		kapi_register_wrapper(&__kapi_wrapper_##name);		\
		name = &__kapi_wrapped_##name;				\
	} else {							\
		name = &__kapi_real_##name;				\
	}								\
}

#else /* !CONFIG_KAPI_RUNTIME_CHECKS */

/* When runtime checks are disabled, no wrapping occurs */
#define kapi_wrap_file_operations(fops) (&(fops))
#define KAPI_DEFINE_FOPS(name, ...) \
static const struct file_operations name = { __VA_ARGS__ }; \
static inline void kapi_init_fops_##name(void) {}

#endif /* CONFIG_KAPI_RUNTIME_CHECKS */

#endif /* _LINUX_IOCTL_API_SPEC_H */