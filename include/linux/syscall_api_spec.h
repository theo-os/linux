/* SPDX-License-Identifier: GPL-2.0 */
/*
 * syscall_api_spec.h - System Call API Specification Integration
 *
 * This header extends the SYSCALL_DEFINEX macros to support inline API specifications,
 * allowing syscall documentation to be written alongside the implementation in a
 * human-readable and machine-parseable format.
 */

#ifndef _LINUX_SYSCALL_API_SPEC_H
#define _LINUX_SYSCALL_API_SPEC_H

#include <linux/kernel_api_spec.h>

/*
 * Extended SYSCALL_DEFINE macros with API specification support
 *
 * Usage example:
 *
 * SYSCALL_DEFINE_SPEC2(example,
 *     KAPI_DESCRIPTION("Example system call"),
 *     KAPI_LONG_DESC("This is a detailed description of the example syscall"),
 *     KAPI_CONTEXT(KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE),
 *
 *     KAPI_PARAM(0, "fd", "int", "File descriptor to operate on")
 *         KAPI_PARAM_FLAGS(KAPI_PARAM_IN)
 *         KAPI_PARAM_RANGE(0, INT_MAX)
 *     KAPI_PARAM_END,
 *
 *     KAPI_PARAM(1, "flags", "unsigned int", "Operation flags")
 *         KAPI_PARAM_FLAGS(KAPI_PARAM_IN)
 *     KAPI_PARAM_END,
 *
 *     KAPI_RETURN("long", "0 on success, negative error code on failure")
 *         KAPI_RETURN_SUCCESS(0, "== 0")
 *     KAPI_RETURN_END,
 *
 *     KAPI_ERROR(0, -EBADF, "EBADF", "fd is not a valid file descriptor",
 *                "The file descriptor is invalid or closed"),
 *     KAPI_ERROR(1, -EINVAL, "EINVAL", "flags contains invalid values",
 *                "Invalid flag combination specified"),
 *
 *     .error_count = 2,
 *     .param_count = 2,
 *
 *     int, fd, unsigned int, flags)
 * {
 *     // Implementation here
 * }
 */

/* Helper to count parameters */
#define __SYSCALL_PARAM_COUNT(...) __SYSCALL_PARAM_COUNT_I(__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0)
#define __SYSCALL_PARAM_COUNT_I(_1, _2, _3, _4, _5, _6, N, ...) N

/* Extract syscall name from parameters */
#define __SYSCALL_NAME(name, ...) name

/* Generate API spec structure name */
#define __SYSCALL_API_SPEC_NAME(name) __kapi_spec_sys_##name

/* Helper to count syscall parameters (pairs of type, name) */
#define __SYSCALL_ARG_COUNT(...) __SYSCALL_ARG_COUNT_I(__VA_ARGS__, 6, 6, 5, 5, 4, 4, 3, 3, 2, 2, 1, 1, 0)
#define __SYSCALL_ARG_COUNT_I(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, N, ...) N

/* Automatic syscall validation infrastructure */
#ifdef CONFIG_KAPI_RUNTIME_CHECKS

/* Helper to inject validation at the beginning of syscall */
#define __KAPI_SYSCALL_VALIDATE_0(name)
#define __KAPI_SYSCALL_VALIDATE_1(name, t1, a1) \
	const struct kernel_api_spec *__spec = kapi_get_spec("sys_" #name); \
	if (__spec) { \
		s64 __params[1] = { (s64)(a1) }; \
		int __ret = kapi_validate_syscall_params(__spec, __params, 1); \
		if (__ret) return __ret; \
	}
#define __KAPI_SYSCALL_VALIDATE_2(name, t1, a1, t2, a2) \
	const struct kernel_api_spec *__spec = kapi_get_spec("sys_" #name); \
	if (__spec) { \
		s64 __params[2] = { (s64)(a1), (s64)(a2) }; \
		int __ret = kapi_validate_syscall_params(__spec, __params, 2); \
		if (__ret) return __ret; \
	}
#define __KAPI_SYSCALL_VALIDATE_3(name, t1, a1, t2, a2, t3, a3) \
	const struct kernel_api_spec *__spec = kapi_get_spec("sys_" #name); \
	if (__spec) { \
		s64 __params[3] = { (s64)(a1), (s64)(a2), (s64)(a3) }; \
		int __ret = kapi_validate_syscall_params(__spec, __params, 3); \
		if (__ret) return __ret; \
	}
#define __KAPI_SYSCALL_VALIDATE_4(name, t1, a1, t2, a2, t3, a3, t4, a4) \
	const struct kernel_api_spec *__spec = kapi_get_spec("sys_" #name); \
	if (__spec) { \
		s64 __params[4] = { (s64)(a1), (s64)(a2), (s64)(a3), (s64)(a4) }; \
		int __ret = kapi_validate_syscall_params(__spec, __params, 4); \
		if (__ret) return __ret; \
	}
#define __KAPI_SYSCALL_VALIDATE_5(name, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5) \
	const struct kernel_api_spec *__spec = kapi_get_spec("sys_" #name); \
	if (__spec) { \
		s64 __params[5] = { (s64)(a1), (s64)(a2), (s64)(a3), (s64)(a4), (s64)(a5) }; \
		int __ret = kapi_validate_syscall_params(__spec, __params, 5); \
		if (__ret) return __ret; \
	}
#define __KAPI_SYSCALL_VALIDATE_6(name, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6) \
	const struct kernel_api_spec *__spec = kapi_get_spec("sys_" #name); \
	if (__spec) { \
		s64 __params[6] = { (s64)(a1), (s64)(a2), (s64)(a3), (s64)(a4), (s64)(a5), (s64)(a6) }; \
		int __ret = kapi_validate_syscall_params(__spec, __params, 6); \
		if (__ret) return __ret; \
	}

#else /* !CONFIG_KAPI_RUNTIME_CHECKS */

#define __KAPI_SYSCALL_VALIDATE_0(name)
#define __KAPI_SYSCALL_VALIDATE_1(name, t1, a1)
#define __KAPI_SYSCALL_VALIDATE_2(name, t1, a1, t2, a2)
#define __KAPI_SYSCALL_VALIDATE_3(name, t1, a1, t2, a2, t3, a3)
#define __KAPI_SYSCALL_VALIDATE_4(name, t1, a1, t2, a2, t3, a3, t4, a4)
#define __KAPI_SYSCALL_VALIDATE_5(name, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)
#define __KAPI_SYSCALL_VALIDATE_6(name, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)

#endif /* CONFIG_KAPI_RUNTIME_CHECKS */

/* Helper to inject validation for return values */
#ifdef CONFIG_KAPI_RUNTIME_CHECKS

#define __KAPI_SYSCALL_VALIDATE_RETURN(name, retval) \
	do { \
		const struct kernel_api_spec *__spec = kapi_get_spec("sys_" #name); \
		if (__spec) { \
			kapi_validate_syscall_return(__spec, (s64)(retval)); \
		} \
	} while (0)

/* Wrapper to validate both params and return value */
#define __SYSCALL_DEFINE_SPEC(name, spec_args, ...) \
	DEFINE_KERNEL_API_SPEC(sys_##name) \
		.name = "sys_" #name, \
		spec_args \
	KAPI_END_SPEC; \
	static long __kapi_sys_##name(__MAP((__SYSCALL_ARG_COUNT(__VA_ARGS__)), __SC_DECL, __VA_ARGS__)); \
	SYSCALL_DEFINE##__SYSCALL_ARG_COUNT(__VA_ARGS__)(name, __VA_ARGS__) \
	{ \
		long __ret; \
		__KAPI_SYSCALL_VALIDATE_##__SYSCALL_ARG_COUNT(__VA_ARGS__)(name, __VA_ARGS__); \
		__ret = __kapi_sys_##name(__MAP((__SYSCALL_ARG_COUNT(__VA_ARGS__)), __SC_CAST, __VA_ARGS__)); \
		__KAPI_SYSCALL_VALIDATE_RETURN(name, __ret); \
		return __ret; \
	} \
	static long __kapi_sys_##name(__MAP((__SYSCALL_ARG_COUNT(__VA_ARGS__)), __SC_DECL, __VA_ARGS__))

#else /* !CONFIG_KAPI_RUNTIME_CHECKS */

#define __SYSCALL_DEFINE_SPEC(name, spec_args, ...) \
	DEFINE_KERNEL_API_SPEC(sys_##name) \
		.name = "sys_" #name, \
		spec_args \
	KAPI_END_SPEC; \
	SYSCALL_DEFINE##__SYSCALL_ARG_COUNT(__VA_ARGS__)(name, __VA_ARGS__)

#endif /* CONFIG_KAPI_RUNTIME_CHECKS */


/* Convenience macros for different parameter counts */
#define SYSCALL_DEFINE_SPEC0(name, spec_args)				\
	DEFINE_KERNEL_API_SPEC(sys_##name)				\
		.name = "sys_" #name,					\
		.param_count = 0,					\
		spec_args						\
	KAPI_END_SPEC;							\
	SYSCALL_DEFINE0(name)

#define SYSCALL_DEFINE_SPEC1(name, spec_args, t1, a1)			\
	__SYSCALL_DEFINE_SPEC(name, spec_args, t1, a1)

#define SYSCALL_DEFINE_SPEC2(name, spec_args, t1, a1, t2, a2)		\
	__SYSCALL_DEFINE_SPEC(name, spec_args, t1, a1, t2, a2)

#define SYSCALL_DEFINE_SPEC3(name, spec_args, t1, a1, t2, a2, t3, a3)	\
	__SYSCALL_DEFINE_SPEC(name, spec_args, t1, a1, t2, a2, t3, a3)

#define SYSCALL_DEFINE_SPEC4(name, spec_args, t1, a1, t2, a2, t3, a3,	\
			     t4, a4)					\
	__SYSCALL_DEFINE_SPEC(name, spec_args, t1, a1, t2, a2, t3, a3, t4, a4)

#define SYSCALL_DEFINE_SPEC5(name, spec_args, t1, a1, t2, a2, t3, a3,	\
			     t4, a4, t5, a5)				\
	__SYSCALL_DEFINE_SPEC(name, spec_args, t1, a1, t2, a2, t3, a3,	\
			      t4, a4, t5, a5)

#define SYSCALL_DEFINE_SPEC6(name, spec_args, t1, a1, t2, a2, t3, a3,	\
			     t4, a4, t5, a5, t6, a6)			\
	__SYSCALL_DEFINE_SPEC(name, spec_args, t1, a1, t2, a2, t3, a3,	\
			      t4, a4, t5, a5, t6, a6)

/*
 * Helper macros for common syscall patterns
 */

/* For syscalls that can sleep */
#define KAPI_SYSCALL_SLEEPABLE \
	KAPI_CONTEXT(KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE)

/* For syscalls that must be atomic */
#define KAPI_SYSCALL_ATOMIC \
	KAPI_CONTEXT(KAPI_CTX_PROCESS | KAPI_CTX_ATOMIC)

/* Common parameter specifications */
#define KAPI_PARAM_FD(idx, desc) \
	KAPI_PARAM(idx, "fd", "int", desc) \
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN) \
		.type = KAPI_TYPE_FD, \
		.constraint_type = KAPI_CONSTRAINT_NONE, \
	KAPI_PARAM_END

#define KAPI_PARAM_USER_BUF(idx, name, desc) \
	KAPI_PARAM(idx, name, "void __user *", desc) \
		KAPI_PARAM_FLAGS(KAPI_PARAM_USER_PTR | KAPI_PARAM_IN) \
	KAPI_PARAM_END

#define KAPI_PARAM_USER_STRUCT(idx, name, struct_type, desc) \
	KAPI_PARAM(idx, name, #struct_type " __user *", desc) \
		KAPI_PARAM_FLAGS(KAPI_PARAM_USER | KAPI_PARAM_IN) \
		.type = KAPI_TYPE_USER_PTR, \
		.size = sizeof(struct_type), \
		.constraint_type = KAPI_CONSTRAINT_NONE, \
	KAPI_PARAM_END

#define KAPI_PARAM_SIZE_T(idx, name, desc) \
	KAPI_PARAM(idx, name, "size_t", desc) \
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN) \
		KAPI_PARAM_RANGE(0, SIZE_MAX) \
	KAPI_PARAM_END

/* Common error specifications */
#define KAPI_ERROR_EBADF(idx) \
	KAPI_ERROR(idx, -EBADF, "EBADF", "Invalid file descriptor", \
		   "The file descriptor is not valid or has been closed")

#define KAPI_ERROR_EINVAL(idx, condition) \
	KAPI_ERROR(idx, -EINVAL, "EINVAL", condition, \
		   "Invalid argument provided")

#define KAPI_ERROR_ENOMEM(idx) \
	KAPI_ERROR(idx, -ENOMEM, "ENOMEM", "Insufficient memory", \
		   "Cannot allocate memory for the operation")

#define KAPI_ERROR_EPERM(idx) \
	KAPI_ERROR(idx, -EPERM, "EPERM", "Operation not permitted", \
		   "The calling process does not have the required permissions")

#define KAPI_ERROR_EFAULT(idx) \
	KAPI_ERROR(idx, -EFAULT, "EFAULT", "Bad address", \
		   "Invalid user space address provided")

/* Standard return value specifications */
#define KAPI_RETURN_SUCCESS_ZERO \
	KAPI_RETURN("long", "0 on success, negative error code on failure") \
		KAPI_RETURN_SUCCESS(0, "== 0") \
	KAPI_RETURN_END

#define KAPI_RETURN_FD_SPEC \
	KAPI_RETURN("long", "File descriptor on success, negative error code on failure") \
		.check_type = KAPI_RETURN_FD, \
	KAPI_RETURN_END

#define KAPI_RETURN_COUNT \
	KAPI_RETURN("long", "Number of bytes processed on success, negative error code on failure") \
		KAPI_RETURN_SUCCESS(0, ">= 0") \
	KAPI_RETURN_END


/*
 * Compat syscall support
 */
#ifdef CONFIG_COMPAT

#define COMPAT_SYSCALL_DEFINE_SPEC0(name, spec_args) \
	DEFINE_KERNEL_API_SPEC(compat_sys_##name) \
		.name = "compat_sys_" #name, \
		.param_count = 0, \
		spec_args \
	KAPI_END_SPEC; \
	COMPAT_SYSCALL_DEFINE0(name)

#define COMPAT_SYSCALL_DEFINE_SPEC1(name, spec_args, t1, a1) \
	DEFINE_KERNEL_API_SPEC(compat_sys_##name) \
		.name = "compat_sys_" #name, \
		.param_count = 1, \
		spec_args \
	KAPI_END_SPEC; \
	COMPAT_SYSCALL_DEFINE1(name, t1, a1)

#define COMPAT_SYSCALL_DEFINE_SPEC2(name, spec_args, t1, a1, t2, a2) \
	DEFINE_KERNEL_API_SPEC(compat_sys_##name) \
		.name = "compat_sys_" #name, \
		.param_count = 2, \
		spec_args \
	KAPI_END_SPEC; \
	COMPAT_SYSCALL_DEFINE2(name, t1, a1, t2, a2)

#define COMPAT_SYSCALL_DEFINE_SPEC3(name, spec_args, t1, a1, t2, a2, t3, a3) \
	DEFINE_KERNEL_API_SPEC(compat_sys_##name) \
		.name = "compat_sys_" #name, \
		.param_count = 3, \
		spec_args \
	KAPI_END_SPEC; \
	COMPAT_SYSCALL_DEFINE3(name, t1, a1, t2, a2, t3, a3)

#define COMPAT_SYSCALL_DEFINE_SPEC4(name, spec_args, t1, a1, t2, a2, t3, a3, \
				     t4, a4) \
	DEFINE_KERNEL_API_SPEC(compat_sys_##name) \
		.name = "compat_sys_" #name, \
		.param_count = 4, \
		spec_args \
	KAPI_END_SPEC; \
	COMPAT_SYSCALL_DEFINE4(name, t1, a1, t2, a2, t3, a3, t4, a4)

#define COMPAT_SYSCALL_DEFINE_SPEC5(name, spec_args, t1, a1, t2, a2, t3, a3, \
				     t4, a4, t5, a5) \
	DEFINE_KERNEL_API_SPEC(compat_sys_##name) \
		.name = "compat_sys_" #name, \
		.param_count = 5, \
		spec_args \
	KAPI_END_SPEC; \
	COMPAT_SYSCALL_DEFINE5(name, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)

#define COMPAT_SYSCALL_DEFINE_SPEC6(name, spec_args, t1, a1, t2, a2, t3, a3, \
				     t4, a4, t5, a5, t6, a6) \
	DEFINE_KERNEL_API_SPEC(compat_sys_##name) \
		.name = "compat_sys_" #name, \
		.param_count = 6, \
		spec_args \
	KAPI_END_SPEC; \
	COMPAT_SYSCALL_DEFINE6(name, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)

#endif /* CONFIG_COMPAT */

#endif /* _LINUX_SYSCALL_API_SPEC_H */