// SPDX-License-Identifier: GPL-2.0
/*
 * ioctl_validation.c - Runtime validation for IOCTL API specifications
 *
 * Provides functions to validate ioctl parameters against their specifications
 * at runtime when CONFIG_KAPI_RUNTIME_CHECKS is enabled.
 */

#include <linux/kernel.h>
#include <linux/kernel_api_spec.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/container_of.h>
#include <linux/export.h>
#include <uapi/fwctl/fwctl.h>

#ifdef CONFIG_KAPI_RUNTIME_CHECKS

/**
 * kapi_validate_ioctl - Validate an ioctl call against its specification
 * @filp: File pointer
 * @cmd: IOCTL command
 * @arg: IOCTL argument
 *
 * Return: 0 if valid, negative errno if validation fails
 */
int kapi_validate_ioctl(struct file *filp, unsigned int cmd, void __user *arg)
{
	const struct kernel_api_spec *spec;
	void *data = NULL;
	size_t copy_size;
	int ret = 0;
	int i;

	spec = kapi_get_ioctl_spec(cmd);
	if (!spec)
		return 0; /* No spec, can't validate */

	pr_debug("kapi: validating ioctl %s (0x%x)\n", spec->cmd_name, cmd);

	/* Check if this ioctl requires specific capabilities */
	if (spec->param_count > 0) {
		for (i = 0; i < spec->param_count; i++) {
			const struct kapi_param_spec *param = &spec->params[i];

			/* Check for capability requirements in constraints */
			if (param->constraint_type == KAPI_CONSTRAINT_CUSTOM &&
			    param->constraints[0] && strstr(param->constraints, "CAP_")) {
				/* Could add capability checks here if needed */
			}
		}
	}

	/* For ioctls with input/output structures, copy and validate */
	if (spec->input_size > 0 || spec->output_size > 0) {
		copy_size = max(spec->input_size, spec->output_size);

		/* Allocate temporary buffer for validation */
		data = kzalloc(copy_size, GFP_KERNEL);
		if (!data)
			return -ENOMEM;

		/* Copy input data from user */
		if (spec->input_size > 0) {
			ret = copy_from_user(data, arg, spec->input_size);
			if (ret) {
				ret = -EFAULT;
				goto out;
			}
		}

		/* Validate structure fields */
		ret = kapi_validate_ioctl_struct(spec, data, copy_size);
		if (ret)
			goto out;
	}

out:
	kfree(data);
	return ret;
}
EXPORT_SYMBOL_GPL(kapi_validate_ioctl);

/**
 * struct field_offset - Maps structure fields to their offsets
 * @field_idx: Parameter index
 * @offset: Offset in structure
 * @size: Size of field
 */
struct field_offset {
	int field_idx;
	size_t offset;
	size_t size;
};

/* Common ioctl structure layouts */
static const struct field_offset fwctl_info_offsets[] = {
	{0, 0, sizeof(u32)},  /* size */
	{1, 4, sizeof(u32)},  /* flags */
	{2, 8, sizeof(u32)},  /* out_device_type */
	{3, 12, sizeof(u32)}, /* device_data_len */
	{4, 16, sizeof(u64)}, /* out_device_data */
};

static const struct field_offset fwctl_rpc_offsets[] = {
	{0, 0, sizeof(u32)},  /* size */
	{1, 4, sizeof(u32)},  /* scope */
	{2, 8, sizeof(u32)},  /* in_len */
	{3, 12, sizeof(u32)}, /* out_len */
	{4, 16, sizeof(u64)}, /* in */
	{5, 24, sizeof(u64)}, /* out */
};

/**
 * get_field_offsets - Get field offset information for an ioctl
 * @cmd: IOCTL command
 * @count: Returns number of fields
 *
 * Return: Array of field offsets or NULL
 */
static const struct field_offset *get_field_offsets(unsigned int cmd, int *count)
{
	switch (cmd) {
	case FWCTL_INFO:
		*count = ARRAY_SIZE(fwctl_info_offsets);
		return fwctl_info_offsets;
	case FWCTL_RPC:
		*count = ARRAY_SIZE(fwctl_rpc_offsets);
		return fwctl_rpc_offsets;
	default:
		*count = 0;
		return NULL;
	}
}

/**
 * extract_field_value - Extract a field value from structure
 * @data: Structure data
 * @param: Parameter specification
 * @offset_info: Field offset information
 *
 * Return: Field value or 0 on error
 */
static s64 extract_field_value(const void *data,
			       const struct kapi_param_spec *param,
			       const struct field_offset *offset_info)
{
	const void *field = data + offset_info->offset;

	switch (param->type) {
	case KAPI_TYPE_UINT:
		if (offset_info->size == sizeof(u32))
			return *(u32 *)field;
		else if (offset_info->size == sizeof(u64))
			return *(u64 *)field;
		break;
	case KAPI_TYPE_INT:
		if (offset_info->size == sizeof(s32))
			return *(s32 *)field;
		else if (offset_info->size == sizeof(s64))
			return *(s64 *)field;
		break;
	case KAPI_TYPE_USER_PTR:
		/* User pointers are typically u64 in ioctl structures */
		return (s64)(*(u64 *)field);
	default:
		break;
	}

	return 0;
}

/**
 * kapi_validate_ioctl_struct - Validate an ioctl structure against specification
 * @spec: IOCTL specification
 * @data: Structure data
 * @size: Size of the structure
 *
 * Return: 0 if valid, negative errno if validation fails
 */
int kapi_validate_ioctl_struct(const struct kernel_api_spec *spec,
				const void *data, size_t size)
{
	const struct field_offset *offsets;
	int offset_count;
	int i, j;

	if (!spec || !data)
		return -EINVAL;

	/* Get field offset information for this ioctl */
	offsets = get_field_offsets(spec->cmd, &offset_count);

	/* Validate each parameter in the structure */
	for (i = 0; i < spec->param_count && i < KAPI_MAX_PARAMS; i++) {
		const struct kapi_param_spec *param = &spec->params[i];
		const struct field_offset *offset_info = NULL;
		s64 value;

		/* Find offset information for this parameter */
		if (offsets) {
			for (j = 0; j < offset_count; j++) {
				if (offsets[j].field_idx == i) {
					offset_info = &offsets[j];
					break;
				}
			}
		}

		if (!offset_info) {
			pr_debug("kapi: no offset info for param %d\n", i);
			continue;
		}

		/* Extract field value */
		value = extract_field_value(data, param, offset_info);

		/* Special handling for user pointers */
		if (param->type == KAPI_TYPE_USER_PTR) {
			/* Check if pointer looks valid (non-kernel address) */
			if (value && (value >= TASK_SIZE)) {
				pr_warn("ioctl %s: parameter %s has kernel pointer %llx\n",
					spec->cmd_name, param->name, value);
				return -EINVAL;
			}

			/* For size validation, check against size_param_idx */
			if (param->size_param_idx >= 0 &&
			    param->size_param_idx < offset_count) {
				const struct field_offset *size_offset = NULL;

				for (j = 0; j < offset_count; j++) {
					if (offsets[j].field_idx == param->size_param_idx) {
						size_offset = &offsets[j];
						break;
					}
				}

				if (size_offset) {
					s64 buf_size = extract_field_value(data,
						&spec->params[param->size_param_idx],
						size_offset);

					/* Validate buffer size constraints */
					if (buf_size > 0 &&
					    !kapi_validate_param(&spec->params[param->size_param_idx],
								 buf_size)) {
						pr_warn("ioctl %s: buffer size %lld invalid for %s\n",
							spec->cmd_name, buf_size, param->name);
						return -EINVAL;
					}
				}
			}
		} else {
			/* Validate using the standard parameter validation */
			if (!kapi_validate_param(param, value)) {
				pr_warn("ioctl %s: parameter %s validation failed (value=%lld)\n",
					spec->cmd_name, param->name, value);
				return -EINVAL;
			}
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(kapi_validate_ioctl_struct);

/* Global registry of wrappers - in real implementation this would be per-module */
static struct kapi_fops_wrapper *kapi_global_wrapper;

/**
 * kapi_register_wrapper - Register a wrapper (called from macro)
 * @wrapper: Wrapper to register
 */
void kapi_register_wrapper(struct kapi_fops_wrapper *wrapper)
{
	/* Simple implementation - just store the last one */
	kapi_global_wrapper = wrapper;
}
EXPORT_SYMBOL_GPL(kapi_register_wrapper);

/**
 * kapi_find_wrapper - Find wrapper for given file_operations
 * @fops: File operations structure to check
 *
 * Return: Wrapper structure or NULL if not wrapped
 */
static struct kapi_fops_wrapper *kapi_find_wrapper(const struct file_operations *fops)
{
	/* Simple implementation - just return the global one if it matches */
	if (kapi_global_wrapper && kapi_global_wrapper->wrapped_fops == fops)
		return kapi_global_wrapper;
	return NULL;
}

/**
 * kapi_ioctl_validation_wrapper - Wrapper function for transparent validation
 * @filp: File pointer
 * @cmd: IOCTL command
 * @arg: User argument
 *
 * This function is called instead of the real ioctl handler when validation
 * is enabled. It performs pre-validation, calls the real handler, then does
 * post-validation.
 *
 * Return: Result from the real ioctl handler or error
 */
long kapi_ioctl_validation_wrapper(struct file *filp, unsigned int cmd,
				   unsigned long arg)
{
	struct kapi_fops_wrapper *wrapper;
	const struct kernel_api_spec *spec;
	long ret;

	wrapper = kapi_find_wrapper(filp->f_op);
	if (!wrapper || !wrapper->real_ioctl)
		return -EINVAL;

	/* Pre-validation */
	spec = kapi_get_ioctl_spec(cmd);
	if (spec) {
		ret = kapi_validate_ioctl(filp, cmd, (void __user *)arg);
		if (ret)
			return ret;
	}

	/* Call the real ioctl handler */
	ret = wrapper->real_ioctl(filp, cmd, arg);

	/* Post-validation - check return value against spec */
	if (spec && spec->error_count > 0) {
		/* Validate that returned error is in the spec */
		if (ret < 0) {
			int i;
			bool found = false;
			for (i = 0; i < spec->error_count; i++) {
				if (ret == spec->errors[i].error_code) {
					found = true;
					break;
				}
			}
			if (!found) {
				pr_warn("IOCTL %s returned unexpected error %ld\n",
					spec->cmd_name, ret);
			}
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(kapi_ioctl_validation_wrapper);

#endif /* CONFIG_KAPI_RUNTIME_CHECKS */
