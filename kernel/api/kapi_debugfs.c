// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel API specification debugfs interface
 *
 * This provides a debugfs interface to expose kernel API specifications
 * at runtime, allowing tools and users to query the complete API specs.
 */

#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/kernel_api_spec.h>
#include <linux/slab.h>
#include <linux/string.h>

/* External symbols for kernel API spec section */
extern struct kernel_api_spec __start_kapi_specs[];
extern struct kernel_api_spec __stop_kapi_specs[];

static struct dentry *kapi_debugfs_root;

/* Helper function to print parameter type as string */
static const char *param_type_str(enum kapi_param_type type)
{
	switch (type) {
	case KAPI_TYPE_INT: return "int";
	case KAPI_TYPE_UINT: return "uint";
	case KAPI_TYPE_PTR: return "ptr";
	case KAPI_TYPE_STRUCT: return "struct";
	case KAPI_TYPE_UNION: return "union";
	case KAPI_TYPE_ARRAY: return "array";
	case KAPI_TYPE_FD: return "fd";
	case KAPI_TYPE_ENUM: return "enum";
	case KAPI_TYPE_USER_PTR: return "user_ptr";
	case KAPI_TYPE_PATH: return "path";
	case KAPI_TYPE_FUNC_PTR: return "func_ptr";
	case KAPI_TYPE_CUSTOM: return "custom";
	default: return "unknown";
	}
}

/* Helper to print parameter flags */
static void print_param_flags(struct seq_file *m, u32 flags)
{
	seq_printf(m, "    flags: ");
	if (flags & KAPI_PARAM_IN) seq_printf(m, "IN ");
	if (flags & KAPI_PARAM_OUT) seq_printf(m, "OUT ");
	if (flags & KAPI_PARAM_INOUT) seq_printf(m, "INOUT ");
	if (flags & KAPI_PARAM_OPTIONAL) seq_printf(m, "OPTIONAL ");
	if (flags & KAPI_PARAM_CONST) seq_printf(m, "CONST ");
	if (flags & KAPI_PARAM_USER) seq_printf(m, "USER ");
	if (flags & KAPI_PARAM_VOLATILE) seq_printf(m, "VOLATILE ");
	if (flags & KAPI_PARAM_DMA) seq_printf(m, "DMA ");
	if (flags & KAPI_PARAM_ALIGNED) seq_printf(m, "ALIGNED ");
	seq_printf(m, "\n");
}

/* Helper to print context flags */
static void print_context_flags(struct seq_file *m, u32 flags)
{
	seq_printf(m, "Context flags: ");
	if (flags & KAPI_CTX_PROCESS) seq_printf(m, "PROCESS ");
	if (flags & KAPI_CTX_HARDIRQ) seq_printf(m, "HARDIRQ ");
	if (flags & KAPI_CTX_SOFTIRQ) seq_printf(m, "SOFTIRQ ");
	if (flags & KAPI_CTX_NMI) seq_printf(m, "NMI ");
	if (flags & KAPI_CTX_SLEEPABLE) seq_printf(m, "SLEEPABLE ");
	if (flags & KAPI_CTX_ATOMIC) seq_printf(m, "ATOMIC ");
	if (flags & KAPI_CTX_PREEMPT_DISABLED) seq_printf(m, "PREEMPT_DISABLED ");
	if (flags & KAPI_CTX_IRQ_DISABLED) seq_printf(m, "IRQ_DISABLED ");
	seq_printf(m, "\n");
}

/* Show function for individual API spec */
static int kapi_spec_show(struct seq_file *m, void *v)
{
	struct kernel_api_spec *spec = m->private;
	int i;

	seq_printf(m, "Kernel API Specification\n");
	seq_printf(m, "========================\n\n");

	/* Basic info */
	seq_printf(m, "Name: %s\n", spec->name);
	seq_printf(m, "Version: %u\n", spec->version);
	seq_printf(m, "Description: %s\n", spec->description);
	if (strlen(spec->long_description) > 0)
		seq_printf(m, "Long description: %s\n", spec->long_description);

	/* Context */
	print_context_flags(m, spec->context_flags);
	seq_printf(m, "\n");

	/* Parameters */
	if (spec->param_count > 0) {
		seq_printf(m, "Parameters (%u):\n", spec->param_count);
		for (i = 0; i < spec->param_count; i++) {
			struct kapi_param_spec *param = &spec->params[i];
			seq_printf(m, "  [%d] %s:\n", i, param->name);
			seq_printf(m, "    type: %s (%s)\n",
				   param_type_str(param->type), param->type_name);
			print_param_flags(m, param->flags);
			if (strlen(param->description) > 0)
				seq_printf(m, "    description: %s\n", param->description);
			if (param->size > 0)
				seq_printf(m, "    size: %zu\n", param->size);
			if (param->alignment > 0)
				seq_printf(m, "    alignment: %zu\n", param->alignment);

			/* Print constraints if any */
			if (param->constraint_type != KAPI_CONSTRAINT_NONE) {
				seq_printf(m, "    constraints:\n");
				switch (param->constraint_type) {
				case KAPI_CONSTRAINT_RANGE:
					seq_printf(m, "      type: range\n");
					seq_printf(m, "      min: %lld\n", param->min_value);
					seq_printf(m, "      max: %lld\n", param->max_value);
					break;
				case KAPI_CONSTRAINT_MASK:
					seq_printf(m, "      type: mask\n");
					seq_printf(m, "      valid_bits: 0x%llx\n", param->valid_mask);
					break;
				case KAPI_CONSTRAINT_ENUM:
					seq_printf(m, "      type: enum\n");
					seq_printf(m, "      count: %u\n", param->enum_count);
					break;
				case KAPI_CONSTRAINT_CUSTOM:
					seq_printf(m, "      type: custom\n");
					if (strlen(param->constraints) > 0)
						seq_printf(m, "      description: %s\n",
							   param->constraints);
					break;
				default:
					break;
				}
			}
			seq_printf(m, "\n");
		}
	}

	/* Return value */
	seq_printf(m, "Return value:\n");
	seq_printf(m, "  type: %s\n", spec->return_spec.type_name);
	if (strlen(spec->return_spec.description) > 0)
		seq_printf(m, "  description: %s\n", spec->return_spec.description);

	switch (spec->return_spec.check_type) {
	case KAPI_RETURN_EXACT:
		seq_printf(m, "  success: == %lld\n", spec->return_spec.success_value);
		break;
	case KAPI_RETURN_RANGE:
		seq_printf(m, "  success: [%lld, %lld]\n",
			   spec->return_spec.success_min,
			   spec->return_spec.success_max);
		break;
	case KAPI_RETURN_FD:
		seq_printf(m, "  success: valid file descriptor (>= 0)\n");
		break;
	case KAPI_RETURN_ERROR_CHECK:
		seq_printf(m, "  success: error check\n");
		break;
	case KAPI_RETURN_CUSTOM:
		seq_printf(m, "  success: custom check\n");
		break;
	default:
		break;
	}
	seq_printf(m, "\n");

	/* Errors */
	if (spec->error_count > 0) {
		seq_printf(m, "Errors (%u):\n", spec->error_count);
		for (i = 0; i < spec->error_count; i++) {
			struct kapi_error_spec *err = &spec->errors[i];
			seq_printf(m, "  %s (%d): %s\n",
				   err->name, err->error_code, err->description);
			if (strlen(err->condition) > 0)
				seq_printf(m, "    condition: %s\n", err->condition);
		}
		seq_printf(m, "\n");
	}

	/* Locks */
	if (spec->lock_count > 0) {
		seq_printf(m, "Locks (%u):\n", spec->lock_count);
		for (i = 0; i < spec->lock_count; i++) {
			struct kapi_lock_spec *lock = &spec->locks[i];
			const char *type_str;
			switch (lock->lock_type) {
			case KAPI_LOCK_MUTEX: type_str = "mutex"; break;
			case KAPI_LOCK_SPINLOCK: type_str = "spinlock"; break;
			case KAPI_LOCK_RWLOCK: type_str = "rwlock"; break;
			case KAPI_LOCK_SEMAPHORE: type_str = "semaphore"; break;
			case KAPI_LOCK_RCU: type_str = "rcu"; break;
			case KAPI_LOCK_SEQLOCK: type_str = "seqlock"; break;
			default: type_str = "unknown"; break;
			}
			seq_printf(m, "  %s (%s): %s\n",
				   lock->lock_name, type_str, lock->description);
			if (lock->acquired)
				seq_printf(m, "    acquired by function\n");
			if (lock->released)
				seq_printf(m, "    released by function\n");
		}
		seq_printf(m, "\n");
	}

	/* Constraints */
	if (spec->constraint_count > 0) {
		seq_printf(m, "Additional constraints (%u):\n", spec->constraint_count);
		for (i = 0; i < spec->constraint_count; i++) {
			seq_printf(m, "  - %s\n", spec->constraints[i].description);
		}
		seq_printf(m, "\n");
	}

	/* Signals */
	if (spec->signal_count > 0) {
		seq_printf(m, "Signal handling (%u):\n", spec->signal_count);
		for (i = 0; i < spec->signal_count; i++) {
			struct kapi_signal_spec *sig = &spec->signals[i];
			seq_printf(m, "  %s (%d):\n", sig->signal_name, sig->signal_num);
			seq_printf(m, "    direction: ");
			if (sig->direction & KAPI_SIGNAL_SEND) seq_printf(m, "send ");
			if (sig->direction & KAPI_SIGNAL_RECEIVE) seq_printf(m, "receive ");
			if (sig->direction & KAPI_SIGNAL_HANDLE) seq_printf(m, "handle ");
			if (sig->direction & KAPI_SIGNAL_BLOCK) seq_printf(m, "block ");
			if (sig->direction & KAPI_SIGNAL_IGNORE) seq_printf(m, "ignore ");
			seq_printf(m, "\n");
			seq_printf(m, "    action: ");
			switch (sig->action) {
			case KAPI_SIGNAL_ACTION_DEFAULT: seq_printf(m, "default"); break;
			case KAPI_SIGNAL_ACTION_TERMINATE: seq_printf(m, "terminate"); break;
			case KAPI_SIGNAL_ACTION_COREDUMP: seq_printf(m, "coredump"); break;
			case KAPI_SIGNAL_ACTION_STOP: seq_printf(m, "stop"); break;
			case KAPI_SIGNAL_ACTION_CONTINUE: seq_printf(m, "continue"); break;
			case KAPI_SIGNAL_ACTION_CUSTOM: seq_printf(m, "custom"); break;
			case KAPI_SIGNAL_ACTION_RETURN: seq_printf(m, "return"); break;
			case KAPI_SIGNAL_ACTION_RESTART: seq_printf(m, "restart"); break;
			default: seq_printf(m, "unknown"); break;
			}
			seq_printf(m, "\n");
			if (strlen(sig->description) > 0)
				seq_printf(m, "    description: %s\n", sig->description);
		}
		seq_printf(m, "\n");
	}

	/* Additional info */
	if (strlen(spec->examples) > 0) {
		seq_printf(m, "Examples:\n%s\n\n", spec->examples);
	}
	if (strlen(spec->notes) > 0) {
		seq_printf(m, "Notes:\n%s\n\n", spec->notes);
	}
	if (strlen(spec->since_version) > 0) {
		seq_printf(m, "Since: %s\n", spec->since_version);
	}
	if (spec->deprecated) {
		seq_printf(m, "DEPRECATED");
		if (strlen(spec->replacement) > 0)
			seq_printf(m, " - use %s instead", spec->replacement);
		seq_printf(m, "\n");
	}

	return 0;
}

static int kapi_spec_open(struct inode *inode, struct file *file)
{
	return single_open(file, kapi_spec_show, inode->i_private);
}

static const struct file_operations kapi_spec_fops = {
	.open = kapi_spec_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* Show all available API specs */
static int kapi_list_show(struct seq_file *m, void *v)
{
	struct kernel_api_spec *spec;
	int count = 0;

	seq_printf(m, "Available Kernel API Specifications\n");
	seq_printf(m, "===================================\n\n");

	for (spec = __start_kapi_specs; spec < __stop_kapi_specs; spec++) {
		seq_printf(m, "%s - %s\n", spec->name, spec->description);
		count++;
	}

	seq_printf(m, "\nTotal: %d specifications\n", count);
	return 0;
}

static int kapi_list_open(struct inode *inode, struct file *file)
{
	return single_open(file, kapi_list_show, NULL);
}

static const struct file_operations kapi_list_fops = {
	.open = kapi_list_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int __init kapi_debugfs_init(void)
{
	struct kernel_api_spec *spec;
	struct dentry *spec_dir;

	/* Create main directory */
	kapi_debugfs_root = debugfs_create_dir("kapi", NULL);

	/* Create list file */
	debugfs_create_file("list", 0444, kapi_debugfs_root, NULL, &kapi_list_fops);

	/* Create specs subdirectory */
	spec_dir = debugfs_create_dir("specs", kapi_debugfs_root);

	/* Create a file for each API spec */
	for (spec = __start_kapi_specs; spec < __stop_kapi_specs; spec++) {
		debugfs_create_file(spec->name, 0444, spec_dir, spec, &kapi_spec_fops);
	}

	pr_info("Kernel API debugfs interface initialized\n");
	return 0;
}

static void __exit kapi_debugfs_exit(void)
{
	debugfs_remove_recursive(kapi_debugfs_root);
}

/* Initialize as part of kernel, not as a module */
fs_initcall(kapi_debugfs_init);