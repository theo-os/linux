// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024-2025, NVIDIA CORPORATION & AFFILIATES
 */
#define pr_fmt(fmt) "fwctl: " fmt
#include <linux/fwctl.h>

#include <linux/container_of.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/kernel_api_spec.h>

#include <uapi/fwctl/fwctl.h>

enum {
	FWCTL_MAX_DEVICES = 4096,
	MAX_RPC_LEN = SZ_2M,
};
static_assert(FWCTL_MAX_DEVICES < (1U << MINORBITS));

static dev_t fwctl_dev;
static DEFINE_IDA(fwctl_ida);
static unsigned long fwctl_tainted;

struct fwctl_ucmd {
	struct fwctl_uctx *uctx;
	void __user *ubuffer;
	void *cmd;
	u32 user_size;
};

static int ucmd_respond(struct fwctl_ucmd *ucmd, size_t cmd_len)
{
	if (copy_to_user(ucmd->ubuffer, ucmd->cmd,
			 min_t(size_t, ucmd->user_size, cmd_len)))
		return -EFAULT;
	return 0;
}

static int copy_to_user_zero_pad(void __user *to, const void *from,
				 size_t from_len, size_t user_len)
{
	size_t copy_len;

	copy_len = min(from_len, user_len);
	if (copy_to_user(to, from, copy_len))
		return -EFAULT;
	if (copy_len < user_len) {
		if (clear_user(to + copy_len, user_len - copy_len))
			return -EFAULT;
	}
	return 0;
}

static int fwctl_cmd_info(struct fwctl_ucmd *ucmd)
{
	struct fwctl_device *fwctl = ucmd->uctx->fwctl;
	struct fwctl_info *cmd = ucmd->cmd;
	size_t driver_info_len = 0;

	if (cmd->flags)
		return -EOPNOTSUPP;

	if (!fwctl->ops->info && cmd->device_data_len) {
		if (clear_user(u64_to_user_ptr(cmd->out_device_data),
			       cmd->device_data_len))
			return -EFAULT;
	} else if (cmd->device_data_len) {
		void *driver_info __free(kfree) =
			fwctl->ops->info(ucmd->uctx, &driver_info_len);
		if (IS_ERR(driver_info))
			return PTR_ERR(driver_info);

		if (copy_to_user_zero_pad(u64_to_user_ptr(cmd->out_device_data),
					  driver_info, driver_info_len,
					  cmd->device_data_len))
			return -EFAULT;
	}

	cmd->out_device_type = fwctl->ops->device_type;
	cmd->device_data_len = driver_info_len;
	return ucmd_respond(ucmd, sizeof(*cmd));
}

static int fwctl_cmd_rpc(struct fwctl_ucmd *ucmd)
{
	struct fwctl_device *fwctl = ucmd->uctx->fwctl;
	struct fwctl_rpc *cmd = ucmd->cmd;
	size_t out_len;

	if (cmd->in_len > MAX_RPC_LEN || cmd->out_len > MAX_RPC_LEN)
		return -EMSGSIZE;

	switch (cmd->scope) {
	case FWCTL_RPC_CONFIGURATION:
	case FWCTL_RPC_DEBUG_READ_ONLY:
		break;

	case FWCTL_RPC_DEBUG_WRITE_FULL:
		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		fallthrough;
	case FWCTL_RPC_DEBUG_WRITE:
		if (!test_and_set_bit(0, &fwctl_tainted)) {
			dev_warn(
				&fwctl->dev,
				"%s(%d): has requested full access to the physical device",
				current->comm, task_pid_nr(current));
			add_taint(TAINT_FWCTL, LOCKDEP_STILL_OK);
		}
		break;
	default:
		return -EOPNOTSUPP;
	}

	void *inbuf __free(kvfree) = kvzalloc(cmd->in_len, GFP_KERNEL_ACCOUNT);
	if (!inbuf)
		return -ENOMEM;
	if (copy_from_user(inbuf, u64_to_user_ptr(cmd->in), cmd->in_len))
		return -EFAULT;

	out_len = cmd->out_len;
	void *outbuf __free(kvfree) = fwctl->ops->fw_rpc(
		ucmd->uctx, cmd->scope, inbuf, cmd->in_len, &out_len);
	if (IS_ERR(outbuf))
		return PTR_ERR(outbuf);
	if (outbuf == inbuf) {
		/* The driver can re-use inbuf as outbuf */
		inbuf = NULL;
	}

	if (copy_to_user(u64_to_user_ptr(cmd->out), outbuf,
			 min(cmd->out_len, out_len)))
		return -EFAULT;

	cmd->out_len = out_len;
	return ucmd_respond(ucmd, sizeof(*cmd));
}

/* On stack memory for the ioctl structs */
union fwctl_ucmd_buffer {
	struct fwctl_info info;
	struct fwctl_rpc rpc;
};

struct fwctl_ioctl_op {
	unsigned int size;
	unsigned int min_size;
	unsigned int ioctl_num;
	int (*execute)(struct fwctl_ucmd *ucmd);
};

#define IOCTL_OP(_ioctl, _fn, _struct, _last)                               \
	[_IOC_NR(_ioctl) - FWCTL_CMD_BASE] = {                              \
		.size = sizeof(_struct) +                                   \
			BUILD_BUG_ON_ZERO(sizeof(union fwctl_ucmd_buffer) < \
					  sizeof(_struct)),                 \
		.min_size = offsetofend(_struct, _last),                    \
		.ioctl_num = _ioctl,                                        \
		.execute = _fn,                                             \
	}
static const struct fwctl_ioctl_op fwctl_ioctl_ops[] = {
	IOCTL_OP(FWCTL_INFO, fwctl_cmd_info, struct fwctl_info, out_device_data),
	IOCTL_OP(FWCTL_RPC, fwctl_cmd_rpc, struct fwctl_rpc, out),
};

static long fwctl_fops_ioctl(struct file *filp, unsigned int cmd,
			       unsigned long arg)
{
	struct fwctl_uctx *uctx = filp->private_data;
	const struct fwctl_ioctl_op *op;
	struct fwctl_ucmd ucmd = {};
	union fwctl_ucmd_buffer buf;
	unsigned int nr;
	int ret;

	nr = _IOC_NR(cmd);
	if ((nr - FWCTL_CMD_BASE) >= ARRAY_SIZE(fwctl_ioctl_ops))
		return -ENOIOCTLCMD;

	op = &fwctl_ioctl_ops[nr - FWCTL_CMD_BASE];
	if (op->ioctl_num != cmd)
		return -ENOIOCTLCMD;

	ucmd.uctx = uctx;
	ucmd.cmd = &buf;
	ucmd.ubuffer = (void __user *)arg;
	ret = get_user(ucmd.user_size, (u32 __user *)ucmd.ubuffer);
	if (ret)
		return ret;

	if (ucmd.user_size < op->min_size)
		return -EINVAL;

	ret = copy_struct_from_user(ucmd.cmd, op->size, ucmd.ubuffer,
				    ucmd.user_size);
	if (ret)
		return ret;

	guard(rwsem_read)(&uctx->fwctl->registration_lock);
	if (!uctx->fwctl->ops)
		return -ENODEV;
	return op->execute(&ucmd);
}

static int fwctl_fops_open(struct inode *inode, struct file *filp)
{
	struct fwctl_device *fwctl =
		container_of(inode->i_cdev, struct fwctl_device, cdev);
	int ret;

	guard(rwsem_read)(&fwctl->registration_lock);
	if (!fwctl->ops)
		return -ENODEV;

	struct fwctl_uctx *uctx __free(kfree) =
		kzalloc(fwctl->ops->uctx_size, GFP_KERNEL_ACCOUNT);
	if (!uctx)
		return -ENOMEM;

	uctx->fwctl = fwctl;
	ret = fwctl->ops->open_uctx(uctx);
	if (ret)
		return ret;

	scoped_guard(mutex, &fwctl->uctx_list_lock) {
		list_add_tail(&uctx->uctx_list_entry, &fwctl->uctx_list);
	}

	get_device(&fwctl->dev);
	filp->private_data = no_free_ptr(uctx);
	return 0;
}

static void fwctl_destroy_uctx(struct fwctl_uctx *uctx)
{
	lockdep_assert_held(&uctx->fwctl->uctx_list_lock);
	list_del(&uctx->uctx_list_entry);
	uctx->fwctl->ops->close_uctx(uctx);
}

static int fwctl_fops_release(struct inode *inode, struct file *filp)
{
	struct fwctl_uctx *uctx = filp->private_data;
	struct fwctl_device *fwctl = uctx->fwctl;

	scoped_guard(rwsem_read, &fwctl->registration_lock) {
		/*
		 * NULL ops means fwctl_unregister() has already removed the
		 * driver and destroyed the uctx.
		 */
		if (fwctl->ops) {
			guard(mutex)(&fwctl->uctx_list_lock);
			fwctl_destroy_uctx(uctx);
		}
	}

	kfree(uctx);
	fwctl_put(fwctl);
	return 0;
}

/* Use KAPI_DEFINE_FOPS for automatic validation wrapping */
KAPI_DEFINE_FOPS(fwctl_fops,
	.owner = THIS_MODULE,
	.open = fwctl_fops_open,
	.release = fwctl_fops_release,
	.unlocked_ioctl = fwctl_fops_ioctl,
);

/* IOCTL API Specifications */

DEFINE_KAPI_IOCTL_SPEC(fwctl_info)
	KAPI_IOCTL_CMD(FWCTL_INFO)
	KAPI_IOCTL_CMD_NAME("FWCTL_INFO")
	KAPI_IOCTL_INPUT_SIZE(sizeof(struct fwctl_info))
	KAPI_IOCTL_OUTPUT_SIZE(sizeof(struct fwctl_info))
	KAPI_IOCTL_FILE_OPS_NAME("fwctl_fops")
	KAPI_DESCRIPTION("Query device information and capabilities")
	KAPI_LONG_DESC("Returns basic information about the fwctl instance, "
		       "including the device type and driver-specific data. "
		       "The driver-specific data format depends on the device type.")
	KAPI_CONTEXT(KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE)

	/* Parameters */
	KAPI_IOCTL_PARAM_SIZE
	KAPI_IOCTL_PARAM_FLAGS

	KAPI_PARAM(2, "out_device_type", "__u32", "Device type from enum fwctl_device_type")
		KAPI_PARAM_FLAGS(KAPI_PARAM_OUT)
		KAPI_PARAM_TYPE(KAPI_TYPE_UINT)
		KAPI_PARAM_CONSTRAINT_TYPE(KAPI_CONSTRAINT_ENUM)
		KAPI_PARAM_ENUM_VALUES(((const s64[]){FWCTL_DEVICE_TYPE_ERROR,
						      FWCTL_DEVICE_TYPE_MLX5,
						      FWCTL_DEVICE_TYPE_CXL,
						      FWCTL_DEVICE_TYPE_PDS}))
	KAPI_PARAM_END

	KAPI_PARAM(3, "device_data_len", "__u32", "Length of device data buffer")
		KAPI_PARAM_FLAGS(KAPI_PARAM_INOUT)
		KAPI_PARAM_TYPE(KAPI_TYPE_UINT)
		KAPI_PARAM_CONSTRAINT_TYPE(KAPI_CONSTRAINT_RANGE)
		KAPI_PARAM_RANGE(0, SZ_1M)	/* Reasonable limit for device info */
	KAPI_PARAM_END

	KAPI_IOCTL_PARAM_USER_OUT_BUF(4, "out_device_data",
				      "Driver-specific device data", 3)

	/* Return value */
	KAPI_RETURN("int", "0 on success, negative errno on failure")
		KAPI_RETURN_TYPE(KAPI_TYPE_INT)
		KAPI_RETURN_CHECK_TYPE(KAPI_RETURN_ERROR_CHECK)
		KAPI_RETURN_ERROR_VALUES(((const s64[]){-EFAULT, -EOPNOTSUPP, -ENODEV}))
		KAPI_RETURN_ERROR_COUNT(3)
	KAPI_RETURN_END

	/* Errors */
	KAPI_ERROR(0, -EFAULT, "EFAULT", "Failed to copy data to/from user space",
		   "Check that provided pointers are valid user space addresses")
	KAPI_ERROR(1, -EOPNOTSUPP, "EOPNOTSUPP", "Invalid flags provided",
		   "Currently flags must be 0")
	KAPI_ERROR(2, -ENODEV, "ENODEV", "Device has been hot-unplugged",
		   "The underlying device is no longer available")

	KAPI_ERROR_COUNT(3)
	KAPI_PARAM_COUNT(5)
	KAPI_SINCE_VERSION("6.13")

	/* Structure specifications */
	KAPI_STRUCT_SPEC(0, fwctl_info, "Device information query structure")
		KAPI_STRUCT_SIZE(sizeof(struct fwctl_info), __alignof__(struct fwctl_info))
		KAPI_STRUCT_FIELD_COUNT(4)

		KAPI_STRUCT_FIELD(0, "size", KAPI_TYPE_UINT, "__u32",
				  "Structure size for versioning")
			KAPI_FIELD_OFFSET(offsetof(struct fwctl_info, size))
			KAPI_FIELD_SIZE(sizeof(__u32))
		KAPI_STRUCT_FIELD_END

		KAPI_STRUCT_FIELD(1, "flags", KAPI_TYPE_UINT, "__u32",
				  "Must be 0, reserved for future use")
			KAPI_FIELD_OFFSET(offsetof(struct fwctl_info, flags))
			KAPI_FIELD_SIZE(sizeof(__u32))
			KAPI_FIELD_CONSTRAINT_RANGE(0, 0)
		KAPI_STRUCT_FIELD_END

		KAPI_STRUCT_FIELD(2, "out_device_type", KAPI_TYPE_UINT, "__u32",
				  "Device type identifier")
			KAPI_FIELD_OFFSET(offsetof(struct fwctl_info, out_device_type))
			KAPI_FIELD_SIZE(sizeof(__u32))
		KAPI_STRUCT_FIELD_END

		KAPI_STRUCT_FIELD(3, "device_data_len", KAPI_TYPE_UINT, "__u32",
				  "Length of device-specific data")
			KAPI_FIELD_OFFSET(offsetof(struct fwctl_info, device_data_len))
			KAPI_FIELD_SIZE(sizeof(__u32))
		KAPI_STRUCT_FIELD_END
	KAPI_STRUCT_SPEC_END

	KAPI_STRUCT_SPEC_COUNT(1)

	/* Side effects */
	KAPI_SIDE_EFFECT(0, KAPI_EFFECT_NONE,
			 "none",
			 "Read-only operation with no side effects")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT_COUNT(1)

	/* State transitions */
	KAPI_STATE_TRANS_COUNT(0)	/* No state transitions for query operation */
KAPI_END_SPEC;

DEFINE_KAPI_IOCTL_SPEC(fwctl_rpc)
	KAPI_IOCTL_CMD(FWCTL_RPC)
	KAPI_IOCTL_CMD_NAME("FWCTL_RPC")
	KAPI_IOCTL_INPUT_SIZE(sizeof(struct fwctl_rpc))
	KAPI_IOCTL_OUTPUT_SIZE(sizeof(struct fwctl_rpc))
	KAPI_IOCTL_FILE_OPS_NAME("fwctl_fops")
	KAPI_DESCRIPTION("Execute a Remote Procedure Call to device firmware")
	KAPI_LONG_DESC("Delivers an RPC to the device firmware and returns the response. "
		       "The RPC format is device-specific and determined by out_device_type "
		       "from FWCTL_INFO. Different scopes have different permission requirements.")
	KAPI_CONTEXT(KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE)

	/* Parameters */
	KAPI_IOCTL_PARAM_SIZE

	KAPI_PARAM(1, "scope", "__u32", "Access scope from enum fwctl_rpc_scope")
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN)
		KAPI_PARAM_TYPE(KAPI_TYPE_UINT)
		KAPI_PARAM_CONSTRAINT_TYPE(KAPI_CONSTRAINT_ENUM)
		KAPI_PARAM_ENUM_VALUES(((const s64[]){FWCTL_RPC_CONFIGURATION,
						      FWCTL_RPC_DEBUG_READ_ONLY,
						      FWCTL_RPC_DEBUG_WRITE,
						      FWCTL_RPC_DEBUG_WRITE_FULL}))
		KAPI_PARAM_CONSTRAINT("FWCTL_RPC_DEBUG_WRITE_FULL requires CAP_SYS_RAWIO")
	KAPI_PARAM_END

	KAPI_PARAM(2, "in_len", "__u32", "Length of input buffer")
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN)
		KAPI_PARAM_TYPE(KAPI_TYPE_UINT)
		KAPI_PARAM_CONSTRAINT_TYPE(KAPI_CONSTRAINT_RANGE)
		KAPI_PARAM_RANGE(0, MAX_RPC_LEN)
	KAPI_PARAM_END

	KAPI_PARAM(3, "out_len", "__u32", "Length of output buffer")
		KAPI_PARAM_FLAGS(KAPI_PARAM_INOUT)
		KAPI_PARAM_TYPE(KAPI_TYPE_UINT)
		KAPI_PARAM_CONSTRAINT_TYPE(KAPI_CONSTRAINT_RANGE)
		KAPI_PARAM_RANGE(0, MAX_RPC_LEN)
	KAPI_PARAM_END

	KAPI_IOCTL_PARAM_USER_BUF(4, "in", "RPC request in device-specific format", 2)
	KAPI_IOCTL_PARAM_USER_OUT_BUF(5, "out", "RPC response in device-specific format", 3)

	/* Return value */
	KAPI_RETURN("int", "0 on success, negative errno on failure")
		KAPI_RETURN_TYPE(KAPI_TYPE_INT)
		KAPI_RETURN_CHECK_TYPE(KAPI_RETURN_ERROR_CHECK)
		KAPI_RETURN_ERROR_VALUES(((const s64[]){-EMSGSIZE, -EOPNOTSUPP, -EPERM,
					      -ENOMEM, -EFAULT, -ENODEV}))
		KAPI_RETURN_ERROR_COUNT(6)
	KAPI_RETURN_END

	/* Errors */
	KAPI_ERROR(0, -EMSGSIZE, "EMSGSIZE", "RPC message too large",
		   "in_len or out_len exceeds MAX_RPC_LEN (2MB)")
	KAPI_ERROR(1, -EOPNOTSUPP, "EOPNOTSUPP", "Invalid scope value",
		   "scope must be one of the defined fwctl_rpc_scope values")
	KAPI_ERROR(2, -EPERM, "EPERM", "Insufficient permissions",
		   "FWCTL_RPC_DEBUG_WRITE_FULL requires CAP_SYS_RAWIO")
	KAPI_ERROR(3, -ENOMEM, "ENOMEM", "Memory allocation failed",
		   "Unable to allocate buffers for RPC")
	KAPI_ERROR(4, -EFAULT, "EFAULT", "Failed to copy data to/from user space",
		   "Check that provided pointers are valid user space addresses")
	KAPI_ERROR(5, -ENODEV, "ENODEV", "Device has been hot-unplugged",
		   "The underlying device is no longer available")

	KAPI_ERROR_COUNT(6)
	KAPI_PARAM_COUNT(6)
	KAPI_SINCE_VERSION("6.13")
	KAPI_NOTES("FWCTL_RPC_DEBUG_WRITE and FWCTL_RPC_DEBUG_WRITE_FULL will "
		   "taint the kernel with TAINT_FWCTL on first use")

	/* Structure specifications */
	KAPI_STRUCT_SPEC(0, fwctl_rpc, "RPC request/response structure")
		KAPI_STRUCT_SIZE(sizeof(struct fwctl_rpc), __alignof__(struct fwctl_rpc))
		KAPI_STRUCT_FIELD_COUNT(6)

		KAPI_STRUCT_FIELD(0, "size", KAPI_TYPE_UINT, "__u32",
				  "Structure size for versioning")
			KAPI_FIELD_OFFSET(offsetof(struct fwctl_rpc, size))
			KAPI_FIELD_SIZE(sizeof(__u32))
		KAPI_STRUCT_FIELD_END

		KAPI_STRUCT_FIELD(1, "scope", KAPI_TYPE_UINT, "__u32",
				  "Access scope level")
			KAPI_FIELD_OFFSET(offsetof(struct fwctl_rpc, scope))
			KAPI_FIELD_SIZE(sizeof(__u32))
			KAPI_FIELD_CONSTRAINT_RANGE(FWCTL_RPC_CONFIGURATION, FWCTL_RPC_DEBUG_WRITE_FULL)
		KAPI_STRUCT_FIELD_END

		KAPI_STRUCT_FIELD(2, "in_len", KAPI_TYPE_UINT, "__u32",
				  "Input data length")
			KAPI_FIELD_OFFSET(offsetof(struct fwctl_rpc, in_len))
			KAPI_FIELD_SIZE(sizeof(__u32))
		KAPI_STRUCT_FIELD_END

		KAPI_STRUCT_FIELD(3, "out_len", KAPI_TYPE_UINT, "__u32",
				  "Output buffer length")
			KAPI_FIELD_OFFSET(offsetof(struct fwctl_rpc, out_len))
			KAPI_FIELD_SIZE(sizeof(__u32))
		KAPI_STRUCT_FIELD_END

		KAPI_STRUCT_FIELD(4, "in", KAPI_TYPE_PTR, "__aligned_u64",
				  "Pointer to input data")
			KAPI_FIELD_OFFSET(offsetof(struct fwctl_rpc, in))
			KAPI_FIELD_SIZE(sizeof(__aligned_u64))
		KAPI_STRUCT_FIELD_END

		KAPI_STRUCT_FIELD(5, "out", KAPI_TYPE_PTR, "__aligned_u64",
				  "Pointer to output buffer")
			KAPI_FIELD_OFFSET(offsetof(struct fwctl_rpc, out))
			KAPI_FIELD_SIZE(sizeof(__aligned_u64))
		KAPI_STRUCT_FIELD_END
	KAPI_STRUCT_SPEC_END

	KAPI_STRUCT_SPEC_COUNT(1)

	/* Side effects */
	KAPI_SIDE_EFFECT(0, KAPI_EFFECT_HARDWARE | KAPI_EFFECT_MODIFY_STATE,
			 "device firmware",
			 "May modify device configuration or firmware state")
		KAPI_EFFECT_CONDITION("scope >= FWCTL_RPC_DEBUG_WRITE")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(1, KAPI_EFFECT_MODIFY_STATE,
			 "kernel taint",
			 "Taints kernel with TAINT_FWCTL on first debug write")
		KAPI_EFFECT_CONDITION("scope >= FWCTL_RPC_DEBUG_WRITE && first use")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT(2, KAPI_EFFECT_SCHEDULE,
			 "process",
			 "May block while firmware processes the RPC")
		KAPI_EFFECT_CONDITION("firmware operation takes time")
	KAPI_SIDE_EFFECT_END

	KAPI_SIDE_EFFECT_COUNT(3)

	/* State transitions */
	KAPI_STATE_TRANS(0, "device state",
			 "current configuration", "modified configuration",
			 "Device configuration changed by RPC command")
		KAPI_STATE_TRANS_COND("RPC modifies device settings")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS(1, "kernel taint state",
			 "untainted", "TAINT_FWCTL set",
			 "Kernel marked as tainted due to firmware modification")
		KAPI_STATE_TRANS_COND("First debug write operation")
	KAPI_STATE_TRANS_END

	KAPI_STATE_TRANS_COUNT(2)
KAPI_END_SPEC;

static int kapi_ioctl_specs_init(void)
{
	return 0;
}

static void kapi_ioctl_specs_exit(void)
{
}

static void fwctl_device_release(struct device *device)
{
	struct fwctl_device *fwctl =
		container_of(device, struct fwctl_device, dev);

	ida_free(&fwctl_ida, fwctl->dev.devt - fwctl_dev);
	mutex_destroy(&fwctl->uctx_list_lock);
	kfree(fwctl);
}

static char *fwctl_devnode(const struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "fwctl/%s", dev_name(dev));
}

static struct class fwctl_class = {
	.name = "fwctl",
	.dev_release = fwctl_device_release,
	.devnode = fwctl_devnode,
};

static struct fwctl_device *
_alloc_device(struct device *parent, const struct fwctl_ops *ops, size_t size)
{
	struct fwctl_device *fwctl __free(kfree) = kzalloc(size, GFP_KERNEL);
	int devnum;

	if (!fwctl)
		return NULL;

	devnum = ida_alloc_max(&fwctl_ida, FWCTL_MAX_DEVICES - 1, GFP_KERNEL);
	if (devnum < 0)
		return NULL;

	fwctl->dev.devt = fwctl_dev + devnum;
	fwctl->dev.class = &fwctl_class;
	fwctl->dev.parent = parent;

	init_rwsem(&fwctl->registration_lock);
	mutex_init(&fwctl->uctx_list_lock);
	INIT_LIST_HEAD(&fwctl->uctx_list);

	device_initialize(&fwctl->dev);
	return_ptr(fwctl);
}

/* Drivers use the fwctl_alloc_device() wrapper */
struct fwctl_device *_fwctl_alloc_device(struct device *parent,
					 const struct fwctl_ops *ops,
					 size_t size)
{
	struct fwctl_device *fwctl __free(fwctl) =
		_alloc_device(parent, ops, size);

	if (!fwctl)
		return NULL;

	cdev_init(&fwctl->cdev, fwctl_fops);
	/*
	 * The driver module is protected by fwctl_register/unregister(),
	 * unregister won't complete until we are done with the driver's module.
	 */
	fwctl->cdev.owner = THIS_MODULE;

	if (dev_set_name(&fwctl->dev, "fwctl%d", fwctl->dev.devt - fwctl_dev))
		return NULL;

	fwctl->ops = ops;
	return_ptr(fwctl);
}
EXPORT_SYMBOL_NS_GPL(_fwctl_alloc_device, "FWCTL");

/**
 * fwctl_register - Register a new device to the subsystem
 * @fwctl: Previously allocated fwctl_device
 *
 * On return the device is visible through sysfs and /dev, driver ops may be
 * called.
 */
int fwctl_register(struct fwctl_device *fwctl)
{
	return cdev_device_add(&fwctl->cdev, &fwctl->dev);
}
EXPORT_SYMBOL_NS_GPL(fwctl_register, "FWCTL");

/**
 * fwctl_unregister - Unregister a device from the subsystem
 * @fwctl: Previously allocated and registered fwctl_device
 *
 * Undoes fwctl_register(). On return no driver ops will be called. The
 * caller must still call fwctl_put() to free the fwctl.
 *
 * Unregister will return even if userspace still has file descriptors open.
 * This will call ops->close_uctx() on any open FDs and after return no driver
 * op will be called. The FDs remain open but all fops will return -ENODEV.
 *
 * The design of fwctl allows this sort of disassociation of the driver from the
 * subsystem primarily by keeping memory allocations owned by the core subsytem.
 * The fwctl_device and fwctl_uctx can both be freed without requiring a driver
 * callback. This allows the module to remain unlocked while FDs are open.
 */
void fwctl_unregister(struct fwctl_device *fwctl)
{
	struct fwctl_uctx *uctx;

	cdev_device_del(&fwctl->cdev, &fwctl->dev);

	/* Disable and free the driver's resources for any still open FDs. */
	guard(rwsem_write)(&fwctl->registration_lock);
	guard(mutex)(&fwctl->uctx_list_lock);
	while ((uctx = list_first_entry_or_null(&fwctl->uctx_list,
						struct fwctl_uctx,
						uctx_list_entry)))
		fwctl_destroy_uctx(uctx);

	/*
	 * The driver module may unload after this returns, the op pointer will
	 * not be valid.
	 */
	fwctl->ops = NULL;
}
EXPORT_SYMBOL_NS_GPL(fwctl_unregister, "FWCTL");

static int __init fwctl_init(void)
{
	int ret;

	/* Initialize the wrapped file_operations */
	kapi_init_fops_fwctl_fops();

	ret = alloc_chrdev_region(&fwctl_dev, 0, FWCTL_MAX_DEVICES, "fwctl");
	if (ret)
		return ret;

	ret = class_register(&fwctl_class);
	if (ret)
		goto err_chrdev;

	ret = kapi_ioctl_specs_init();
	if (ret)
		goto err_class;

	return 0;

err_class:
	class_unregister(&fwctl_class);
err_chrdev:
	unregister_chrdev_region(fwctl_dev, FWCTL_MAX_DEVICES);
	return ret;
}

static void __exit fwctl_exit(void)
{
	kapi_ioctl_specs_exit();
	class_unregister(&fwctl_class);
	unregister_chrdev_region(fwctl_dev, FWCTL_MAX_DEVICES);
}

module_init(fwctl_init);
module_exit(fwctl_exit);
MODULE_DESCRIPTION("fwctl device firmware access framework");
MODULE_LICENSE("GPL");
