// SPDX-License-Identifier: GPL-2.0
/*
 * blk-integrity.c - Block layer data integrity extensions
 *
 * Copyright (C) 2007, 2008 Oracle Corporation
 * Written by: Martin K. Petersen <martin.petersen@oracle.com>
 */

#include <linux/blk-integrity.h>
#include <linux/backing-dev.h>
#include <linux/mempool.h>
#include <linux/bio.h>
#include <linux/scatterlist.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/kernel_api_spec.h>
#include <linux/syscall_api_spec.h>

#include "blk.h"

/**
 * blk_rq_count_integrity_sg - Count number of integrity scatterlist elements
 * @q:		request queue
 * @bio:	bio with integrity metadata attached
 *
 * Description: Returns the number of elements required in a
 * scatterlist corresponding to the integrity metadata in a bio.
 */
int blk_rq_count_integrity_sg(struct request_queue *q, struct bio *bio)
{
	struct bio_vec iv, ivprv = { NULL };
	unsigned int segments = 0;
	unsigned int seg_size = 0;
	struct bvec_iter iter;
	int prev = 0;

	bio_for_each_integrity_vec(iv, bio, iter) {

		if (prev) {
			if (!biovec_phys_mergeable(q, &ivprv, &iv))
				goto new_segment;
			if (seg_size + iv.bv_len > queue_max_segment_size(q))
				goto new_segment;

			seg_size += iv.bv_len;
		} else {
new_segment:
			segments++;
			seg_size = iv.bv_len;
		}

		prev = 1;
		ivprv = iv;
	}

	return segments;
}

/**
 * blk_rq_map_integrity_sg - Map integrity metadata into a scatterlist
 * @rq:		request to map
 * @sglist:	target scatterlist
 *
 * Description: Map the integrity vectors in request into a
 * scatterlist.  The scatterlist must be big enough to hold all
 * elements.  I.e. sized using blk_rq_count_integrity_sg() or
 * rq->nr_integrity_segments.
 */
int blk_rq_map_integrity_sg(struct request *rq, struct scatterlist *sglist)
{
	struct bio_vec iv, ivprv = { NULL };
	struct request_queue *q = rq->q;
	struct scatterlist *sg = NULL;
	struct bio *bio = rq->bio;
	unsigned int segments = 0;
	struct bvec_iter iter;
	int prev = 0;

	bio_for_each_integrity_vec(iv, bio, iter) {
		if (prev) {
			if (!biovec_phys_mergeable(q, &ivprv, &iv))
				goto new_segment;
			if (sg->length + iv.bv_len > queue_max_segment_size(q))
				goto new_segment;

			sg->length += iv.bv_len;
		} else {
new_segment:
			if (!sg)
				sg = sglist;
			else {
				sg_unmark_end(sg);
				sg = sg_next(sg);
			}

			sg_set_page(sg, iv.bv_page, iv.bv_len, iv.bv_offset);
			segments++;
		}

		prev = 1;
		ivprv = iv;
	}

	if (sg)
		sg_mark_end(sg);

	/*
	 * Something must have been wrong if the figured number of segment
	 * is bigger than number of req's physical integrity segments
	 */
	BUG_ON(segments > rq->nr_integrity_segments);
	BUG_ON(segments > queue_max_integrity_segments(q));
	return segments;
}
EXPORT_SYMBOL(blk_rq_map_integrity_sg);

int blk_rq_integrity_map_user(struct request *rq, void __user *ubuf,
			      ssize_t bytes)
{
	int ret;
	struct iov_iter iter;

	iov_iter_ubuf(&iter, rq_data_dir(rq), ubuf, bytes);
	ret = bio_integrity_map_user(rq->bio, &iter);
	if (ret)
		return ret;

	rq->nr_integrity_segments = blk_rq_count_integrity_sg(rq->q, rq->bio);
	rq->cmd_flags |= REQ_INTEGRITY;
	return 0;
}
EXPORT_SYMBOL_GPL(blk_rq_integrity_map_user);

bool blk_integrity_merge_rq(struct request_queue *q, struct request *req,
			    struct request *next)
{
	if (blk_integrity_rq(req) == 0 && blk_integrity_rq(next) == 0)
		return true;

	if (blk_integrity_rq(req) == 0 || blk_integrity_rq(next) == 0)
		return false;

	if (bio_integrity(req->bio)->bip_flags !=
	    bio_integrity(next->bio)->bip_flags)
		return false;

	if (req->nr_integrity_segments + next->nr_integrity_segments >
	    q->limits.max_integrity_segments)
		return false;

	if (integrity_req_gap_back_merge(req, next->bio))
		return false;

	return true;
}

bool blk_integrity_merge_bio(struct request_queue *q, struct request *req,
			     struct bio *bio)
{
	int nr_integrity_segs;

	if (blk_integrity_rq(req) == 0 && bio_integrity(bio) == NULL)
		return true;

	if (blk_integrity_rq(req) == 0 || bio_integrity(bio) == NULL)
		return false;

	if (bio_integrity(req->bio)->bip_flags != bio_integrity(bio)->bip_flags)
		return false;

	nr_integrity_segs = blk_rq_count_integrity_sg(q, bio);
	if (req->nr_integrity_segments + nr_integrity_segs >
	    q->limits.max_integrity_segments)
		return false;

	return true;
}

static inline struct blk_integrity *dev_to_bi(struct device *dev)
{
	return &dev_to_disk(dev)->queue->limits.integrity;
}

const char *blk_integrity_profile_name(struct blk_integrity *bi)
{
	switch (bi->csum_type) {
	case BLK_INTEGRITY_CSUM_IP:
		if (bi->flags & BLK_INTEGRITY_REF_TAG)
			return "T10-DIF-TYPE1-IP";
		return "T10-DIF-TYPE3-IP";
	case BLK_INTEGRITY_CSUM_CRC:
		if (bi->flags & BLK_INTEGRITY_REF_TAG)
			return "T10-DIF-TYPE1-CRC";
		return "T10-DIF-TYPE3-CRC";
	case BLK_INTEGRITY_CSUM_CRC64:
		if (bi->flags & BLK_INTEGRITY_REF_TAG)
			return "EXT-DIF-TYPE1-CRC64";
		return "EXT-DIF-TYPE3-CRC64";
	case BLK_INTEGRITY_CSUM_NONE:
		break;
	}

	return "nop";
}
EXPORT_SYMBOL_GPL(blk_integrity_profile_name);

static ssize_t flag_store(struct device *dev, const char *page, size_t count,
		unsigned char flag)
{
	struct request_queue *q = dev_to_disk(dev)->queue;
	struct queue_limits lim;
	unsigned long val;
	int err;

	err = kstrtoul(page, 10, &val);
	if (err)
		return err;

	/* note that the flags are inverted vs the values in the sysfs files */
	lim = queue_limits_start_update(q);
	if (val)
		lim.integrity.flags &= ~flag;
	else
		lim.integrity.flags |= flag;

	err = queue_limits_commit_update_frozen(q, &lim);
	if (err)
		return err;
	return count;
}

static ssize_t flag_show(struct device *dev, char *page, unsigned char flag)
{
	struct blk_integrity *bi = dev_to_bi(dev);

	return sysfs_emit(page, "%d\n", !(bi->flags & flag));
}

/*
 * Sysfs API specifications for integrity attributes
 */
DEFINE_SYSFS_API_SPEC(format)
	KAPI_DESCRIPTION("Metadata format for integrity")
	KAPI_LONG_DESC("Metadata format for integrity capable block device. "
		       "E.g. T10-DIF-TYPE1-CRC. This field describes the type of T10 "
		       "Protection Information that the block device can send and receive. "
		       "If the device can store application integrity metadata but "
		       "no T10 Protection Information profile is used, this field "
		       "contains 'nop'. If the device does not support integrity "
		       "metadata, this field contains 'none'.")
	KAPI_PARAM_COUNT(1)
	KAPI_PARAM(0, "format", "string", "Integrity metadata format")
		KAPI_PARAM_TYPE(KAPI_TYPE_STRING)
		KAPI_PERMISSIONS(0444)
		KAPI_PATH("/sys/block/<disk>/integrity/format")
		KAPI_PARAM_FLAGS(KAPI_PARAM_SYSFS_READONLY)
	KAPI_PARAM_END
	KAPI_SUBSYSTEM("block")
	KAPI_EXAMPLES("cat /sys/block/sda/integrity/format")
KAPI_END_SPEC;

static ssize_t format_show(struct device *dev, struct device_attribute *attr,
			   char *page)
{
	struct blk_integrity *bi = dev_to_bi(dev);

	if (!bi->tuple_size)
		return sysfs_emit(page, "none\n");
	return sysfs_emit(page, "%s\n", blk_integrity_profile_name(bi));
}

DEFINE_SYSFS_API_SPEC(tag_size)
	KAPI_DESCRIPTION("Integrity tag size")
	KAPI_LONG_DESC("Number of bytes of integrity tag space available per "
		       "protection_interval_bytes, which is typically "
		       "the device's logical block size. "
		       "This field describes the size of the application tag "
		       "if the storage device is formatted with T10 Protection "
		       "Information and permits use of the application tag.")
	KAPI_PARAM_COUNT(1)
	KAPI_PARAM(0, "tag_size", "unsigned int", "Tag size in bytes")
		KAPI_PARAM_TYPE(KAPI_TYPE_UINT)
		KAPI_PERMISSIONS(0444)
		KAPI_PATH("/sys/block/<disk>/integrity/tag_size")
		KAPI_PARAM_RANGE(0, 65535)
		KAPI_UNITS("bytes")
		KAPI_PARAM_FLAGS(KAPI_PARAM_SYSFS_READONLY)
	KAPI_PARAM_END
	KAPI_SUBSYSTEM("block")
	KAPI_EXAMPLES("cat /sys/block/sda/integrity/tag_size")
	KAPI_NOTES("If the device does not support T10 Protection Information (even if the "
		   "device provides application integrity metadata space), this field is set to 0. "
		   "The owner of this tag space is the owner of the block device. The filesystem "
		   "can use this extra space to tag sectors as they see fit. Because the tag space "
		   "is limited, the block interface allows tagging bigger chunks by way of interleaving. "
		   "This way, 8*16 bits of information can be attached to a typical 4KB filesystem block.")
KAPI_END_SPEC;

static ssize_t tag_size_show(struct device *dev, struct device_attribute *attr,
			     char *page)
{
	struct blk_integrity *bi = dev_to_bi(dev);

	return sysfs_emit(page, "%u\n", bi->tag_size);
}

DEFINE_SYSFS_API_SPEC(protection_interval_bytes)
	KAPI_DESCRIPTION("Protection interval size")
	KAPI_LONG_DESC("Describes the number of data bytes which are protected by one "
		       "integrity tuple. Typically the device's logical block size. "
		       "For example, a 512-byte sector with 8-byte integrity metadata "
		       "would have a protection interval of 512 bytes.")
	KAPI_PARAM_COUNT(1)
	KAPI_PARAM(0, "protection_interval_bytes", "unsigned int", "Protection interval in bytes")
		KAPI_PARAM_TYPE(KAPI_TYPE_UINT)
		KAPI_PERMISSIONS(0444)
		KAPI_PATH("/sys/block/<disk>/integrity/protection_interval_bytes")
		KAPI_PARAM_RANGE(0, 65536)
		KAPI_UNITS("bytes")
		KAPI_PARAM_FLAGS(KAPI_PARAM_SYSFS_READONLY)
	KAPI_PARAM_END
	KAPI_SUBSYSTEM("block")
	KAPI_EXAMPLES("cat /sys/block/sda/integrity/protection_interval_bytes")
	KAPI_NOTES("This is typically the same as the device's logical block size")
KAPI_END_SPEC;

static ssize_t protection_interval_bytes_show(struct device *dev,
					      struct device_attribute *attr,
					      char *page)
{
	struct blk_integrity *bi = dev_to_bi(dev);

	return sysfs_emit(page, "%u\n",
			  bi->interval_exp ? 1 << bi->interval_exp : 0);
}

static ssize_t read_verify_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *page, size_t count)
{
	return flag_store(dev, page, count, BLK_INTEGRITY_NOVERIFY);
}

static ssize_t read_verify_show(struct device *dev,
				struct device_attribute *attr, char *page)
{
	return flag_show(dev, page, BLK_INTEGRITY_NOVERIFY);
}

DEFINE_SYSFS_API_SPEC(read_verify)
	KAPI_DESCRIPTION("Read request integrity verification")
	KAPI_LONG_DESC("Indicates whether the block layer should verify the integrity "
		       "of read requests serviced by devices that support sending "
		       "integrity metadata. A value of 1 enables verification, while "
		       "0 disables it. When enabled, the block layer will check "
		       "integrity metadata on read operations.")
	KAPI_PARAM_COUNT(1)
	KAPI_PARAM(0, "read_verify", "bool", "Enable read integrity verification")
		KAPI_PARAM_TYPE(KAPI_TYPE_BOOL)
		KAPI_PERMISSIONS(0644)
		KAPI_PATH("/sys/block/<disk>/integrity/read_verify")
		KAPI_PARAM_FLAGS(KAPI_PARAM_SYSFS_RW)
	KAPI_PARAM_END
	KAPI_SUBSYSTEM("block")
	KAPI_EXAMPLES("echo 1 > /sys/block/sda/integrity/read_verify")
	KAPI_NOTES("This attribute only has effect if the device supports integrity metadata")
KAPI_END_SPEC;

static ssize_t write_generate_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *page, size_t count)
{
	return flag_store(dev, page, count, BLK_INTEGRITY_NOGENERATE);
}

static ssize_t write_generate_show(struct device *dev,
				   struct device_attribute *attr, char *page)
{
	return flag_show(dev, page, BLK_INTEGRITY_NOGENERATE);
}

DEFINE_SYSFS_API_SPEC(write_generate)
	KAPI_DESCRIPTION("Write request integrity generation")
	KAPI_LONG_DESC("Indicates whether the block layer should automatically generate "
		       "checksums for write requests bound for devices that support "
		       "receiving integrity metadata. A value of 1 enables generation, "
		       "while 0 disables it. When enabled, the block layer will compute "
		       "and attach integrity metadata to write operations.")
	KAPI_PARAM_COUNT(1)
	KAPI_PARAM(0, "write_generate", "bool", "Enable write integrity generation")
		KAPI_PARAM_TYPE(KAPI_TYPE_BOOL)
		KAPI_PERMISSIONS(0644)
		KAPI_PATH("/sys/block/<disk>/integrity/write_generate")
		KAPI_PARAM_FLAGS(KAPI_PARAM_SYSFS_RW)
	KAPI_PARAM_END
	KAPI_SUBSYSTEM("block")
	KAPI_EXAMPLES("echo 1 > /sys/block/sda/integrity/write_generate")
	KAPI_NOTES("This attribute only has effect if the device supports integrity metadata")
KAPI_END_SPEC;

DEFINE_SYSFS_API_SPEC(device_is_integrity_capable)
	KAPI_DESCRIPTION("Device integrity capability")
	KAPI_LONG_DESC("Indicates whether a storage device is capable of storing "
		       "integrity metadata. Set if the device is T10 PI-capable. "
		       "This flag is set to 1 if the storage media is formatted "
		       "with T10 Protection Information. If the storage media is "
		       "not formatted with T10 Protection Information, this flag "
		       "is set to 0. This is a key indicator for whether the device "
		       "supports end-to-end data protection using standards like "
		       "T10 DIF (Data Integrity Field) for SCSI devices.")
	KAPI_PARAM_COUNT(1)
	KAPI_PARAM(0, "device_is_integrity_capable", "bool", "Device integrity capability flag")
		KAPI_PARAM_TYPE(KAPI_TYPE_BOOL)
		KAPI_PERMISSIONS(0444)
		KAPI_PATH("/sys/block/<disk>/integrity/device_is_integrity_capable")
		KAPI_PARAM_FLAGS(KAPI_PARAM_SYSFS_READONLY)
	KAPI_PARAM_END
	KAPI_SUBSYSTEM("block")
	KAPI_EXAMPLES("cat /sys/block/sda/integrity/device_is_integrity_capable")
KAPI_END_SPEC;

static ssize_t device_is_integrity_capable_show(struct device *dev,
						struct device_attribute *attr,
						char *page)
{
	struct blk_integrity *bi = dev_to_bi(dev);

	return sysfs_emit(page, "%u\n",
			  !!(bi->flags & BLK_INTEGRITY_DEVICE_CAPABLE));
}

static DEVICE_ATTR_RO(format);
static DEVICE_ATTR_RO(tag_size);
static DEVICE_ATTR_RO(protection_interval_bytes);
static DEVICE_ATTR_RW(read_verify);
static DEVICE_ATTR_RW(write_generate);
static DEVICE_ATTR_RO(device_is_integrity_capable);

static struct attribute *integrity_attrs[] = {
	&dev_attr_format.attr,
	&dev_attr_tag_size.attr,
	&dev_attr_protection_interval_bytes.attr,
	&dev_attr_read_verify.attr,
	&dev_attr_write_generate.attr,
	&dev_attr_device_is_integrity_capable.attr,
	NULL
};

const struct attribute_group blk_integrity_attr_group = {
	.name = "integrity",
	.attrs = integrity_attrs,
};
