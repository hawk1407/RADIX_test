#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/sysfs.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/bio.h>
#include <linux/bvec.h>
#include <linux/init.h>
#include <linux/wait.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/numa.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/jiffies.h>
#include <linux/moduleparam.h>
#include <linux/spinlock_types.h>
#ifdef BLK_MQ_MODE
#include <linux/blk-mq.h>
#endif

#include "sbdd_bus.h"

#define SBDD_SECTOR_SHIFT      9
#define SBDD_SECTOR_SIZE       (1 << SBDD_SECTOR_SHIFT)
#define SBDD_MIB_SECTORS       (1 << (20 - SBDD_SECTOR_SHIFT))
#define SBDD_NAME              "sbdd"
#define BUF_SIZE 1024

struct sbdd {
        wait_queue_head_t       exitwait;
        spinlock_t              datalock;
        atomic_t                deleting;
        atomic_t                refs_cnt;
        sector_t                capacity;
        u8                      *data;
        int		        major;
        struct gendisk          *gd;
        struct sbdd_device      *dev;
        struct request_queue    *q;
	struct block_device_operations *bdev_ops;
#ifdef BLK_MQ_MODE
	struct blk_mq_ops   	*sbdd_blk_mq_ops; 
        struct blk_mq_tag_set   *tag_set;
#endif
};

static int sbdd_create(struct sbdd *sbdd_dev);
static void sbdd_delete(struct sbdd *sbdd_dev);

int sbdd_drv_probe(struct sbdd_device *dev)
{
	struct sbdd *sbdd_dev;
        int ret;

	pr_info("sbdd_drv_probe\n");
        dev_info(&dev->dev, "%s\n", __func__);

	sbdd_dev = kzalloc(sizeof(*sbdd_dev), GFP_KERNEL);
        if (!sbdd_dev)
                return -ENOMEM;

	sbdd_dev->dev = dev;
	ret = sbdd_create(sbdd_dev);
        
	if (ret) {
		dev_err(&dev->dev, "failed to register block device: %d\n", ret);
                return ret;
	}

	return 0;
}


void sbdd_drv_remove(struct sbdd_device *dev)
{
	struct sbdd *sbdd_dev=NULL;

	pr_info("sbdd drv remove device");

	sbdd_dev = (struct sbdd *)dev_get_drvdata(&dev->dev);
	if (!sbdd_dev) {
		pr_err("could not find dev\n");
		return;
	}
	
	sbdd_delete(sbdd_dev);
}

int sbdd_drv_resize_disk(struct sbdd_device *dev, unsigned long capacity_mib)
{
	struct sbdd *sbdd_dev=NULL;

        sbdd_dev = (struct sbdd *)dev_get_drvdata(&dev->dev);
        if (!sbdd_dev) {
                pr_err("could not find dev\n");
                return - EINVAL;;
        }

        pr_info("sbdd drv resize %s to %lu\n", dev_name(&sbdd_dev->dev->dev), capacity_mib);

	spin_lock(&sbdd_dev->datalock);
        //init_waitqueue_head(&sbdd_dev->exitwait);

	sbdd_dev->dev->capacity_mib = capacity_mib;	
	sbdd_dev->capacity = (sector_t)sbdd_dev->dev->capacity_mib * SBDD_MIB_SECTORS;

        pr_info("allocating data\n");
        pr_info("data for allocation %llu\n", sbdd_dev->capacity << SBDD_SECTOR_SHIFT);

	vfree(sbdd_dev->data);

	sbdd_dev->data = vmalloc(sbdd_dev->capacity << SBDD_SECTOR_SHIFT);
        if (!sbdd_dev->data) {
                pr_err("unable to alloc data\n");
                return -ENOMEM;
        }

	set_capacity(sbdd_dev->gd, sbdd_dev->capacity);
	spin_unlock(&sbdd_dev->datalock);
	
	return 0;
}

int sbdd_drv_set_mod(struct sbdd_device *dev, int flag_ro)
{
        struct sbdd *sbdd_dev=NULL;

        sbdd_dev = (struct sbdd *)dev_get_drvdata(&dev->dev);
        if (!sbdd_dev) {
                pr_err("could not find dev\n");
                return -EINVAL;
        }
        pr_info("sbdd drv set %s ro mode %d\n", dev_name(&sbdd_dev->dev->dev), flag_ro);

	set_disk_ro(sbdd_dev->gd, flag_ro);

	return 0;
}


struct sbdd_driver __sbdd_driver = {
        .probe = sbdd_drv_probe,
        .remove = sbdd_drv_remove,
	.resize_disk = sbdd_drv_resize_disk,
	.set_mod = sbdd_drv_set_mod,
        .driver = {
                .owner = THIS_MODULE,
                .name = SBDD_NAME,
        },
};

static unsigned long    __sbdd_capacity_mib = 100;
static int __usr_mod_dev = 1;

static sector_t sbdd_xfer(struct bio_vec* bvec, sector_t pos, int dir, struct sbdd *sbdd_dev)
{
	void *buff = page_address(bvec->bv_page) + bvec->bv_offset;
	sector_t len = bvec->bv_len >> SBDD_SECTOR_SHIFT;
	size_t offset;
	size_t nbytes;

	if (pos + len > sbdd_dev->capacity)
		len = sbdd_dev->capacity - pos;

	offset = pos << SBDD_SECTOR_SHIFT;
	nbytes = len << SBDD_SECTOR_SHIFT;

	spin_lock(&sbdd_dev->datalock);

	if (dir)
		memcpy(sbdd_dev->data + offset, buff, nbytes);
	else
		memcpy(buff, sbdd_dev->data + offset, nbytes);

	spin_unlock(&sbdd_dev->datalock);

	pr_debug("pos=%6llu len=%4llu %s\n", pos, len, dir ? "written" : "read");

	return len;
}

#ifdef BLK_MQ_MODE

static void sbdd_xfer_rq(struct request *rq)
{
	struct req_iterator iter;
	struct bio_vec bvec;
	int dir = rq_data_dir(rq);
	sector_t pos = blk_rq_pos(rq);

	rq_for_each_segment(bvec, rq, iter)
		pos += sbdd_xfer(&bvec, pos, dir, rq->bio->bi_disk->private_data);
}

static blk_status_t sbdd_queue_rq(struct blk_mq_hw_ctx *hctx,
                                  struct blk_mq_queue_data const *bd)
{
	struct sbdd *sbdd_dev = bd->rq->bio->bi_disk->private_data;

	if (atomic_read(&sbdd_dev->deleting))
		return BLK_STS_IOERR;

	atomic_inc(&sbdd_dev->refs_cnt);

	blk_mq_start_request(bd->rq);
	sbdd_xfer_rq(bd->rq);
	blk_mq_end_request(bd->rq, BLK_STS_OK);

	if (atomic_dec_and_test(&sbdd_dev->refs_cnt))
		wake_up(&sbdd_dev->exitwait);

	return BLK_STS_OK;
}

static struct blk_mq_ops const __sbdd_blk_mq_ops = {
	/*
	The function receives requests for the device as arguments
	and can use various functions to process them. The functions
	used to process requests in the handler are described below:

	blk_mq_start_request()   - must be called before processing a request
	blk_mq_requeue_request() - to re-send the request in the queue
	blk_mq_end_request()     - to end request processing and notify upper layers
	*/
	.queue_rq = sbdd_queue_rq,
};

#else

static void sbdd_xfer_bio(struct bio *bio)
{
	struct bvec_iter iter;
	struct bio_vec bvec;
	int dir = bio_data_dir(bio);
	sector_t pos = bio->bi_iter.bi_sector;

	bio_for_each_segment(bvec, bio, iter)
		pos += sbdd_xfer(&bvec, pos, dir, bio->bi_disk->private_data);
}

static blk_qc_t sbdd_make_request(struct request_queue *q, struct bio *bio)
{
	struct sbdd *sbdd_dev = bio->bi_disk->private_data;
	if (atomic_read(&sbdd_dev->deleting))
		return BLK_STS_IOERR;

	atomic_inc(&sbdd_dev->refs_cnt);

	sbdd_xfer_bio(bio);
	bio_endio(bio);

	if (atomic_dec_and_test(&sbdd_dev->refs_cnt))
		wake_up(&sbdd_dev->exitwait);

	return BLK_STS_OK;
}

#endif /* BLK_MQ_MODE */

/*
There are no read or write operations. These operations are performed by
the request() function associated with the request queue of the disk.
*/

static struct block_device_operations const __sbdd_bdev_ops = {
	.owner = THIS_MODULE,
};


static int sbdd_create(struct sbdd *sbdd_dev)
{
	int ret = 0;
	
	/*
	This call is somewhat redundant, but used anyways by tradition.
	The number is to be displayed in /proc/devices (0 for auto).
	*/
	pr_info("registering blkdev\n");
	sbdd_dev->major = register_blkdev(0, dev_name(&sbdd_dev->dev->dev));
	if (sbdd_dev->major < 0) {
		pr_err("call register_blkdev() failed with %d\n", sbdd_dev->major);
		return -EBUSY;
	}

	sbdd_dev->capacity = (sector_t)sbdd_dev->dev->capacity_mib * SBDD_MIB_SECTORS;

	pr_info("allocating data\n");
	pr_info("data for allocation %llu\n", sbdd_dev->capacity << SBDD_SECTOR_SHIFT);
	sbdd_dev->data = vmalloc(sbdd_dev->capacity << SBDD_SECTOR_SHIFT);
	if (!sbdd_dev->data) {
		pr_err("unable to alloc data\n");
		return -ENOMEM;
	}

	spin_lock_init(&sbdd_dev->datalock);
	init_waitqueue_head(&sbdd_dev->exitwait);

#ifdef BLK_MQ_MODE
	pr_info("allocating tag_set\n");
	sbdd_dev->tag_set = kzalloc(sizeof(struct blk_mq_tag_set), GFP_KERNEL);
	if (!sbdd_dev->tag_set) {
		pr_err("unable to alloc tag_set\n");
		return -ENOMEM;
	}

	/* Number of hardware dispatch queues */
	sbdd_dev->tag_set->nr_hw_queues = 1;
	/* Depth of hardware dispatch queues */
	sbdd_dev->tag_set->queue_depth = 128;
	sbdd_dev->tag_set->numa_node = NUMA_NO_NODE;
	
	sbdd_dev->sbdd_blk_mq_ops = kzalloc(sizeof(*sbdd_dev->sbdd_blk_mq_ops), GFP_KERNEL);
	sbdd_blk_mq_ops->queue_rq = sbdd_queue_rq; 
	sbdd_dev->tag_set->ops = sbdd_dev->sbdd_blk_mq_ops;

	//sbdd_dev->tag_set->ops = &__sbdd_blk_mq_ops;

	ret = blk_mq_alloc_tag_set(sbdd_dev->tag_set);
	if (ret) {
		pr_err("call blk_mq_alloc_tag_set() failed with %d\n", ret);
		return ret;
	}

	/* Creates both the hardware and the software queues and initializes structs */
	pr_info("initing queue\n");
	sbdd_dev->q = blk_mq_init_queue(sbdd_dev->tag_set);
	if (IS_ERR(sbdd_dev->q)) {
		ret = (int)PTR_ERR(sbdd_dev->q);
		pr_err("call blk_mq_init_queue() failed witn %d\n", ret);
		sbdd_dev->q = NULL;
		return ret;
	}
#else
	pr_info("allocating queue\n");
	sbdd_dev->q = blk_alloc_queue(GFP_KERNEL);
	if (!sbdd_dev->q) {
		pr_err("call blk_alloc_queue() failed\n");
		return -EINVAL;
	}
	blk_queue_make_request(sbdd_dev->q, sbdd_make_request);
#endif /* BLK_MQ_MODE */

	/* Configure queue */
	blk_queue_logical_block_size(sbdd_dev->q, SBDD_SECTOR_SIZE);

	/* A disk must have at least one minor */
	pr_info("allocating disk\n");
	sbdd_dev->gd = alloc_disk(1);

	/* Configure gendisk */
	sbdd_dev->gd->queue = sbdd_dev->q;
	sbdd_dev->gd->major = sbdd_dev->major;
	sbdd_dev->gd->first_minor = 0;

	sbdd_dev->bdev_ops = kzalloc(sizeof(*sbdd_dev->bdev_ops), GFP_KERNEL);
	sbdd_dev->gd->fops = sbdd_dev->bdev_ops;
	/* Represents name in /proc/partitions and /sys/block */
	scnprintf(sbdd_dev->gd->disk_name, DISK_NAME_LEN, dev_name(&sbdd_dev->dev->dev));
	set_capacity(sbdd_dev->gd, sbdd_dev->capacity);
	sbdd_dev->gd->private_data = sbdd_dev;

	dev_set_drvdata(&sbdd_dev->dev->dev, sbdd_dev);

	/*
	Allocating gd does not make it available, add_disk() required.
	After this call, gd methods can be called at any time. Should not be
	called before the driver is fully initialized and ready to process reqs.
	*/
	pr_info("adding disk\n");
	device_add_disk(&sbdd_dev->dev->dev, sbdd_dev->gd, NULL);
	
	return ret;
}

static void sbdd_delete(struct sbdd *sbdd_dev)
{
	char name[DISK_NAME_LEN];
	pr_info("deleting dev...\n");
	atomic_set(&sbdd_dev->deleting, 1);

	wait_event(sbdd_dev->exitwait, !atomic_read(&sbdd_dev->refs_cnt));

	/* gd will be removed only after the last reference put */
	if (sbdd_dev->gd) {
		pr_info("deleting disk\n");
		del_gendisk(sbdd_dev->gd);
	}

	if (sbdd_dev->q) {
		pr_info("cleaning up queue\n");
		blk_cleanup_queue(sbdd_dev->q);
	}

	memcpy(name, sbdd_dev->gd->disk_name, DISK_NAME_LEN);

	if (sbdd_dev->gd)
		put_disk(sbdd_dev->gd);

#ifdef BLK_MQ_MODE
	if (sbdd_dev->tag_set && sbdd_dev->tag_set->tags) {
		pr_info("freeing tag_set\n");
		blk_mq_free_tag_set(sbdd_dev->tag_set);
	}

	if (sbdd_dev->tag_set)
		kfree(sbdd_dev->tag_set);

	if (sbdd_dev->sbdd_blk_mq_ops)
		kfree(sbdd_dev->sbdd_blk_mq_ops);

#endif

	if (sbdd_dev->data) {
		pr_info("freeing data\n");
		vfree(sbdd_dev->data);
	}

	if (sbdd_dev->major > 0) {
		pr_info("unregistering blkdev %s\n", name);
		unregister_blkdev(sbdd_dev->major, name);
		sbdd_dev->major = 0;
	}

	if (sbdd_dev->bdev_ops)
		kfree(sbdd_dev->bdev_ops);
	memset(sbdd_dev, 0, sizeof(struct sbdd));
}

/*
Note __init is for the kernel to drop this function after
initialization complete making its memory available for other uses.
There is also __initdata note, same but used for variables.
*/
static int __init sbdd_driver_init(void)
{
	int ret = 0;

	pr_info("starting driver initialization...\n");
	ret = sbdd_register_driver(&__sbdd_driver);

        if (ret) {
                pr_err("unable to register driver: %d\n", ret);
                goto driver_err;
        }

	if (!__usr_mod_dev) {
		pr_info("starting dev initialization...\n");
		ret = sbdd_add_dev(SBDD_NAME, __sbdd_capacity_mib, 1);

		if (ret) {
			pr_warn("dev initialization failed\n");
			goto auto_dev_err;
		} else {
			pr_info("dev initialization complete\n");
		}
	}

	set_usr_mod_dev(__usr_mod_dev);
	return ret;

auto_dev_err:
	sbdd_unregister_driver(&__sbdd_driver);
driver_err:
	return ret;
}

/*
Note __exit is for the compiler to place this code in a special ELF section.
Sometimes such functions are simply discarded (e.g. when module is built
directly into the kernel). There is also __exitdata note.
*/
static void __exit sbdd_driver_exit(void)
{
	pr_info("exiting...\n");
	sbdd_unregister_driver(&__sbdd_driver);
	pr_info("driver unregistered\n");

	pr_info("exiting complete\n");
}

/* Called on module loading. Is mandatory. */
module_init(sbdd_driver_init);

/* Called on module unloading. Unloading module is not allowed without it. */
module_exit(sbdd_driver_exit);

/* Set desired capacity with insmod */
module_param_named(capacity_mib, __sbdd_capacity_mib, ulong, S_IRUGO);
module_param_named(usr_mod_dev, __usr_mod_dev, int, S_IRUGO);

/* Note for the kernel: a free license module. A warning will be outputted without it. */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple Block Device Driver");
