#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
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

#include "sbdd.h"

#define SBDD_SECTOR_SHIFT      9
#define SBDD_SECTOR_SIZE       (1 << SBDD_SECTOR_SHIFT)
#define SBDD_MIB_SECTORS       (1 << (20 - SBDD_SECTOR_SHIFT))
#define SBDD_NAME              "sbdd"
#define BUF_SIZE 1024

static int sbdd_match(struct device *dev, struct device_driver *driver)
{
	struct device **dev_ptr = &dev;
	struct sbdd *sbdd_dev = to_sbdd_device(dev_ptr);
	struct sbdd_driver *sbdd_drv = to_sbdd_driver(driver);
	if(!strcmp(sbdd_dev->gd->disk_name, sbdd_drv->driver.name))
		return 1;
	return 0;
}

static int sbdd_probe(struct device *dev)
{
	struct device **dev_ptr = &dev;
	struct sbdd *sbdd_dev = to_sbdd_device(dev_ptr);
	struct sbdd_driver *sbdd_drv = to_sbdd_driver(dev->driver);
	return sbdd_drv->probe(sbdd_dev);
}

static int sbdd_remove(struct device *dev)
{
	struct device **dev_ptr = &dev;
	struct sbdd *sbdd_dev = to_sbdd_device(dev_ptr);
	struct sbdd_driver *sbdd_drv = to_sbdd_driver(dev->driver);
	pr_info("bus remove device %31s", sbdd_dev->gd->disk_name);
	sbdd_drv->remove(sbdd_dev);
	return 0;
}

static int sbdd_add_dev(const char *name, unsigned long capacity_mib);

static int sbdd_create(struct sbdd *sbdd_dev, const char *name, unsigned long capacity_mib);
static void sbdd_delete(struct sbdd *sbdd_dev);

static ssize_t
add_store(struct bus_type *bt, const char *buf, size_t count)
{
	char name[32];
	unsigned long capacity_mib;
	int ret;
	ret = sscanf(buf, "%31s %lu", name, &capacity_mib);
	if(ret != 2)
	{
		pr_err("user add_dev not enough arguments read\n");
		return -EINVAL;
	}

	return sbdd_add_dev(name, capacity_mib) ? : count;
}
struct bus_attribute bus_attr_add = __ATTR(add, S_IWUSR, NULL, add_store);


static struct attribute *sbdd_drv_attrs[] = {
	&bus_attr_add.attr,
	NULL
};

static struct attribute_group sbdd_drv_group = {	
	.attrs = sbdd_drv_attrs,
	NULL,
};

static const struct attribute_group *sbdd_drv_groups[] = {
	&sbdd_drv_group,
	NULL,
};

struct bus_type __sbdd_bus_type = {
	.name = "sbdd",
	.match = sbdd_match,
	.probe = sbdd_probe,
	.remove = sbdd_remove,
	.drv_groups = sbdd_drv_groups,
};

static int sbdd_add_dev(const char *name, unsigned long capacity_mib)
{
	struct sbdd *sbdd_dev;
	pr_info("user add dev name: %s, capacity_mib: %lu \n", name, capacity_mib);
	sbdd_dev = kzalloc(sizeof(*sbdd_dev), GFP_KERNEL);
	sbdd_create(sbdd_dev, name, capacity_mib);

	return 0;
}


int sbdd_register_driver(struct sbdd_driver *drv)
{
	int ret;
	drv->driver.bus = &__sbdd_bus_type;
	ret = driver_register(&drv->driver);
	pr_info("driver registered\n");
	if(ret)
		return ret;
	return 0;
}

void sbdd_unregister_driver(struct sbdd_driver *drv)
{
	driver_unregister(&drv->driver);
}

int sbdd_drv_probe(struct sbdd *sbdd_dev)
{
        return 0;
}

void sbdd_drv_remove(struct sbdd *sbdd_dev)
{
	sbdd_delete(sbdd_dev);

}

struct sbdd_driver __sbdd_driver = {
        .probe = sbdd_drv_probe,
        .remove = sbdd_drv_remove,
        .driver = {
                .owner = THIS_MODULE,
                .name = "sbdd",
        },
};

static int sbdd_dev_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	return add_uevent_var(env, "MODALIAS=sbdd:%s", dev_name(dev));
}

static void sbdd_dev_release(struct device *dev)
{
	struct device **dev_ptr = &dev;
	struct sbdd *sbdd_dev = to_sbdd_device(dev_ptr);
	if(sbdd_dev == NULL)
		return;
	sbdd_delete(sbdd_dev);
}

struct device_type __sbdd_device_type = {
	.uevent = sbdd_dev_uevent,
	.release = sbdd_dev_release,
};

static struct sbdd      __sbdd;
//static int              __sbdd_major = 0;
static unsigned long    __sbdd_capacity_mib = 100;
static int __auto_add_dev = 1;

static sector_t sbdd_xfer(struct bio_vec* bvec, sector_t pos, int dir)
{
	void *buff = page_address(bvec->bv_page) + bvec->bv_offset;
	sector_t len = bvec->bv_len >> SBDD_SECTOR_SHIFT;
	size_t offset;
	size_t nbytes;

	if (pos + len > __sbdd.capacity)
		len = __sbdd.capacity - pos;

	offset = pos << SBDD_SECTOR_SHIFT;
	nbytes = len << SBDD_SECTOR_SHIFT;

	spin_lock(&__sbdd.datalock);

	if (dir)
		memcpy(__sbdd.data + offset, buff, nbytes);
	else
		memcpy(buff, __sbdd.data + offset, nbytes);

	spin_unlock(&__sbdd.datalock);

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
		pos += sbdd_xfer(&bvec, pos, dir);
}

static blk_status_t sbdd_queue_rq(struct blk_mq_hw_ctx *hctx,
                                  struct blk_mq_queue_data const *bd)
{
	if (atomic_read(&__sbdd.deleting))
		return BLK_STS_IOERR;

	atomic_inc(&__sbdd.refs_cnt);

	blk_mq_start_request(bd->rq);
	sbdd_xfer_rq(bd->rq);
	blk_mq_end_request(bd->rq, BLK_STS_OK);

	if (atomic_dec_and_test(&__sbdd.refs_cnt))
		wake_up(&__sbdd.exitwait);

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
		pos += sbdd_xfer(&bvec, pos, dir);
}

static blk_qc_t sbdd_make_request(struct request_queue *q, struct bio *bio)
{
	if (atomic_read(&__sbdd.deleting))
		return BLK_STS_IOERR;

	atomic_inc(&__sbdd.refs_cnt);

	sbdd_xfer_bio(bio);
	bio_endio(bio);

	if (atomic_dec_and_test(&__sbdd.refs_cnt))
		wake_up(&__sbdd.exitwait);

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

static int sbdd_create(struct sbdd *sbdd_dev, const char *name, unsigned long capacity_mib)
{
	int ret = 0;
	
	memset(sbdd_dev, 0, sizeof(struct sbdd));
	/*
	This call is somewhat redundant, but used anyways by tradition.
	The number is to be displayed in /proc/devices (0 for auto).
	*/
	pr_info("registering blkdev\n");
	sbdd_dev->major = register_blkdev(0, name);
	if (sbdd_dev->major < 0) {
		pr_err("call register_blkdev() failed with %d\n", sbdd_dev->major);
		return -EBUSY;
	}

	sbdd_dev->capacity_mib = capacity_mib;
	sbdd_dev->capacity = (sector_t)sbdd_dev->capacity_mib * SBDD_MIB_SECTORS;

	pr_info("allocating data\n");
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
	/*struct block_device_operations sbdd_bdev_ops = {
		.owner = THIS_MODULE,
	};*/
	sbdd_dev->tag_set->ops = &__sbdd_blk_mq_ops;
	//sbdd_dev->tag_set->ops = sbdd_bdev_ops;

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
	sbdd_dev->gd->fops = &__sbdd_bdev_ops;
	//sbdd_dev->gd->fops = sbdd_dev_ops;
	/* Represents name in /proc/partitions and /sys/block */
	scnprintf(sbdd_dev->gd->disk_name, DISK_NAME_LEN, name);
	set_capacity(sbdd_dev->gd, sbdd_dev->capacity);

	sbdd_dev->dev = disk_to_dev(sbdd_dev->gd);
	//sbdd_dev->dev->bus = &__sbdd_bus_type;
	//sbdd_dev->dev->type = &__sbdd_device_type;
	//sbdd_dev->dev->parent = NULL;
	/*
	Allocating gd does not make it available, add_disk() required.
	After this call, gd methods can be called at any time. Should not be
	called before the driver is fully initialized and ready to process reqs.
	*/
	pr_info("adding disk\n");
	add_disk(sbdd_dev->gd);

	
	return ret;
}

static void sbdd_delete(struct sbdd *sbdd_dev)
{
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

	char name[DISK_NAME_LEN];
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
#endif

	if (sbdd_dev->data) {
		pr_info("freeing data\n");
		vfree(sbdd_dev->data);
	}

	memset(sbdd_dev, 0, sizeof(struct sbdd));

	if (sbdd_dev->major > 0) {
		pr_info("unregistering blkdev %31s\n", name);
		unregister_blkdev(sbdd_dev->major, name);
		sbdd_dev->major = 0;
	}
}

/*
Note __init is for the kernel to drop this function after
initialization complete making its memory available for other uses.
There is also __initdata note, same but used for variables.
*/
static int __init sbdd_init(void)
{
	int ret = 0;

	pr_info("starting bus initialization...\n");
	ret = bus_register(&__sbdd_bus_type);
	if (ret < 0) {
		pr_err("Unable to register bus \n");
		goto bus_err;
	}

	pr_info("starting driver initialization...\n");
	ret = sbdd_register_driver(&__sbdd_driver);

        if (ret) {
                pr_err("unable to register driver: %d\n", ret);
                goto driver_err;
        }
	
	if (__auto_add_dev) {
		pr_info("starting dev initialization...\n");
		ret = sbdd_create(&__sbdd, SBDD_NAME, __sbdd_capacity_mib);

		if (ret) {
			pr_warn("dev initialization failed\n");
			goto auto_dev_err;
		} else {
			pr_info("dev initialization complete\n");
		}
	}

	return ret;

auto_dev_err:
	sbdd_delete(&__sbdd);
	sbdd_unregister_driver(&__sbdd_driver);
driver_err:
	bus_unregister(&__sbdd_bus_type);
bus_err:
	return ret;
}

/*
Note __exit is for the compiler to place this code in a special ELF section.
Sometimes such functions are simply discarded (e.g. when module is built
directly into the kernel). There is also __exitdata note.
*/
static void __exit sbdd_exit(void)
{
	pr_info("exiting...\n");
	sbdd_unregister_driver(&__sbdd_driver);
	pr_info("driver unregistered\n");
	bus_unregister(&__sbdd_bus_type);
	pr_info("bus unregistered\n");
	if(__auto_add_dev)
		sbdd_delete(&__sbdd);
	pr_info("exiting complete\n");
}

/* Called on module loading. Is mandatory. */
module_init(sbdd_init);

/* Called on module unloading. Unloading module is not allowed without it. */
module_exit(sbdd_exit);

/* Set desired capacity with insmod */
module_param_named(capacity_mib, __sbdd_capacity_mib, ulong, S_IRUGO);
module_param_named(auto_add_dev, __auto_add_dev, int, S_IRUGO);

/* Note for the kernel: a free license module. A warning will be outputted without it. */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple Block Device Driver");
