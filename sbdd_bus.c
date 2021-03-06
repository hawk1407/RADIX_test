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
//#include <drivers/base/platform.h>
#ifdef BLK_MQ_MODE
#include <linux/blk-mq.h>
#endif

#include "sbdd_bus.h"

static int usr_mod_dev;

static int sbdd_match(struct device *dev, struct device_driver *driver)
{
	struct sbdd_device *sbdd_dev;
        struct sbdd_driver *sbdd_drv;

	pr_info("sbdd_match\n");
	sbdd_dev = to_sbdd_device(dev);
        sbdd_drv = to_sbdd_driver(driver);

        /*if (!strcmp(dev_name(&sbdd_dev->dev), sbdd_drv->driver.name)) {
		return 1;
	}
	pr_err("dev %s and drv %s does not match\n", dev_name(&sbdd_dev->dev), 
		sbdd_drv->driver.name);
	return 0;*/
	return 1;
}

static int sbdd_probe(struct device *dev)
{
	struct sbdd_device *sbdd_dev;
        struct sbdd_driver *sbdd_drv;

	pr_info("sbdd_probe\n");
	sbdd_dev = to_sbdd_device(dev);
	sbdd_drv = to_sbdd_driver(dev->driver);

        return sbdd_drv->probe(sbdd_dev);

}

static int sbdd_remove(struct device *dev)
{
	struct sbdd_device *sbdd_dev;
        struct sbdd_driver *sbdd_drv;

	pr_info("bus remove device\n");
	sbdd_dev = to_sbdd_device(dev);
        sbdd_drv = to_sbdd_driver(dev->driver);

        sbdd_drv->remove(sbdd_dev);

	return 0;
}

static int sbdd_dev_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	return add_uevent_var(env, "MODALIAS=sbdd:%s", dev_name(dev));
}

static void sbdd_dev_release(struct device *dev)
{
	struct sbdd_device *sbdd_dev;
	pr_info("sbdd_dev_release\n");
	sbdd_dev = to_sbdd_device(dev);

        kfree(sbdd_dev);
}

static int sbdd_del_dev(struct device *dev, void *p);
static int sbdd_del_dev_name(const char *name, int allow_del);

static ssize_t
resize_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct sbdd_device *sbdd_dev;
	struct sbdd_driver *sbdd_drv;
	unsigned long capacity_mib;
	int ret;
	ret = sscanf(buf, "%lu", &capacity_mib);
	if(ret != 1)
        {
                pr_err("resize_dev not enough arguments read\n");
                return -EINVAL;
        }

	sbdd_dev = to_sbdd_device(dev);
        sbdd_drv = to_sbdd_driver(dev->driver);
	
	return sbdd_drv->resize_disk(sbdd_dev, capacity_mib) ? : count;
}
struct device_attribute dev_attr_resize = __ATTR(resize, S_IWUSR, NULL, resize_store);

static ssize_t
set_mod_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct sbdd_device *sbdd_dev;
        struct sbdd_driver *sbdd_drv;
	int flag_ro;
	int ret;

	ret = sscanf(buf, "%d", &flag_ro);  
        if (ret != 1) {
                pr_err("set_mod_dev not enough arguments read\n");
                return -EINVAL;
	}

	sbdd_dev = to_sbdd_device(dev);
        sbdd_drv = to_sbdd_driver(dev->driver);

        return sbdd_drv->set_mod(sbdd_dev, flag_ro) ? : count;

}
struct device_attribute dev_attr_set_mod = __ATTR(set_mod, S_IWUSR, NULL, set_mod_store);

static struct attribute *sbdd_dev_attrs[] = {
        &dev_attr_resize.attr,
	&dev_attr_set_mod.attr,
        NULL
};

static struct attribute_group sbdd_dev_group = {
        .attrs = sbdd_dev_attrs,
        NULL,
};

static const struct attribute_group *sbdd_dev_groups[] = {
        &sbdd_dev_group,
        NULL,
};


struct device_type __sbdd_device_type = {
	.uevent = sbdd_dev_uevent,
	.release = sbdd_dev_release,
	.groups = sbdd_dev_groups,
};

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

	return sbdd_add_dev(name, capacity_mib, usr_mod_dev) ? : count;
}
struct bus_attribute bus_attr_add = __ATTR(add, S_IWUSR, NULL, add_store);


static ssize_t
del_store(struct bus_type *bt, const char *buf, size_t count)
{
        char name[32];

        if (sscanf(buf, "%s", name) != 1)
                return -EINVAL;

        return sbdd_del_dev_name(name, usr_mod_dev) ? : count;

}
struct bus_attribute bus_attr_del = __ATTR(del, S_IWUSR, NULL, del_store);

/*static int custom_match_dev(struct device *dev, void *data)
{
// this function implements the comaparison logic. Return not zero if found.
    const char *name = data;

    return sysfs_streq(name, dev->of_node->name);
}

static struct device *find_dev( const char *name )
{
    struct device *dev = bus_find_device(&platform_bus_type, NULL, name, custom_match_dev);

    return dev;
}

static int sbdd_find_dev_name(const char *name)
{
	struct device *dev;
	dev = find_dev(name);

	if(dev)
	{
		pr_info("dev found %s\n", dev_name(dev));
	}

	return 1;
}

static ssize_t
find_store(struct bus_type *bt, const char *buf, size_t count)
{
        char name[32];

        if (sscanf(buf, "%s", name) != 1)
                return -EINVAL;

        return sbdd_find_dev_name(name) ? : count;
}
struct bus_attribute bus_attr_find = __ATTR(find, S_IWUSR, NULL, find_store);
*/


static struct attribute *sbdd_drv_attrs[] = {
	&bus_attr_add.attr,
	&bus_attr_del.attr,
	//&bus_attr_find.attr,
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
	//.dev_groups = sbdd_dev_groups,
};

int sbdd_add_dev(const char *name, unsigned long capacity_mib, int allow_add)
{
	struct sbdd_device *sbdd_dev;
	if(!allow_add)
	{
		pr_info("user cannot mod devs mode is enabled\n");
		return 0;
	}
	pr_info("user add dev name: %s, capacity_mib: %lu \n", name, capacity_mib);
        sbdd_dev = kzalloc(sizeof(*sbdd_dev), GFP_KERNEL);
        if (!sbdd_dev)
                return -ENOMEM;

        sbdd_dev->dev.bus = &__sbdd_bus_type;
        sbdd_dev->dev.type = &__sbdd_device_type;
        sbdd_dev->dev.parent = NULL;
	sbdd_dev->capacity_mib = capacity_mib;

        dev_set_name(&sbdd_dev->dev, "%s", name);

        return device_register(&sbdd_dev->dev);
}
EXPORT_SYMBOL(sbdd_add_dev);

static int sbdd_del_dev_name(const char *name, int allow_del)
{
        struct device *dev = NULL;
	if(!allow_del)
	{
		pr_info("user cannot mod devs mode is enabled\n");
		return 0;
	}

	pr_info("sbdd_del_dev %s", name);
        dev = bus_find_device_by_name(&__sbdd_bus_type, NULL, name);
        if (!dev)
                return -EINVAL;

        device_unregister(dev);
        put_device(dev);

	pr_info("device %s removed\n", name);

        return 0;
}

static int sbdd_del_dev(struct device *dev, void *p)
{
        pr_info("removing device %s\n", dev_name(dev));
        device_unregister(dev);
        put_device(dev);

        return 0;
}

static void sbdd_del_all_devs(void)
{

        pr_info("bex_del_all_devs\n");
        bus_for_each_dev(&__sbdd_bus_type, NULL, NULL, sbdd_del_dev);
        pr_info("all devs removed\n");
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
EXPORT_SYMBOL(sbdd_register_driver);

void sbdd_unregister_driver(struct sbdd_driver *drv)
{
	driver_unregister(&drv->driver);
	pr_info("driver unregistered\n");
}
EXPORT_SYMBOL(sbdd_unregister_driver);

void set_usr_mod_dev(int only_usr_mod_dev)
{
	usr_mod_dev = only_usr_mod_dev;
}
EXPORT_SYMBOL(set_usr_mod_dev);

static int __init sbdd_bus_init(void)
{
	int ret = 0;

	pr_info("starting bus initialization...\n");
	ret = bus_register(&__sbdd_bus_type);
	if (ret < 0) {
		pr_err("Unable to register bus \n");
		return ret;
	}

	pr_info("bus initialized\n");

	return ret;
}

static void __exit sbdd_bus_exit(void)
{
	pr_info("exiting...\n");
	sbdd_del_all_devs();
	bus_unregister(&__sbdd_bus_type);
	pr_info("bus unregistered\n");
	pr_info("exiting complete\n");
}

/* Called on module loading. Is mandatory. */
module_init(sbdd_bus_init);

/* Called on module unloading. Unloading module is not allowed without it. */
module_exit(sbdd_bus_exit);

/* Note for the kernel: a free license module. A warning will be outputted without it. */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple Block Device Bus");
