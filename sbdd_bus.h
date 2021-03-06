#ifndef _SBDD_BUS_H
#define _SBDD_BUS_H

struct sbdd_device {
	struct device dev;
	unsigned long capacity_mib;
};

#define to_sbdd_device(device) container_of(device, struct sbdd_device, dev)

struct sbdd_driver {
        int (*probe)(struct sbdd_device *dev);
        void (*remove)(struct sbdd_device *dev);
	int (*resize_disk)(struct sbdd_device *dev, unsigned long capacity_mib);
	int (*set_mod)(struct sbdd_device *dev, int flag_ro);

        struct device_driver driver;
};

#define to_sbdd_driver(drv) container_of(drv, struct sbdd_driver, driver)

int sbdd_register_driver(struct sbdd_driver *drv);
void sbdd_unregister_driver(struct sbdd_driver *drv);
int sbdd_add_dev(const char *name, unsigned long capacity_mib, int allow_add);
void set_usr_mod_dev(int only_usr_mod_dev);

#endif //_SBDD_BUS_H
