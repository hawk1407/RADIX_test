#ifndef _SBDD_H
#define _SBDD_H

struct sbdd {
        wait_queue_head_t       exitwait;
        spinlock_t              datalock;
        atomic_t                deleting;
        atomic_t                refs_cnt;
        sector_t                capacity;
        u8                      *data;
        const char              *type;
        struct gendisk          *gd;
        struct device           *dev;
        struct request_queue    *q;
#ifdef BLK_MQ_MODE
        struct blk_mq_tag_set   *tag_set;
#endif
};

#define to_sbdd_device(device) container_of(device, struct sbdd, dev)

struct sbdd_driver {
        const char *type;

        int (*probe)(struct sbdd *dev);
        void (*remove)(struct sbdd *dev);

        struct device_driver driver;
};

#define to_sbdd_driver(drv) container_of(drv, struct sbdd_driver, driver)

int sbdd_register_driver(struct sbdd_driver *drv);
void sbdd_unregister_driver(struct sbdd_driver *drv);
#endif //_SBDD_H
