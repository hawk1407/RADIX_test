#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include "sbdd.h"

MODULE_DESCRIPTION("SBDD misc driver");
MODULE_AUTHOR("Anokhin");
MODULE_LICENSE("GPL");

#define BUF_SIZE 1024

struct sbdd_misc_device {
	struct miscdevice misc;
	struct sbdd *__sbdd;
	char buf[BUF_SIZE];
};

int sbdd_misc_probe(struct sbdd *sbdd)
{
	return 0;
}

void sbdd_misc_remove(struct sbdd *sbdd)
{
	
}

struct sbdd_driver sbdd_misc_driver = {
	.type = "misc",
	.probe = sbdd_misc_probe,
	.remove = sbdd_misc_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = "sbdd_misc",
	},
};

static int misc_drv_init(void)
{
	int err;
	err = sbdd_register_driver(&sbdd_misc_driver);

	if(err) {
		pr_err("unable to register driver: %d\n", err);
		return err;
	}
	return 0;
}

static void misc_drv_exit(void)
{
	sbdd_unregister_driver(&sbdd_misc_driver);
}

module_init(misc_drv_init);
module_exit(misc_drv_exit);
