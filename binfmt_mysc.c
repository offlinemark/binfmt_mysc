/*
 *  binfmt_mysc.c 
 *
 *  Author: Mark Mossberg <mark.mossberg@gmail.com>
 */

#include <linux/module.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/kobject.h>

MODULE_LICENSE("GPL");

static struct kobject *mysc_kobj;

static ssize_t mysc_show(struct kobject *kobj, struct kobj_attribute *attr,
        char *buf)
{
    return sprintf(buf, "hello world ugh\n");
}

static struct kobj_attribute mysc_attribute = __ATTR(mysc, 0664, mysc_show, NULL);


static int __init init_mysc_binfmt(void)
{
    int ret;

    printk(KERN_INFO "binfmt_mysc registering!\n");

    // register fs attributes
    mysc_kobj = kobject_create_and_add("binfmt_mysc", kernel_kobj);
    if (!mysc_kobj)
        return -ENOMEM;

    ret = sysfs_create_file(mysc_kobj, &mysc_attribute.attr);
    if (ret)
        kobject_put(mysc_kobj); // release



    /* register_binfmt(&spym_format); */
    return ret;
}


static void exit_mysc_binfmt(void)
{
    printk(KERN_INFO "Unregistering mysc format!\n");
    /* unregister_binfmt(&spym_format); */
}

module_init(init_mysc_binfmt);
module_exit(exit_mysc_binfmt);
