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

static char shitbuf[256];

static ssize_t mysc_store(struct kobject *dev, struct kobj_attribute *attr,
                     const char *buf, size_t count)
{
    printk(KERN_INFO "yo dat size was %u\n", count);
    if (count > 10) {
        printk(KERN_INFO "too big tho\n");
        return count;
    }
    scnprintf(shitbuf, 10, "%s", buf);
    printk(KERN_INFO "shitbuf: %s\n", shitbuf);
    return count;
}

static struct kobj_attribute mysc_attribute = __ATTR(mysc, 0666, mysc_show, mysc_store);

static int create_file_interface(void)
{
    // register fs attributes
    mysc_kobj = kobject_create_and_add("binfmt_mysc", kernel_kobj);
    if (!mysc_kobj)
        return -ENOMEM;

    int ret = sysfs_create_file(mysc_kobj, &mysc_attribute.attr);
    if (ret) {
        kobject_put(mysc_kobj); // release
        return ret;
    }

    return 0;
}


static int __init init_mysc_binfmt(void)
{
    int ret;

    printk(KERN_INFO "binfmt_mysc registering!\n");

    ret = create_file_interface();
    if (ret)
        return ret;




    /* register_binfmt(&spym_format); */
    return ret;
}


static void exit_mysc_binfmt(void)
{
    printk(KERN_INFO "Unregistering mysc format!\n");
    kobject_put(mysc_kobj);
    /* unregister_binfmt(&spym_format); */
}

module_init(init_mysc_binfmt);
module_exit(exit_mysc_binfmt);
