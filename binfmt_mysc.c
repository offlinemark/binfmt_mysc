#include <linux/module.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

static struct kobject *mysc_kobj;
struct binfmt {
    char str[256];
    struct list_head list;
};

LIST_HEAD(binfmts);

static ssize_t mysc_show(struct kobject *kobj, struct kobj_attribute *attr,
        char *buf)
{
    return sprintf(buf, "hello world ugh\n");
}

static char shitbuf[8];

static ssize_t mysc_store(struct kobject *dev, struct kobj_attribute *attr,
                     const char *buf, size_t count)
{
    struct binfmt *bf;
    bf = kmalloc(sizeof(*bf), GFP_KERNEL);
    if (!bf)
        return -ENOMEM;

    printk(KERN_INFO "yo dat size was %u\n", count);
    scnprintf(bf->str, sizeof(bf->str), "%s", buf);
    printk(KERN_INFO "bf->str: %s\n", bf->str);

    list_add(&bf->list, &binfmts);
    printk(KERN_INFO "added to list\n");

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
