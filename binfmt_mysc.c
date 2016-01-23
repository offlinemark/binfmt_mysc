#include <linux/module.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

static struct kobject *mysc_kobj;
struct binfmt {
    char magic[256];
    char interp[256];
    struct list_head list;
};

LIST_HEAD(binfmts);

static ssize_t mysc_show(struct kobject *kobj, struct kobj_attribute *attr,
        char *buf)
{
    char *curr = buf;
    ssize_t bytes_written = 0;

    struct binfmt *bf;
    int i = 0;
    list_for_each_entry(bf, &binfmts, list) {
        bytes_written += scnprintf(curr+bytes_written, PAGE_SIZE-bytes_written, "%d: %s %s\n", i, bf->magic, bf->interp);
        if (bytes_written == PAGE_SIZE-1)
            return bytes_written;
        printk(KERN_INFO "yo %d bf->str: %s\n", i, bf->interp);
        i++;
    }
    return bytes_written;
    /* return scnprintf(buf, PAGE_SIZE, "hello world ugh\n"); */
}

static ssize_t hexpairs_to_buf(char *const buf, size_t bufsz, const char *hexpairs, size_t hexsz)
{
    strcpy(buf, "SPYM\x00");
    return 0;
    // TODO actually implement. "aabbccdd" => \xaa\xbb\xcc\xdd
    /* if (hexsz % 2) */
    /*     return -EINVAL; */
    /* for (size_t i = 0; i < hexsz; i+= 2) { */

    /* } */

}

static ssize_t mysc_store(struct kobject *dev, struct kobj_attribute *attr,
                     const char *buf, size_t count)
{
    struct binfmt *bf;
    bf = kmalloc(sizeof(*bf), GFP_KERNEL);
    if (!bf)
        return -ENOMEM;

    INIT_LIST_HEAD(&bf->list);

    printk(KERN_INFO "yo dat size was %u\n", count);

    char *colon = strnchr(buf, count, ':');
    if (!colon) {
        return -EINVAL;
    }

    hexpairs_to_buf(bf->magic, sizeof(bf->magic), buf, colon - buf);
    int interpsz = scnprintf(bf->interp, sizeof(bf->interp), "%s", colon+1);
    if (bf->interp[interpsz-1] == '\n') {
        bf->interp[interpsz-1] = '\0';
    }


    printk(KERN_INFO "bf->magic: %s\n", bf->magic);
    printk(KERN_INFO "bf->intepr: %s\n", bf->interp);

    list_add_tail(&bf->list, &binfmts);
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
    // TODO free memory
    /* unregister_binfmt(&spym_format); */
}

module_init(init_mysc_binfmt);
module_exit(exit_mysc_binfmt);
