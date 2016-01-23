#include <linux/module.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/ctype.h>

MODULE_LICENSE("GPL");

static struct kobject *mysc_kobj;
struct binfmt {
    unsigned char magic[256];
    unsigned char interp[256];
    struct list_head list;
};

LIST_HEAD(binfmts);

static void dump(unsigned char *buf) {
    while (*buf) {
        printk(KERN_INFO "%x\n", *buf++);
    }
    printk(KERN_INFO "\n");
}

static size_t print_bf_struct(const int i, char *const buf, struct binfmt *bf)
{
    size_t bytes_written = 0;
    bytes_written += scnprintf(buf, PAGE_SIZE, "%d: ", i);
    unsigned char *m = bf->magic;
    while (m) {
        bytes_written += scnprintf(buf+bytes_written, PAGE_SIZE-bytes_written, "%x", *m++);
        if (bytes_written == PAGE_SIZE-1)
            return bytes_written;
    }
    bytes_written += scnprintf(buf+bytes_written, PAGE_SIZE-bytes_written, "%s\n", bf->interp);
    return bytes_written;
}

static ssize_t mysc_show(struct kobject *kobj, struct kobj_attribute *attr,
        char *buf)
{
    char *curr = buf;
    ssize_t bytes_written = 0;

    struct binfmt *bf;
    int i = 0;
    list_for_each_entry(bf, &binfmts, list) {
        bytes_written += print_bf_struct(i, curr, bf);
        if (bytes_written == PAGE_SIZE-1)
            return bytes_written;
        printk(KERN_INFO "yo %d bf->str: %s\n", i, bf->interp);
        i++;
    }
    return bytes_written;
}

static ssize_t hexpairs_to_buf(unsigned char *const buf, size_t bufsz, char *const hexpairs, size_t hexsz)
{
    /* strcpy(buf, "SPYM\x00"); */
    /* return 0; */
    // TODO actually implement. "aabbccdd" => \xaa\xbb\xcc\xdd
    unsigned char *b = buf;
    size_t i;
    printk(KERN_INFO "i am in hexpairs %s\n", hexpairs);
    if (hexsz % 2)
        goto err;

    printk(KERN_INFO "first pass bufsz %u hexsz %u hexpairs %s\n", bufsz, hexsz, hexpairs);
    for (i = 0; i < hexsz; i++) {
        if(!isxdigit(hexpairs[i])) {
            printk(KERN_INFO "YO IT WASNT X %c\n", hexpairs[i]);
            goto err;
        }
        if (hexpairs[i] >= 'A' && hexpairs[i] <= 'F') {
                hexpairs[i] += 32; // convert all caps to lowercase
        }
    }

    printk(KERN_INFO "second pass bufsz %u hexsz %u\n", bufsz, hexsz);
    for (i = 0; i < hexsz; i+=2) {
        char newchar;
        if(isdigit(hexpairs[i]))
            newchar = (hexpairs[i]-'0')*0x10;
        else
            newchar = (hexpairs[i]-'W')*0x10;
        if(isdigit(hexpairs[i+1]))
            newchar += (hexpairs[i+1]-'0');
        else
            newchar += (hexpairs[i+1]-'W');
        *b++ = newchar;
        printk(KERN_INFO "FUCK %x\n", (unsigned char)newchar);
    }
    *b = '\0';
    printk(KERN_INFO "FFFFFF\n");
    printk(KERN_INFO "0 %x\n", buf[0]);
    printk(KERN_INFO "1 %x\n", buf[1]);
    printk(KERN_INFO "2 %x\n", buf[2]);
    printk(KERN_INFO "3 %x\n", buf[3]);
    dump(buf);

    return b-buf+1;


err:
    return -EINVAL;
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

    printk(KERN_INFO "ABOUT TO CALL HEXPAIRS %s %u %u\n", buf, colon - buf, sizeof(bf->magic));
    ssize_t ret = hexpairs_to_buf(bf->magic, sizeof(bf->magic), buf, colon - buf);
    if (ret < 0)
        return ret;
    int interpsz = scnprintf(bf->interp, sizeof(bf->interp), "%s", colon+1);
    if (bf->interp[interpsz-1] == '\n') {
        bf->interp[interpsz-1] = '\0';
    }


    printk(KERN_INFO "bf->magic: \n");
    printk(KERN_INFO "FFFFFF\n");
    printk(KERN_INFO "0 %x\n", bf->magic[0]);
    printk(KERN_INFO "1 %x\n", bf->magic[1]);
    printk(KERN_INFO "2 %x\n", bf->magic[2]);
    printk(KERN_INFO "3 %x\n", bf->magic[3]);
    dump(bf->magic);
    /* unsigned char *shit = bf->magic; */
    /* while (shit) { */
        /* printk(KERN_INFO "%x", *bf->magic); */
    /* } */
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


    return ret;
}

static void destroy_list(struct list_head *head)
{
    struct binfmt *pos, *next;
    list_for_each_entry_safe(pos, next, head, list) {
        list_del(&pos->list);
        kfree(pos);
    }
}


static void exit_mysc_binfmt(void)
{
    printk(KERN_INFO "Unregistering mysc format!\n");
    kobject_put(mysc_kobj);
    destroy_list(&binfmts);
    // TODO free memory
}

module_init(init_mysc_binfmt);
module_exit(exit_mysc_binfmt);
