#include <linux/module.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/ctype.h>

MODULE_LICENSE("GPL");

#define JAVA_MAGIC "\xca\xfe\xba\xbe"

static struct kobject *mysc_kobj;
struct binfmt {
    /* we really shouldn't use static buffers */
    unsigned char magic[256];
    unsigned char interp[256];
    struct list_head list;
};

LIST_HEAD(binfmts);

static void dump(unsigned char *buf) {
    while (*buf) {
        printk(KERN_INFO "%x\n", *buf++);
    }
    printk(KERN_INFO "-- end --\n");
}

static void dumpn(unsigned char *buf, size_t n) {
    while (*buf && n--) {
        printk(KERN_INFO "%x\n", *buf++);
    }
    printk(KERN_INFO "-- end --\n");
}

static size_t print_bf_struct(const int i, char *const buf, struct binfmt *bf)
{
    unsigned char *m = bf->magic;
    size_t bytes_written = 0;
    bytes_written += scnprintf(buf, PAGE_SIZE, "%d: ", i);
    while (*m) {
        bytes_written += scnprintf(buf+bytes_written, PAGE_SIZE-bytes_written, "%x", *m++);
        if (bytes_written == PAGE_SIZE-1)
            return bytes_written;
    }
    bytes_written += scnprintf(buf+bytes_written, PAGE_SIZE-bytes_written, " -> %s\n", bf->interp);
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
        dump(bf->magic);
        bytes_written += print_bf_struct(i++, curr+bytes_written, bf);
        if (bytes_written == PAGE_SIZE-1)
            return bytes_written;
    }
    return bytes_written;
}

static ssize_t hexpairs_to_buf(unsigned char *const buf, size_t bufsz, char *const hexpairs, size_t hexsz)
{
    unsigned char *b = buf;
    size_t i;
    if (hexsz % 2)
        goto err;

    /* TODO do this in one pass */
    for (i = 0; i < hexsz; i++) {
        if(!isxdigit(hexpairs[i])) {
            goto err;
        }
        if (hexpairs[i] >= 'A' && hexpairs[i] <= 'F') {
                hexpairs[i] += 32; // convert all caps to lowercase
        }
    }

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
    }
    *b = '\0';
    return b-buf+1;

err:
    return -EINVAL;
}

static ssize_t mysc_store(struct kobject *dev, struct kobj_attribute *attr,
                     const char *buf, size_t count)
{
    char *colon;
    int interpsz;
    struct binfmt *bf;
    ssize_t ret;
    bf = kmalloc(sizeof(*bf), GFP_KERNEL);
    if (!bf)
        return -ENOMEM;

    /* i think this is not necessary */
    INIT_LIST_HEAD(&bf->list);

    colon = strnchr(buf, count, ':');
    if (!colon) {
        return -EINVAL;
    }

    ret = hexpairs_to_buf(bf->magic, sizeof(bf->magic), buf, colon - buf);
    if (ret < 0)
        return ret;
    interpsz = scnprintf(bf->interp, sizeof(bf->interp), "%s", colon+1);
    if (bf->interp[interpsz-1] == '\n') {
        bf->interp[interpsz-1] = '\0';
    }

    list_add_tail(&bf->list, &binfmts);
    return count;
}

/* 666 for development ease */
static struct kobj_attribute mysc_attribute = __ATTR(mysc, 0666, mysc_show, mysc_store);

static int create_file_interface(void)
{
    int ret;
    mysc_kobj = kobject_create_and_add("binfmt_mysc", kernel_kobj);
    if (!mysc_kobj)
        return -ENOMEM;

    ret = sysfs_create_file(mysc_kobj, &mysc_attribute.attr);
    if (ret) {
        kobject_put(mysc_kobj); // release
        return ret;
    }

    return ret;
}

static int load_mysc_bf(struct binfmt *bf, struct linux_binprm *bprm)
{
    int retval;
    struct file *file;

    /* magic! */
    /* just doing offset 0 for now, maybe add other offsets later */
    if (memcmp(bprm->buf, bf->magic, strlen(bf->magic))) {
        return -ENOEXEC;
    }

    retval = remove_arg_zero(bprm);
    if (retval)
        return retval;

    /* ok it was legit, let's exec that interp they registered */

    char *last_arg = bprm->interp;
    //special case for java, we need to remove that pesky .class extension
    //this is buggy
    if (memcmp(bprm->buf, JAVA_MAGIC, 4) == 0) {
        if (strncmp(last_arg, "./", 2)==0) {
            last_arg += 2;
        }
        char *period = strchr(last_arg+1, '.');
        if (period) {
            *period = '\0';
        }
    }

    /* this is stolen from fs/bintmf_script.c */

    retval = copy_strings_kernel(1, &last_arg, bprm);
    if (retval){
        return retval;
    }

    bprm->argc++;

    char *wtf = bf->interp;
    retval = copy_strings_kernel(1, &wtf, bprm);
    if (retval){
        return retval;
    }
    bprm->argc++;

    retval = bprm_change_interp((char *)bf->interp, bprm);
    if (retval)
        return retval;

    file = open_exec(bf->interp);
    if (IS_ERR(file))
        return PTR_ERR(file);

    bprm->file = file;
    retval = prepare_binprm(bprm);
    if (retval < 0)
        return retval;

    return search_binary_handler(bprm);
}

static int check_all_mysc(struct linux_binprm *bprm)
{
    int retval = -ENOEXEC;
    struct binfmt *bf;
    list_for_each_entry(bf, &binfmts, list) {
        retval = load_mysc_bf(bf, bprm);
        if (retval != -ENOEXEC) {
            return retval;
        }
    }
    return retval;
}

static struct linux_binfmt mysc_format = {
    .module = THIS_MODULE,
    .load_binary = check_all_mysc,
};


static int __init init_mysc_binfmt(void)
{
    int ret;

    printk(KERN_INFO "binfmt_mysc registering!\n");
    ret = create_file_interface();
    if (ret)
        return ret;
    register_binfmt(&mysc_format);

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
    unregister_binfmt(&mysc_format);
    kobject_put(mysc_kobj);
    destroy_list(&binfmts);
}

module_init(init_mysc_binfmt);
module_exit(exit_mysc_binfmt);
