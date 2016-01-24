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
        printk(KERN_INFO "omg\n");
        dump(bf->magic);
        bytes_written += print_bf_struct(i, curr+bytes_written, bf);
        if (bytes_written == PAGE_SIZE-1)
            return bytes_written;
        printk(KERN_INFO "yo %d bf->str: %s\n", i, bf->interp);
        i++;
    }
    return bytes_written;
}

static ssize_t hexpairs_to_buf(unsigned char *const buf, size_t bufsz, char *const hexpairs, size_t hexsz)
{
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
    char *colon;
    int interpsz;
    struct binfmt *bf;
    ssize_t ret;
    bf = kmalloc(sizeof(*bf), GFP_KERNEL);
    if (!bf)
        return -ENOMEM;

    INIT_LIST_HEAD(&bf->list);

    printk(KERN_INFO "yo dat size was %u\n", count);

    colon = strnchr(buf, count, ':');
    if (!colon) {
        return -EINVAL;
    }

    printk(KERN_INFO "ABOUT TO CALL HEXPAIRS %s %u %u\n", buf, colon - buf, sizeof(bf->magic));
    ret = hexpairs_to_buf(bf->magic, sizeof(bf->magic), buf, colon - buf);
    if (ret < 0)
        return ret;
    interpsz = scnprintf(bf->interp, sizeof(bf->interp), "%s", colon+1);
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
    int ret;
    // register fs attributes
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

    printk(KERN_INFO "yo entering that load thing\n");

    dumpn(bprm->buf, 8);
    dumpn(bf->magic, 4);


    /* magic! */
    /* just doing offset 0 for now, maybe add other offsets later */
    if (memcmp(bprm->buf, bf->magic, strlen(bf->magic))) {
        printk(KERN_INFO "NO IT DID NOT MAGIC\n");
            return -ENOEXEC;
    }

    printk(KERN_INFO "wow the magic passed\n");

    retval = remove_arg_zero(bprm);
    if (retval)
            return retval;

    /* ok it was legit, let's exec that interp they registered */

    printk(KERN_INFO "last arg %s\n", bprm->interp);
    char *last_arg = bprm->interp;
    //special case for java, we need to remove that pesky .class extension
#define JAVA_MAGIC "\xca\xfe\xba\xbe"
    dumpn(bprm->buf, 4);
    dumpn(JAVA_MAGIC, 4);
    printk(KERN_INFO "omggggggg last arg: %s\n", last_arg);
    /* printk(KERN_INFO "str: %s\n", last_arg); */
    if (memcmp(bprm->buf, JAVA_MAGIC, 4) == 0) {
        printk(KERN_INFO "in here?: %s\n", last_arg);
        if (strncmp(last_arg, "./", 2)==0) {
            last_arg += 2; 
        }
        char *period = strchr(last_arg+1, '.');
        if (period) {
            printk(KERN_INFO "FOUND DAT PERIOD\n");
            *period = '\0';
        }
    }
    printk(KERN_INFO "omggggggg last arg: %s\n", last_arg);
    retval = copy_strings_kernel(1, &last_arg, bprm);
    if (retval){
            return retval;
    }

    bprm->argc++;

    printk(KERN_INFO "first arg %s\n", bf->interp);
    char *wtf = bf->interp;
    /* retval = copy_strings_kernel(1, &(bf->interp), bprm); */
    retval = copy_strings_kernel(1, &wtf, bprm);
    if (retval){
        printk(KERN_INFO "fuckk why did this fail!!!!\n");
            return retval;
    }
    bprm->argc++;

    printk(KERN_INFO "got stack all set \n");

    retval = bprm_change_interp((char *)bf->interp, bprm);
    if (retval)
            return retval;

    printk(KERN_INFO "got change interp all set \n");

    /* Final preparations */
    file = open_exec(bf->interp);
    if (IS_ERR(file))
            return PTR_ERR(file);

    printk(KERN_INFO "got open exec all set \n");

    bprm->file = file;
    retval = prepare_binprm(bprm);
    if (retval < 0)
            return retval;

    printk(KERN_INFO "got prepare binprm all set \n");

    return search_binary_handler(bprm);
}

static int check_all_mysc(struct linux_binprm *bprm)
{
    int retval = -ENOEXEC;
    struct binfmt *bf;
    list_for_each_entry(bf, &binfmts, list) {
        printk(KERN_INFO "processing %s\n", bf->interp);
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
    // TODO free memory
}

module_init(init_mysc_binfmt);
module_exit(exit_mysc_binfmt);
