#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>

int main(int argc, char **argv)
{
    char buf[1024] = {0};
    int fd = open("/sys/kernel/binfmt_mysc/mysc", O_RDWR);
    if (fd < 0) {
        puts("kernel module not loaded! :(");
        return 1;
    }
    if (argc == 1) {
        read(fd, buf, sizeof(buf)-1);
        printf("%s", buf);
    } else if (argc == 3) {
        snprintf(buf, sizeof(buf), "%s:%s", argv[1], argv[2]);
        write(fd, buf, strlen(buf));
    } else {
        puts("Usage: myctl [<magic> <interp>]");
        return 1;
    }

    close(fd);

    return 0;
}
