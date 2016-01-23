obj-m := binfmt_mysc.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -rf *.symvers *.order *.ko *.o *.mod*
