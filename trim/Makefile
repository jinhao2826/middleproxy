obj-m +=trim.o

KDIR =/usr/src/linux-headers-3.16.0-4-amd64

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order
