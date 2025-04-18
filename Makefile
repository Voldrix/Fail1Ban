obj-m += fail1ban_mod.o

PWD := $(CURDIR) 

all: mod log

mod:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

log:
	gcc -Wall -Wno-unused-function -O2 fail1ban_log.c -o fail1ban_log

cf:
	gcc -Wall -Wno-unused-function -O2 fail1ban_log.c -DCF -o fail1ban_log_cf

clean:
	rm -f *.o *.o.cmd *.mod *.mod.c *.ko *.order *.order.cmd *.symvers .fail1ban* .modules.order.cmd .Module.symvers.cmd

cleanmods:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

