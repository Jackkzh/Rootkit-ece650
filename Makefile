ifeq ($(KERNELRELEASE),)  

KERNELDIR ?= /lib/modules/$(shell uname -r)/build 
PWD := $(shell pwd)  

.PHONY: build clean  

build:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules  

clean:
	rm -rf *.o *~ core .depend .*.cmd *.order *.symvers *.ko *.mod.c 
else  

$(info Building with KERNELRELEASE = ${KERNELRELEASE}) 
obj-m :=    sneaky_mod.o  

endif



# TARGETS=test 

# all: $(TARGETS)

# test: sneaky_process.c
# 	gcc -o sneaky_process sneaky_process.c
# .PHONY:
# 	clean
# clean:
# 	rm -rf *.o sneaky_process