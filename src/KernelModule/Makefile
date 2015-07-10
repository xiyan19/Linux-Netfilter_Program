obj-m += myhook.o

MAKEARGSB := -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
MAKEARGSC := -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

all:
	@$(MAKE) $(MAKEARGSB)

clean:
	@$(MAKE) $(MAKEARGSC)
