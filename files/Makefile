ARCH := $(shell uname -m)

bind.so.$(ARCH):	bind.c
	gcc -nostartfiles -fpic -shared bind.c -o bind.so.$(ARCH) -ldl -D_GNU_SOURCE -O2 -Wall
	chmod -x bind.so.$(ARCH)

clean:
	rm -f bind.so.*
