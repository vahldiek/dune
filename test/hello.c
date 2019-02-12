#include <stdio.h>
#include <stdlib.h>

#include "libdune/dune.h"
#include "libdune/cpu-x86.h"

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>

#define VMFUNC_NORMAL_DOMAIN 0
#define VMFUNC_SECURE_DOMAIN 1

#define vmfunc_switch(mapping)						\
  __asm__ __volatile__ (						\
			"mov $0, %%eax \n\t" /* vmfunc number (0=eptp switch) */ \
			"mov %0, %%ecx \n\t" /* eptp index */		\
			"vmfunc \n\t"					\
			:						\
			: "irm"(mapping)				\
			: "%rax", "%rcx", "memory");


static size_t _pageground(size_t sz) {
    int pgz = sysconf(_SC_PAGESIZE);
    return (sz & ~(pgz - 1)) + pgz;
}

void * vmfunc_malloc(size_t size) {

  unsigned int sz = _pageground(size);
  void * pages = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
	       -1, 0);
  if (pages == MAP_FAILED)
    {
        perror("_vmfunc_alloc");
        return NULL;
    }

  printf("page %p size %d\n", pages, sz);
  syscall(DUNE_VMCALL_SECRET_MAPPING_ADD, pages, sz);
  
  return pages;
}

int main(int argc, char *argv[])
{
	volatile int ret;

	printf("hello: not running dune yet\n");

	ret = dune_init_and_enter();
	if (ret) {
		printf("failed to initialize dune\n");
		return ret;
	}

	//	printf("hello: now printing from dune mode\n");

	int * secret = NULL;

	vmfunc_switch(VMFUNC_SECURE_DOMAIN);

	secret = vmfunc_malloc(1024*1024*1024);
	*secret = 7777;
	printf("secret:%p %d\n", secret, *secret);

	vmfunc_switch(VMFUNC_NORMAL_DOMAIN);

	printf("no access to secret: %p\n", secret);

	//printf("pagefault secret: %d\n", *secret);

	vmfunc_switch(VMFUNC_SECURE_DOMAIN);

	*secret += 1;
	printf("secret %d\n", *secret);

	vmfunc_switch(VMFUNC_NORMAL_DOMAIN);
	
	/*
	dune_register_intr_handler(T_DIVIDE, divide_by_zero_handler);
	
	ret = 1 / ret; 

	printf("hello: we won't reach this call\n");
	*/

	return 0;
}

