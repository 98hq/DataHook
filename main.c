#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sched.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <link.h>
extern void syscall_addr(void);
extern long enter_syscall(int32_t, int32_t, int32_t, int32_t, int32_t, int32_t, int32_t);
extern void asm_syscall_hook(void);
unsigned long libc_start=0;
unsigned long libc_exec_start=0;
unsigned long libc_end=0;
unsigned long after_gs_24=0;
unsigned long int sysinfo=0;
void ____asm_impl(void)
{
	/*
	 * enter_syscall triggers a kernel-space system call
	 */
	asm volatile (
	".globl enter_syscall \n\t"
	"enter_syscall: \n\t"
	"push %ebp \n\t" 
	"mov 0x8(%esp), %eax \n\t"
	"mov 0xc(%esp), %ebx \n\t"
	"mov 0x10(%esp), %ecx \n\t"
	"mov 0x14(%esp), %edx \n\t"
	"mov 0x18(%esp), %esi \n\t"
	"mov 0x1c(%esp), %edi \n\t"
	"mov 0x20(%esp), %ebp \n\t"
	".globl syscall_addr \n\t"
	"syscall_addr: \n\t"
	"call *sysinfo \n\t" //Jump to the __kernel_vsyscall function in the vDSO to execute the syscall/sysenter instruction
	"pop %ebp \n\t"
	"ret \n\t"
	);

	/*
	 * asm_syscall_hook is the initial entry point for all hooked system calls
	 *
	 * the procedure below calls the C function
	 * named syscall_hook.
	 *
	 * at the entry point of this,
	 * the register values follow the calling convention
	 * of the system calls.
	 *
	 */
	asm volatile (
	".globl asm_syscall_hook \n\t"
	"asm_syscall_hook: \n\t"
	
	"push %ebp \n\t"
	"mov %esp, %ebp \n\t"

	/* assuming callee preserves edi、esi、ebx、edx  */

	"push %edi \n\t"
	"push %esi \n\t"
	"push %ebx \n\t"
	"push %edx \n\t"

	/* arguments for syscall_hook */

	"push 4(%ebp) \n\t"	
	"push 0(%ebp) \n\t"
	"push %edi \n\t"
	"push %esi \n\t"
	"push %edx \n\t"
	"push %ecx \n\t"
	"push %ebx \n\t"
	"push %eax \n\t"
	"call syscall_hook \n\t" 
	"add $32, %esp \n\t"
	
	"pop %edx \n\t"
	"pop %ebx \n\t"
	"pop %esi \n\t"
	"pop %edi \n\t"
	"leave \n\t"
	"ret \n\t"
	);
}

static long (*hook_fn)(int32_t a1, int32_t a2, int32_t a3,
		       int32_t a4, int32_t a5, int32_t a6,
		       int32_t a7) = enter_syscall;
static long (*hook_fn1)(int32_t a1, int32_t a2, int32_t a3,
		       int32_t a4, int32_t a5, int32_t a6,
		       int32_t a7) = enter_syscall;

long syscall_hook(int32_t eax, int32_t ebx,
		  int32_t ecx, int32_t edx, int32_t esi,
		  int32_t edi,
		  int32_t ebp,
		  int32_t retptr)
{
	if((retptr >= libc_exec_start) && (retptr < libc_end))
	{
		return hook_fn1(eax, ebx,ecx,edx,esi,edi,ebp);//Will not be hooked, will only execute the original system call
	}
	return hook_fn(eax, ebx,ecx,edx,esi,edi,ebp); //Performs the hook operation and also performs the original system call
}
static void get_range(void)
{
	FILE *fp;
	int find=0;
	/* get memory mapping information from procfs */
	assert((fp = fopen("/proc/self/maps", "r")) != NULL);
	{
		char buf[4096];
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			if (strstr(buf, "libc")) {
				char c[5];
				uint32_t from, to;				
				sscanf(buf, "%x-%x %s %*s %*s %*d %*s", &from,&to,c);
				if(from == libc_start)
				{
					find=1;
					continue;
				}
				if(find)
				{
					int mem_prot = 0;
					{
						size_t j;
						for (j = 0; j < strlen(c); j++) {
							if (c[j] == 'r')
								mem_prot |= PROT_READ;
							if (c[j] == 'w')
								mem_prot |= PROT_WRITE;
							if (c[j] == 'x')
								mem_prot |= PROT_EXEC;
						}
					}
					if (mem_prot & PROT_EXEC) {
						libc_exec_start=from;
						libc_end=to;
						find=0;
								
					}
				}			
			}
		}
	}
}

static void init(void)
{
	unsigned long gs_10;
	
	asm volatile(
    "mov %%gs:0x10, %%eax\n\t"  
	"mov %%eax,%0\n\t"        
    : "+m" (gs_10)
    :
    : "%eax");//Get the content of gs:0x10
	sysinfo=gs_10; 
	after_gs_24=(unsigned long)asm_syscall_hook;
	asm volatile(
	"mov %%eax,%%gs:0x24\n\t"
        : 
        : "a"(after_gs_24): );// Copy the address of asm_syscall_hook to gs:0x24
}

static void load_hook_lib(void)
{
	void *handle;
	struct link_map * libcmap=NULL;
	{
		const char *filename;
		filename = getenv("LIBZPHOOK");
		if (!filename) {
			fprintf(stderr, "env LIBZPHOOK is empty, so skip to load a hook library\n");
			return;
		}

		handle = dlmopen(LM_ID_NEWLM, filename, RTLD_NOW | RTLD_LOCAL); //Load the library into a new namespace
		if (!handle) {
			fprintf(stderr, "dlmopen failed: %s\n\n", dlerror());
			fprintf(stderr, "NOTE: this may occur when the compilation of your hook function library misses some specifications in LDFLAGS. or if you are using a C++ compiler, dlmopen may fail to find a symbol, and adding 'extern \"C\"' to the definition may resolve the issue.\n");
			exit(1);
		}
		
		if (dlinfo(handle, RTLD_DI_LINKMAP , &libcmap) == -1) { // Get the link_map corresponding to the new namespace
               		fprintf(stderr, "RTLD_DI_LMID  failed: %s\n", dlerror());
               		exit(EXIT_FAILURE);
           	}
	}
	while(libcmap->l_next)
	{
		libcmap=libcmap->l_next;
		if(strstr(libcmap->l_name,"libc.so.6"))
		{
			libc_start=libcmap->l_addr;// Get the starting address of libc in the new namespace
			break;
		}
		
	}
	get_range(); // Get the start and end addresses of the executable area of ​​libc in the new namespace
	{
		int (*hook_init)(long, ...);
		hook_init = dlsym(handle, "__hook_init");
		assert(hook_init);
		assert(hook_init(0, &hook_fn) == 0);//Calling initialization functions in other libraries.
	}
}

__attribute__((constructor(0xffff))) static void __datahook_init(void)
{
	init(); //Perform some initialization
	load_hook_lib(); // Load the library that implements the hook operations into a new namespace
}