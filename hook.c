#include <stdio.h>
#include <syscall.h>
typedef long (*syscall_fn_t)(long, long, long, long, long, long, long);
static syscall_fn_t next_sys_call = NULL;
static long hook_function(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
		return next_sys_call(a1, a2, a3, a4, a5, a6, a7);// Execute original system calls in a unified way
}

int __hook_init(long placeholder __attribute__((unused)),
		void *sys_call_hook_ptr)
{
	next_sys_call = *((syscall_fn_t *) sys_call_hook_ptr);// The next_sys_call pointer points to the function that performs the original system call
	*((syscall_fn_t *) sys_call_hook_ptr) = hook_function;// Change the value of the pointer passed in the parameter to the address of hook_function
	asm volatile(
	"mov %%gs:0x24,%%eax\n\t"
	"mov %%eax,%%gs:0x10\n\t" //Modify the value of gs:0x10
        : 
        : :"%eax" );
	return 0;
}
