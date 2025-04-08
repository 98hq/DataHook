# DataHook: An Efficient and Lightweight System Call Hooking Technique without Instruction Modification
## Build and How to Use
To build the dynamic library, please type the following command.
```
make
```
Please specify ```libbasichook.so``` for the ```LIBZPHOOK``` environment variable and ```libdatahook.so``` for LD_PRELOAD. The example command is as follows.
```
$ LIBZPHOOK=./libbasichook.so LD_PRELOAD=./libdatahook.so [program you wish to run]
```
## Version
The code in the current directory can be adapted to run multi-threaded/single-threaded programs. The code in the "single-threaded version" directory can only be used to run single-threaded programs. 
The difference between them is that the multi-threaded version changes the way the original system call is called.
## How to implement my system call hook

Currently, ```libdatahook.so``` is independent of the hook function library. So, you can build your own hook function library, and to activate it, you only need to specify it to the ```LIBZPHOOK``` 
environment variable.

In the hook function library, you should implement ```__hook_init```.
It will have the pointer to the hook function address as the argument, and by overwriting it, the hook function library can apply an arbitrary hook function.

For details, please check ```hook.c```.

