# LOGBOOK 5

## SEED Labs - Buffer Overflow Attack Lab (Set-UID Version)

### Preparation

To prepare our systems for this lab, we followed the Environment Setup section of the guide:

1. Turn off address space randomization for the stack and the heap
   - Execute `sudo sysctl -w kernel.randomize_va_space=0`
   - This command instructs the kernel to stop randomizing the starting addresses of the stack and the heap. This is necessary for this lab because it makes the address at which our shellcode will be located more predictable.

2. Link `/bin/sh` to `/bin/zsh`
   - Execute `sudo ln -sf /bin/zsh /bin/sh`
   - This command is executed because, normally, `/bin/sh` points to `/bin/dash`. Both `dash` and `bash` contain special protections against being executed from a program with the Set-UID bit set, which is the program we will be trying to attack. `zsh`, on the other hand, doesn't have that kind of protections.

### Tasks

The guides for each of the tasks are located at:

- [Task #1](guides/logbook-5/task1.md)
- [Task #2](guides/logbook-5/task2.md)
- [Task #3](guides/logbook-5/task3.md)
