# SEED Labs - Buffer Overflow Attack Lab (Set-UID Version)
## Task #1

The goal of this task is to understand how a shellcode works and how the execution of it inside another program works.

We are given a shellcode - and the corresponding binary version - that executes `/bin//sh` (which is the same as `/bin/sh`) using `execve`.

To execute this shellcode, we can compile the program `call_shellcode.c`.

1. Run `cd shellcode`
2. Run `make`
   - This will compile the file code into two different executables: `a64.out` and `a32.out`. We are interested in the 32-bit architecture.
3. Run `a32.out`
   - This will execute the shellcode and, therefore, `/bin/sh`. Inside the shell, you can execute `whoami` and confirm you are executing the shell as `seed`. You may use the shell to freely execute any command, taking advantage of the machine.
4. Run `make setuid`
   - After compilation, this will set the Set-UID bit of `a32.out` and it's owner will be changed to `root`. This means that when `a32.out` is executed, the process's user ID to that of `root`.
5. Run `a32.out`
6. Inside the shell, execute `whoami`
   - The name `root` should appear on the screen, indicating you are executing the shell as `root`. Any command you execute will be executed as `root` as well. 

