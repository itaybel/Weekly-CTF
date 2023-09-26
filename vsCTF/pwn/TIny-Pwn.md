Tinypwn was the first pwn challenge I encountered in the CTF.
It was pretty easy and I managed to solve it very quick, and even first blooded it:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/6895a593-3d57-49d0-b26e-42689f490cdb)


It was a small 32-bit binary, just 69 bytes, and did the following:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/6008e3e6-3580-465c-a798-93f0f536cba2)

Writing 0xd bytes into the stack and jumping to it lets us execute a shellcode of size 0xd. To set up `exceve(/bin/sh)` shellcode, I ran `strings --radix=x tinypwn`. This showed that the string `/bin/sh` is located at offset 0x20, and the binary base is 0x10000, meaning `/bin/sh` is at 0x10020.
To execute `/bin/sh` via the `exceve` syscall, we need `eax=0xb` (the syscall number), `ebx=/bin/sh`, `edx=0`, and `ecx=0` as parameters. However, we can only write 0xd bytes, so we need to be creative. The instruction `mov eax, 0xb` is 5 bytes, which is too long.
We can leverage the fact that syscalls put their return value in `eax`. For example, the read syscall will return the number of bytes read. This lets us write exactly 0xb bytes, saving us the instruction `mov eax, 0xb`. We can then write `xor edx, edx` and `xor ecx, ecx` (2 bytes each), `mov ebx, 0x10020` (5 bytes), and `int 0x80` (2 bytes).
This adds up to 0xb bytes exactly what we needed and we successfully exploited this challenge.
Final code:
```py
from pwn import *
p = remote("vsc.tf" , 3026)
a = """
xor edx, edx\n
xor ecx, ecx\n
mov ebx, 0x10020\n
syscall\n
"""

p.send(asm(a))

p.interactive()
```
