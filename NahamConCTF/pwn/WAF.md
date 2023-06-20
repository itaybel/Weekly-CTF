This challenge is a heap challenge.
The binary is pretty big, so I will not provide the code.
The binary consists of 5 options:
```
Web Application Firewall Configuration.

1. Add new configuration.
2. Edit configuration.
3. Print configuration.
4. Remove last added configuration.
5. Print all configurations.
6. Exit

```

The add option will create a new configuration, which simply mallocs a configuration struct of size 0x18.
Then it asks the user for `id`, `size`, and a `setting` of size `size`, which it mallocs.
It doesn't initilize any mallocs.

the second option is an edit option, it prompts for `id`, and aloows the user to realloc and change the size+setting of the configuration.
There is an UAF bug here, since it doesn't checks if the struct is free

third option just prints info about a given config. the add option doesn't initilize chunks, so we can leak some heap/libc addresses.

fourth option basiclly just frees a configuration , and its setting. doesn't do any checks (besides idx limits), so a double free is possible.

My idea was pretty simple. I just started leaking data, and moved on from there.
leaking heap is pretty simple, we can just allocate any chunk , free it, and use the print option to print its data.
tcachebins contains `heap fd` in their chunk meta data, so its an easy leak.
```py
	add(1, 1, '1')
	remove()
	heap = print_conf(0)[0] - 0x280
```

Then, in order to leak libc, I used the same approach.
unsortedbins contains libc addresses in their chunk metadata, so we need to add one.
Tcache bins are limited to only 7 chunks, so we can free 7 chunks, then allocate a big chunk (we don't want it to be treated as fastbin), and it will be added to the unsorted bin.

```py
	for i in range(8): #fill tcache, to add a chunk to unsorted bins
		add(1, 0x100, 'a'*8)
	for i in range(8):
		remove()
	libc.address = u64(print_conf(idx)[1].ljust(8, b'\x00')) - 0x3ebca0
  ```
  now we have all the leaks we need. we'll be trying to get an arbitrary write primitive using our uafs.
  First of all , lets empty out all the bins to make everything nicer.
  
  ```py
  #empty out tcache
	add(1, 0x81, 'b'*10)
	for i in range(7):
		add(1, 0x100, 'a'*8) #this will sort one chunk to the smallbin

	add(1, 0x50, 'w' * 0x50)  #we get that smal bin chunk
  ```
  
  Now we will start to understand how we get arb-write primitive.
  first of all, lets trick libc, by allocating a chunk, freeing it into the tcache, and change its fd using the edit command.
  We will change `fd` to a chunk we control. libc will think that there is a free chunk there. then we can fully control its fd, and put it whereever we want to write to.

  ```py
  #trigger write after free, and trick libc to think there is a free list in heap+0xc00
	write_chunk = add(1, 0x50, 'k' * 0x50) 
	remove()
  ```
  this will make our bins look like this:
  ![image](https://github.com/Itay212121/Weekly-CTF/assets/56035342/8cb07ebe-70b5-4a45-ae2f-a4a39e90c923)

  then, we'll use the edit, to trick malloc and add our fake fd:
  ```py
  edit(write_chunk, heap + 0xc00, 16, 'b' * 16)
  ```
  
  this will make the bins like this:
 
  ![image](https://github.com/Itay212121/Weekly-CTF/assets/56035342/bd5a69be-12a6-452a-93f4-092f063ba8b4)
  
  as you can see, the address `0x1edbc00`, is linked to 2 different bins!

  now, we can use the add option, with size=0x18. this will first malloc a struct, and take the first chunk at 0x1edbbe0. 
  then it will do `malloc(0x18)`, which will return `0x1edbc00`, and will let us control it! remember that `0x1edbc00` is still in the 0x60 tcache bin.
  Now we can basiclly write our fake bk, which will be the address we want to write to. in our case we triggered the `__free_hook`:
  
  ```py
  add(1, 0x18, p64(libc.sym.__free_hook)) 
  ```
  now the bins will look like this:
  ![image](https://github.com/Itay212121/Weekly-CTF/assets/56035342/44787cfc-72fe-497c-94b9-31eb43e92e2a)
  
  now we can just add anything we want of size 0x58, which will delete the head of the tcache bin, and will make it contains just our arbitrary address.
  And then , we can malloc, and get a chunk at this arbitrary address. tcache is pretty shit when it comes to security (it is created to make everything faster, which makes it lack security)
  so malloc doesn't even check if there is a valid chunk at this address, and just give us our arbitrary chunk. then we just write one_gadget address there and win.

  ```py
  
  add(1, 0x18, p64(libc.sym.__free_hook)) #fake_chunk->fd->libc.sym.__free_hook
	add(1, 0x58, 'AAAAAAAA') #remove fake_chunk from tcache
	add(1, 0x58,p64(libc.address + 0x4f432)) #get fake_chunk->fd, which is libc.sym.__free_hook
  ```
  
  then we can just free something, and it will call the `__free_hook`, which is our one_gadget.
  what a fun challenge!
  
  
  
  
  
