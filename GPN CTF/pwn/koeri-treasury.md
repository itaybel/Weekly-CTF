This chall had 13 solved durning the compeition.
I actually first-blooded this challenge, and the organizers created a meme:
![image](https://github.com/Itay212121/Weekly-CTF/assets/56035342/e39d1a40-8eb7-40d9-8fdb-cb44f17f0812)

This challenge is pretty close to `koeri-stocks`, the only difference is that we can't leak anything in the `koeri_choice` function
and that we can now have a option which prints the encrypted flag:
```c
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "koeri_crypt.h"

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
        }
    }
    else {
        puts("We do not have that kœri, yet");
    }
}

int main(int argc, char** argv) {
    be_a_ctf_challenge();
    int choice;
    int data[7] = {0};
    koeri_crypt_init(data);

    // encryption is costly
    char* encrypted_flag = koeri_encrypt_flag();
    while (1) {
        puts("[1] Add kœri to stock [2] Enter today's kœri consumption,\n[3] Print encrypted flag [4] Exit");
        scanf("%d", &choice);
        if (choice == 1) {
            koeri_choice(data, 1);
        } else if (choice == 2) {
            koeri_choice(data, 0);
        } else if (choice == 3) {
            puts(encrypted_flag);
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

The binary is using functions from a shared object file with this code:
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void koeri_crypt_init(int* data);
char* koeri_encrypt_flag();


char flag[] = "GPNCTF{fake_flag}";
char enc_flag[] = "GPNCTF{fake_flag}";
char otp[] = "GPNCTF{fake_flag}";

void koeri_crypt_init(int* data) {
    FILE* f = fopen("/dev/urandom", "r");
    fread(otp, 1, strlen(flag), f);
    fclose(f);
    for (int i = 0; i < 7; i++) {
        data[i] = otp[i];
    }
}

void koeri_crypt_scrub_flag() {
    for (int i = 0; i < strlen(flag); i++) {
        flag[i] = 'A';
    }
}

char* koeri_encrypt_flag() {
    for (int i = 0; i < strlen(flag); i++) {
        enc_flag[i] = flag[i] ^ otp[i];
    }
    enc_flag[strlen(flag)] = 0;
    return enc_flag;
}
```

so, there is 3 global varibles, and if we'll be able to read `flag`, we win.
In fact, in our binary main function, there is a pointer to the `enc_flag` string, which is inside the shared object memory.
So using the `koeri_choice` function, we can use our Out-Of-Bounds bug, we can reach to that pointer, and add anything to it. the `flag` variable is 32 bytes before it, so its an ez win:
![image](https://github.com/Itay212121/Weekly-CTF/assets/56035342/e9bc1f82-7252-431a-9056-5f782d77dc1d)

(In fact, I have no idea why this challenge has so little solves lol)
