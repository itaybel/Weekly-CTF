Ror was the fourth and last challenge in the REV section of the CTF.
we are given a single file, named `food`:
```
itay@itay-Latitude-3520:~/Desktop/CSAW/rev/ror$ file food 
food: ELF 64-bit LSB executable, x86-64, version 1 (FreeBSD), dynamically linked, interpreter /libexec/ld-elf.so.1, for FreeBSD 13.1, FreeBSD-style, with debug_info, not stripped
```
its a 64bit elf, built for the FreeBSD operating system.
Since we can't easily run it, I have right away started static analysis with IDA:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/a32ab7bf-2988-4213-9abe-fdcd115f9db2)

We can understand that the program was built with CPP.
It takes our input from `argv[1]`, and calls verify with it.
lets try to understand how verify works:

```c
int verify(char* inp){
  char v28[74]; // [rsp+50h] [rbp-90h] BYREF
  -- REDACTED--
  
  qmemcpy(v28, "?B8_zWqtfDG2=\x16c", 15);
  v28[15] = 31;
  v28[16] = 18;
  v28[17] = 26;
  v28[18] = 18;
  v28[19] = 92;
  v28[20] = 42;
  v28[21] = 3;
  v28[22] = 100;
  v28[23] = 28;
  v28[24] = 21;
  v28[25] = 64;
  v28[26] = 1;
  v28[27] = 63;
  v28[28] = 76;
  v28[29] = 2;
  v28[30] = 58;
  v28[31] = 48;
  v28[32] = 29;
  v28[33] = 124;
  v28[34] = 105;
  v28[35] = 77;
  v28[36] = 25;
  v28[37] = 95;
  v28[38] = 72;
  v28[39] = 94;
  v28[40] = 32;
  v28[41] = 3;
  v28[42] = 23;
  v28[43] = 9;
  v28[44] = 82;
  v28[45] = 107;
  v28[46] = 76;
  v28[47] = 101;
  v28[48] = 111;
  v28[49] = 72;
  v28[50] = 6;
  v28[51] = 91;
  v28[52] = 43;
  v28[53] = 40;
  v28[54] = 64;
  v28[55] = 46;
  v28[56] = 78;
  v28[57] = 11;
  v28[58] = 22;
  v28[59] = 49;
  v28[60] = 48;
  v28[61] = 86;
  v28[62] = 33;
  v28[63] = 110;
  v28[64] = 45;
  v28[65] = 48;
  v28[66] = 75;
  v28[67] = 28;
  v28[68] = 16;
  v28[69] = 4;
  v28[70] = 63;
  v28[71] = 24;
  qmemcpy(&v28[72], "A4", 2);
```
So it will write tons of hardcoded values to an array in the stack, called `v28`.
After that, this code will be executed:
```c
 std::vector<unsigned char>::vector(xorresult, v28, 74LL, &v29);
  for ( i = 0; ; ++i )
  {
    if ( i >= std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(inp) )
      break;
    curr = *(_BYTE *)std::vector<unsigned char>::operator[](xorresult, i);
    v3 = curr ^ *(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                            inp,
                            i);
    *(_BYTE *)std::vector<unsigned char>::operator[](xorresult, i) = v3;
  }
```

It will create a `cpp vector` of size 74, from our hardcoded `v28` buffer. then it will take every character of our input, and xor is with its corrosponding character in the vector.
Lets implement this behaviour in python:
```py
v28 = [ord(i) for i in "?B8_zWqtfDG2=\x16c"]
v28 += (75 - len(v28)) * [0]
v28[15] = 31;
v28[16] = 18;
v28[17] = 26;
v28[18] = 18;
v28[19] = 92;
v28[20] = 42;
v28[21] = 3;
v28[22] = 100;
v28[23] = 28;
v28[24] = 21;
v28[25] = 64;
v28[26] = 1;
v28[27] = 63;
v28[28] = 76;
v28[29] = 2;
v28[30] = 58;
v28[31] = 48;
v28[32] = 29;
v28[33] = 124;
v28[34] = 105;
v28[35] = 77;
v28[36] = 25;
v28[37] = 95;
v28[38] = 72;
v28[39] = 94;
v28[40] = 32;
v28[41] = 3;
v28[42] = 23;
v28[43] = 9;
v28[44] = 82;
v28[45] = 107;
v28[46] = 76;
v28[47] = 101;
v28[48] = 111;
v28[49] = 72;
v28[50] = 6;
v28[51] = 91;
v28[52] = 43;
v28[53] = 40;
v28[54] = 64;
v28[55] = 46;
v28[56] = 78;
v28[57] = 11;
v28[58] = 22;
v28[59] = 49;
v28[60] = 48;
v28[61] = 86;
v28[62] = 33;
v28[63] = 110;
v28[64] = 45;
v28[65] = 48;
v28[66] = 75;
v28[67] = 28;
v28[68] = 16;
v28[69] = 4;
v28[70] = 63;
v28[71] = 24;
v28[72] = ord('A')
v28[73] = ord("4")

inp = input()
xorresult = v28
xorresult = [xorresult[i] ^ inp[i] for i in range(len(inp))]
```

Now lets move to the next part of the program:

```c
for ( j = 0; ; ++j )
  {
    if ( j >= std::vector<unsigned char>::size(xorresult) )
      break;
    inp_curr = *(unsigned __int8 *)std::vector<unsigned char>::operator[](xorresult, j);
    idx = 10 * j + 12;
    data_size = std::vector<int>::size(&data);
    data_curr = *(_DWORD *)std::vector<int>::operator[](&data, idx % data_size);
    inp_size = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(inp);
    new_val = data_curr
            + *(char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                         inp,
                         j % inp_size);
    v12 = std::vector<int>::size(&data);
    LODWORD(new_val) = inp_curr ^ *(_DWORD *)std::vector<int>::operator[](&data, new_val % v12);
    v1 = (char *)j;
    *(_BYTE *)std::vector<unsigned char>::operator[](xorresult, j) = new_val;
  }
```

It will go through each index `j` from 0 to the size of`xorresult`, and do the following:
  1. take `data[(10 * j + 12) % len(data)]` and add it to `inp[j % len(inp)j`
  2. xor the result with the result with the current character in `xorresult`
  3. store the result in `xorresult`


In order to replicate it in python. we need the big `data` array.
I used GDB (didn't ran anything) , and just read all the memory of data, and put it in a file called `vector`:

```
$ head vector 
0x403740:	0x0000003c	0x00000064	0x00000058	0x00000029
0x403750:	0x0000005a	0x00000062	0x0000002e	0x00000047
0x403760:	0x00000057	0x00000032	0x0000001b	0x0000001c
0x403770:	0x0000004a	0x00000015	0x0000005e	0x00000070
0x403780:	0x0000007c	0x00000075	0x00000068	0x00000030
0x403790:	0x00000002	0x0000007e	0x00000074	0x00000066
0x4037a0:	0x0000001d	0x0000001a	0x0000003f	0x00000026
0x4037b0:	0x00000019	0x0000007a	0x00000013	0x00000055
0x4037c0:	0x0000004e	0x00000051	0x0000004c	0x00000060
0x4037d0:	0x00000012	0x00000069	0x00000054	0x00000005
...
...
```
then I extraced all the values with my script:

```py
data = []
for i in open("vector", 'r').readlines():
    
    a = [int(j, 16) for j in i.split(':\t')[1][:-1].split('\t')]
    for j in a:
        data.append(j)

```
(ugly af, I know :) )


Now, we are ready to write the second step of the program purely in python:
```py
inp = input()
xorresult = v28
xorresult = [xorresult[i] ^ inp[i] for i in range(len(inp))]
for j in range(len(inp)):
            num1 = data[(10 * j + 12) % len(data)]
            out1 = num1 + inp[j % len(inp)]
            out2 = data[out1 % len(data)]
            xorresult[j] ^= out2


```

Here is the third step code:
```c
 for ( k = 5; ; ++k )
  {
    if ( k >= std::vector<unsigned char>::size(xorresult) )
      break;
    for ( m = 0; m <= 299; ++m )
    {
      curr = (_BYTE *)std::vector<unsigned char>::operator[](xorresult, k);
      calc = (32 * m) ^ *curr;
      result = calc ^ (*(_BYTE *)std::vector<unsigned char>::operator[](xorresult, k - 5) == 'n');
      *(_BYTE *)std::vector<unsigned char>::operator[](xorresult, k) = result;
    }
  }
```

It will go thourgh number netween `5` and and `sizeof(xorresult)`, take each character and it will enter a for loop:
  1. take the current character , `xorresult[k]`, and xor it with `32m`, when `m` is the running index of the for loop.
  2. if `xorresult[k-5]` is "n", it will xor the result of #1 with 1
  3. save the result to `xorresult`

pretty simple behaviour, and its easy to write in python:
```py
inp = input()
xorresult = v28
xorresult = [xorresult[i] ^ inp[i] for i in range(len(inp))]
for j in range(len(inp)):
            num1 = data[(10 * j + 12) % len(data)]
            out1 = num1 + inp[j % len(inp)]
            out2 = data[out1 % len(data)]
            xorresult[j] ^= out2

        for k in range(5, len(xorresult)):
            for m in range(300):
                a = xorresult[k]
                b = (32*m) ^ a
                c = b ^ (xorresult[k - 5] == "n")
                xorresult[k] = c
                break
```

Lastly , here is the final step:

```py
 std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string<std::allocator<char>>(
    v26,
    "flag{ph3w...u finaLly g0t it! jump into cell wHen U g3t t0 the next cha11}",
    &v30);
  std::allocator<char>::~allocator(&v30);
  v19 = time(0LL);
  srand(v19);
  for ( n = 0; ; ++n )
  {
    v22 = n;
    if ( v22 >= std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(v26) )
      break;
    curr_c = *(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](v26, n);
    if ( curr_c != *(_BYTE *)std::vector<unsigned char>::operator[](xorresult, n) )
    {
      v31 = rand();
      v21 = std::operator<<<std::char_traits<char>>(
              &std::cout,
              ((__int64)(v31 % 6) << 7) + 4232480,
              (unsigned int)(v31 % 6));
      std::ostream::operator<<(v21, &std::endl<char,std::char_traits<char>>);
      goto LABEL_19;
    }
```
It will basiclly just compare each byte of `xorrandom`, with the string `"flag{ph3w...u finaLly g0t it! jump into cell wHen U g3t t0 the next cha11}"`, and if everything is correct,
it means that our input is the flag!. but, how can we reverse all of these steps to retrieve the flag?
We don't really need to do it! since all the manipluation on our input was byte-byte with predefined data, we can just bruteforce the input byte-byte, and if `xorresult` of our input is `target`, we know that the new character is correct
Lets take eveything we wrote in python, and write a bruteforce bytebyte script.
Final script:

```py
data = []
for i in open("vector", 'r').readlines():
    
    a = [int(j, 16) for j in i.split(':\t')[1][:-1].split('\t')]
    for j in a:
        data.append(j)


target = "flag{ph3w...u finaLly g0t it! jump into cell wHen U g3t t0 the next cha11}"
v28 = [ord(i) for i in "?B8_zWqtfDG2=\x16c"]
v28 += (75 - len(v28)) * [0]
v28[15] = 31;
v28[16] = 18;
v28[17] = 26;
v28[18] = 18;
v28[19] = 92;
v28[20] = 42;
v28[21] = 3;
v28[22] = 100;
v28[23] = 28;
v28[24] = 21;
v28[25] = 64;
v28[26] = 1;
v28[27] = 63;
v28[28] = 76;
v28[29] = 2;
v28[30] = 58;
v28[31] = 48;
v28[32] = 29;
v28[33] = 124;
v28[34] = 105;
v28[35] = 77;
v28[36] = 25;
v28[37] = 95;
v28[38] = 72;
v28[39] = 94;
v28[40] = 32;
v28[41] = 3;
v28[42] = 23;
v28[43] = 9;
v28[44] = 82;
v28[45] = 107;
v28[46] = 76;
v28[47] = 101;
v28[48] = 111;
v28[49] = 72;
v28[50] = 6;
v28[51] = 91;
v28[52] = 43;
v28[53] = 40;
v28[54] = 64;
v28[55] = 46;
v28[56] = 78;
v28[57] = 11;
v28[58] = 22;
v28[59] = 49;
v28[60] = 48;
v28[61] = 86;
v28[62] = 33;
v28[63] = 110;
v28[64] = 45;
v28[65] = 48;
v28[66] = 75;
v28[67] = 28;
v28[68] = 16;
v28[69] = 4;
v28[70] = 63;
v28[71] = 24;
v28[72] = ord('A')
v28[73] = ord("4")

msg = []
sols = []
chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}"


for t in range(74):
    sols = []
    for i in range(256):
        xorresult = v28

        inp = msg + [i] 
        inp += (len(xorresult) - len(inp)) * [0]

        xorresult = [xorresult[i] ^ inp[i] for i in range(len(inp))]

        for j in range(len(inp)):
            num1 = data[(10 * j + 12) % len(data)]
            out1 = num1 + inp[j % len(inp)]
            out2 = data[out1 % len(data)]

            xorresult[j] ^= out2

        for k in range(5, len(xorresult)):
            for m in range(300):
                a = xorresult[k]
                b = (32*m) ^ a
                c = b ^ (xorresult[k - 5] == "n")
                xorresult[k] = c
                break

        if xorresult[t] == ord(target[t]):

            sols.append(i)
            
    sols = [chr(i) for i in sols if chr(i) in chars]
    if len(sols) != 1:
        print("choose")
        print(", ".join(sols))
        idx = int(input("> "))
        msg += [ord(sols[idx])]
    else:
        msg += [ord(sols[0])]
    print("".join([chr(i) for i in msg]))

```

Please notice that sometimes multiple solutions will be found. I just manually choose the correct character which made sense:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/aa69f417-a7fd-499d-b00c-c78df500cfe8)

