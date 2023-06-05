This challenge is all about reversing rust binary.
At first, I didn't really want to do this challenge, because the binary is HUGE.
but after a short time I really found this challenge interseting and fun.

Lets run the binary:

```
itay@itay-Vortex-G25-8RD:/media/itay/Data/DanteCTF/rev$ ./safe 
Enter the code
1
Wrong.
itay@itay-Vortex-G25-8RD:/media/itay/Data/DanteCTF/rev$ ./safe 
Enter the code
a
```

We can guess that its a program which reads a number from a user and compares it to an hardcoded value.
After searching for a bit in IDA, I saw the function which does most things:

```c
 number = sub_40490(v3, v4);
  if ( (number & 1) != 0 )
  {
    LOBYTE(v14) = BYTE1(number);
    sub_8BC0("You must enter a number", 24LL, &v14, &off_51ED0, &off_51F78);
  }
  v32 = number & 0xFFFFFFFF00000000LL;
  if ( (number & 0xFFFFFFFF00000000LL) == 0x2A00000000LL )
  {
    sub_9A00(&v19, &unk_420B3, 81LL, &unk_42166, 26LL);
    v23 = (__int64 *)&v19;
```

we can guess that `number` is our input. we can see thats its comparing it with 0x2A00000000LL.
lets debug this with gdb. I put a breakpoint right before the comparasion, and entered 100(0x64) as out input.

```
──────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────────────
 RAX  0x2a00000000
 RBX  0x1
 RCX  0x6400000000
 RDX  0xa
 RDI  0x5555555acbb0 ◂— 0xa303031 /* '100\n' */
 RSI  0x3
 R8   0x0
 R9   0x0
 R10  0x55555559b3b7 ◂— 0x202020202020202
 R11  0x5555555acbb2 ◂— 0xa30 /* '0\n' */
 R12  0x0
 R13  0x7fffffffdcd0 —▸ 0x5555555aab10 ◂— 0x6e69616d /* 'main' */
 R14  0x7fffffffdc18 —▸ 0x5555555a9040 ◂— 0x0
 R15  0x555555596020 ◂— 'called `Result::unwrap()` on an `Err` valueEnter the code\nFailed to read line'
 RBP  0x7fffff7fe000
 RSP  0x7fffffffdbc0 ◂— 0x0
*RIP  0x55555555d47f ◂— cmp rcx, rax
───────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────────────────────────
   0x55555555d477    mov    qword ptr [rsp + 0xa0], rcx
 ► 0x55555555d47f    cmp    rcx, rax
   0x55555555d482    jne    0x55555555d50f                <0x55555555d50f>
    ↓
   0x55555555d50f    lea    rax, [rip + 0x48a9a]
   0x55555555d516    mov    qword ptr [rsp + 0x10], rax

```

As we can see, it compares our input << 8 with 0x2a << 8. so if we'll just enter input = 0x2a = 42, we'll pass this check!
```
itay@itay-Vortex-G25-8RD:/media/itay/Data/DanteCTF/rev$ ./safe 
Enter the code
42
This is the answer to the Ultimate Question of Life, the Universe, and Everything
```

But, thats not enough! we didn't get the flag yet.
After I tried to nc to the remote server and submit 42, I saw that a whole menu has showed up to me:

```
* COMMAND  DESCRIPTION                 
* awesome  Print awesome content       
* dir      Create a directory          
* env      Set an environment variable 
* file     Create a file               
* flag     Print the flag              
* poem     Have some poetry!           
* run      Runs the RustySafe binary   

RustySafe-shell > 
```
we can create a directory, set env variable, create flag, and run the binary we saw earlier.
since all of this funcionallity is given to us, I thought maybe the binary checks for this staff (files, dirs, env varibles).
So I started with enviroment variables. I basiclly hooked the getenv function, and saw an interesting string:

```
Breakpoint 1, __GI_getenv (name=0x7fffffffd9b0 "MY_FAV_POET") at ./stdlib/getenv.c:34
34	./stdlib/getenv.c: No such file or directory.
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────────────
*RAX  0x0
*RBX  0x7fffffffd9b0 ◂— 'MY_FAV_POET'
*RCX  0x1
*RDX  0xb
*RDI  0x7fffffffd9b0 ◂— 'MY_FAV_POET'
```
the program gets the MY_FAV_POET environment varible!
lets see that in code:

```c
  sub_1E1A0(&v19, "MY_FAV_POET", 11LL);
  if ( v19 )
  {
    if ( ptr && v20 )
      MEMORY[0xA100](ptr);
    v0 = 0;
    goto LABEL_11;
  }
  v1 = v20;
  v2 = ptr;
  if ( v22.m128i_i64[0] == 5 && !(*(_DWORD *)ptr ^ 0x544E4144 | *((unsigned __int8 *)ptr + 4) ^ 0x45) )  <----------- (1)
  {
    LOBYTE(v0) = 1;
    if ( !v20 )
      goto LABEL_11;
    goto LABEL_10;
  }
```

The IDA is having some problems here, but what we can see is enough.
After dynamiclly debuging, we can see the ptr holds the value of the MY_FAV_POET enviroment varible.
in this code we can see that it checks if the 4 bytes xord with 0x544E4144 is zero, and if the fifth byte xord with 0x45 is zero.
0x544E4144 is basiclly DANT, and 0x45 is E.
SO we figured out the first piece of the puzzle, that we need to set the enviroment varible MY_FAV_POET to be DANTE!!!
but still, thats not enough. we didn't get the flag yet.
Next thing I checked interesting code in the same function as the number check and the enviroment varible check. if we scroll down a bit we can see this:

```
for ( i = 0; ; i = v11 )
  {
    check_next_file(&v14, &v30);
    if ( !v14 )
      break;
    if ( !v17 )
    {
      v23 = v15;
      sub_8BC0(
        "called `Result::unwrap()` on an `Err` valueEnter the code\nFailed to read line",
        43LL,
        &v23,
        &off_51EF0,
        &off_51FD8);
    }
    v19 = v15;
    v20 = v16;
    ptr = v17;
    v22 = _mm_loadu_si128(&v18);
    sub_1E600(&v23, &v19);
    v7 = v24;
    v8 = (const __m128i *)sub_25F50(v24, v25);
    ```
    basiclly a for loop which does something interesting. in the check_next_file function we can see a call to readdir64. 
    after dynamiclly debugging it, I saw that this for loops basiclly loops over ALL of the files in the tmp directory. (which we can create files into!!!)
    Lets see what checks are there inside the for loop:
    ```c
    for ( i = 0; ; i = WIN_FLAG )
    {
      check_next_file(&v14, &v30);
      if ( !v14 )
        break;
      v10 = _mm_movemask_epi8(
              _mm_and_si128(
                _mm_cmpeq_epi8(_mm_cvtsi32_si128(v8[1].m128i_u8[0]), (__m128i)xmmword_42010),
                _mm_cmpeq_epi8(_mm_loadu_si128(v8), (__m128i)xmmword_42000))) == 0xFFFF;
      WIN_FLAG = 1;
      if ( !v10 )
        WIN_FLAG = i;
    }
    ```
    in order for the `for` loop to end, we need either to make v14 = 0, whick will happen when we finished all the files in tmp, or if we can make v10 = true, which does some kind of comparassion. lets see whats inside xmmword_42000:
    `xmmword_42000   xmmword 'gnp.etnaD3<I/pmt/'`
    
    wow! this looks like a reverse tmp directory!!
    after reversing it we got /tmp/I<3Dante.png, which will be our path!
    
    We basiclly finished. lets run it on the remote machine:
    
    ```
    * COMMAND  DESCRIPTION                 
* awesome  Print awesome content       
* dir      Create a directory          
* env      Set an environment variable 
* file     Create a file               
* flag     Print the flag              
* poem     Have some poetry!           
* run      Runs the RustySafe binary   

RustySafe-shell > env
Enter the name of the variable: MY_FAV_POET
Enter the value it should be set to: DANTE
RustySafe-shell > file
Enter the name of the file to be created in /tmp: I<3Dante.png
File was created
RustySafe-shell > run
Enter the code
42
This is the answer to the Ultimate Question of Life, the Universe, and Everything
DANTE{tRUST_m3_D4nT3_1s_th3_bEsT}
```

This challenge was pretty hard for me. in this writeup I talk about things like they are trivial, but as someone which does the challenge and know nothing, trust me its hard.
It was one of the least solved challs, so I glad I was able to do it!
    

