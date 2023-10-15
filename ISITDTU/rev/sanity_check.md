The challenge consisted of another go binary, but luckily now its an ELF. it nicecly asked for the flag, and it will check if its correct.
After putting the binary in IDA, we can see this while loop checking our input:

```c
  while ( i < 0x23 )
  {
    index = i;
    v35 = v4;
    v40 = v5;
    v6 = fibbon();
    if ( v34 <= index )
      runtime_panicIndex();
    if ( !*(_QWORD *)(v39 + 16 * index + 8) )
      runtime_panicIndex();
    if ( v6 == (v37[index] ^ **(unsigned __int8 **)(v39 + 16 * index)) ) (1)
    {
      main_calc();
      v33 = runtime_intstring(v15, v23);
      v7 = v40;
      v34 = runtime_concatstring2(v16, v24, v29, v32, v33);
    }
    else
    {
      v46 = v1;
      runtime_convT64(v15);
      *(_QWORD *)&v46 = &unk_489860;
      *((_QWORD *)&v46 + 1) = v9;
      fmt_Fprintln(v17, v23, v29);
      v44 = &unk_489EA0;
      v45 = &WRONG;
      fmt_Fprintln(v18, v25, v30);
      v32 = os_Exit(v19);
      v7 = v35;
      v8 = v40;
    }
    i = index + 1;
    v4 = v7;
    v5 = v8;
  }
```
Firstly, lets look at the `fibbon` number, because its output gets compared with the xor:

```c
__int64 __usercall fibbon@<rax>(int index)
{
  __int64 result; // rax
  __int64 v2; // r14
  char *v3; // [rsp-8h] [rbp-18h]
  char *v4; // [rsp-8h] [rbp-18h]
  __int64 v5; // [rsp+0h] [rbp-10h]
  void *retaddr; // [rsp+10h] [rbp+0h] BYREF

  if ( (unsigned __int64)&retaddr <= *(_QWORD *)(v2 + 16) )
    runtime_morestack_noctxt_abi0();
  if ( result > 1 )
  {
    v5 = fibbon(v3);
    return v5 + fibbon(v4);
  }
  return result;
}
```
It gets called with the current index, just like that:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/84ee9236-8a29-4995-a256-e0491dbfaffa)

We can see that it basically calculates the fibbonachi number with the corrosponding index.

Now let's use gdb and put a breakpoint on this compare at (1):

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/ea0d0fc5-2a83-4c84-9f16-a0f8ca0fa959)

I have just entered 0x23 a's, because thats the condition of the while loop (it accounts for 0x23 characters)

We can see that the program will xor the next character, in our case, 'a', which is 0x61, with this arbitrary 0x54 which is in the stack.
A quick check shows that there are tons of hardcoded values like 0x54 in the stack:
![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/17d9a168-1fa8-472e-895a-d274008891e0)

After the xor, it will compare it with our character in the input.

So basiclly, the program will take the i'th character of our input, xor it with the i'th fibbonachi number, and check if its equals to the corrosponding number in the hardcoded array.
After exporting all these numbers, and exporting the first 100 fibbonachi numbers, I wrote this script which finds the flag:

```py
nums = [
0x54,
0x69,
0x68,
0x71,
0x5c,
0x4c,
0x7b,
0x52,
0x42,
0x4a,
0x52,
0x2b,
0xf5,
0xb6,
0x0000000000000120	,0x000000000000020d
,0x00000000000003ae,	0x000000000000064f
,0x0000000000000a47	,0x0000000000001007
,	0x0000000000001a28,	0x0000000000002a9d
,	0x0000000000004565	,0x0000000000006f9e
,	0x000000000000b555,	0x0000000000012563
,	0x000000000001da5f	,0x000000000002ff27
,	0x000000000004d90a	,0x000000000007d8ea
,	0x00000000000cb26a,	0x0000000000148ab8
,	0x0000000000213d62	,0x000000000035c78b
,	0x0000000000570489]

flag = ""
idx = 0

fibbon = [...] #its big lol

for i in nums:
	flag += chr(fibbon[idx] ^ i)
	print(flag)
	idx += 1
print(flag)
```
