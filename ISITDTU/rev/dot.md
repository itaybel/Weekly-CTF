Dot was the second reversing challenge in the event.
It was a basic `dot.exe` binary.
When we try to run it, we get an error:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/738f4ead-779b-4958-849e-e39daec1c621)

Lets put the binary in IDA and start reversing it.
Firstly, lets locate where the check is made:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/e8d2afdd-9579-4d0c-a28f-78a2410ceab8)

Ida's decompliation is kinda bad with exe, so looking at assembly is better.

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/e78d87e8-e098-4ef3-8524-9197e2379477)

We can see that this morse code is getting compared with some string. we can guess that this string is the output of some kind of transformation that has been done on our input.
When we look for `xrefs`, we can see that the output of the `main_encodeToMorse` function is saved in this string:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/eed9b324-0b83-4edc-aa04-d4f79b85d9d8)

So we can understand that the function `main_encodeToMorse` is called (probably with the hostname), and then its output is compared with this hardcoded string: `..... ... --- .. --.. ----- --... .---- --. ----- --.. -.-- --...`.
At first I tried to use an online decoder of morse code, to check if thats that easy, but it wasn't the flag:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/84886797-1235-4b29-ad80-281e7e4c93e1)

Then I dug up the code a bit more. so this piece of code:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/f970d283-7569-4409-9fcb-d9467991b259)

Here are those global variables:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/9ce9fb5b-360c-4c4f-8ec8-a2c37c18b335)


![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/212096f6-9065-41be-94fa-130fdc92f51e)

These 2 arrays are of the same size. now, it makes sense that the `morse_codes_dic` variable is the encoded morse code of the corrosponding character in the `characters_dic` array.
With that in mind, I wrote a small python script that decodes the `..... ... --- .. --.. ----- --... .---- --. ----- --.. -.-- --...`. string:

```
morse = ["--..",".--","-..",".---",".-..","_","..---",".--.",".....","---","....","-.--","-...","-....","--.-","-..-","----.","-----","..-.","-.-",".","--","-","--...",".-.",".----","-.","...-","...--",".-","..-","....-","...","--.","..","---..","-.-."]

alpha = ['U', 'S', '2', 'H', 'J', 'L', 'Y', 'G', 'C', 'M', '9', 'W', 'A', 'I', 'F', 'V', '4', 'T', '8', '5', '1', 'E', 'N', '3', 'Z', 'R', ' ', 'Q', 'X', '7', 'K', 'O', '0', 'D', 'P', '6', 'B']


out = '..... ... --- .. --.. ----- --... .---- --. ----- --.. -.-- --...'.split(' ')

for i in out:
	a = alpha[morse.index(i)]
	print(a, end="")
print()
```

This code printed `C0MPUT3RDTUW3` which indeed looks like the beginning of the flag.
I got back to IDA and saw that IDA was tricking us, and the string doesn't end there:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/ce01f2d0-2e8f-4f29-ac5a-25612395ede4)

After adding these last characters we get the flag:

```py

morse = ["--..",".--","-..",".---",".-..","_","..---",".--.",".....","---","....","-.--","-...","-....","--.-","-..-","----.","-----","..-.","-.-",".","--","-","--...",".-.",".----","-.","...-","...--",".-","..-","....-","...","--.","..","---..","-.-."]

alpha = ['U', 'S', '2', 'H', 'J', 'L', 'Y', 'G', 'C', 'M', '9', 'W', 'A', 'I', 'F', 'V', '4', 'T', '8', '5', '1', 'E', 'N', '3', 'Z', 'R', ' ', 'Q', 'X', '7', 'K', 'O', '0', 'D', 'P', '6', 'B']


out = "..... ... --- .. --.. ----- --... .---- --. ----- --.. -.-- --... _ ..... ... --- --...".split(" ")

for i in out:
	a = alpha[morse.index(i)]
	print(a, end="")
print()

#C0MPUT3RDTUW3LC0M3
```
