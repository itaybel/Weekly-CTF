
These two challenges were a pyjail escape challenges. they contain a python code that restircts the character we can write.

Censorship:

```py
#!/usr/local/bin/python
flag = "tmp_flag"
for _ in [flag]:
    while True:
        try:
            code = ascii(input("Give code: "))
            if "flag" in code or "e" in code or "t" in code or "\\" in code:
                raise ValueError("invalid input")
            exec(eval(code))
        except Exception as err:
            print(err)

```

Censorship Lite:

```py
#!/usr/local/bin/python
flag = 'tmp_flag'
for _ in [flag]:
    while True:
        try:
            code = ascii(input("Give code: "))

            if any([i in code for i in "\lite0123456789"]):
                raise ValueError("invalid input")
            exec(eval(code))
        except Exception as err:
            print(err)
```

the solution here was really simple. both python files print the error when an execption is caught.
I used it to my own adventage, by triggering an error which prints a variable to us.
In my solution I used the `KeyError` exception in dictioanries, and my solution was basiclly:
`{"a": "a"}[_]`
`_` will be our flag, and it'll try to reach the flag in this dictionary. this dict doesn't contian the flag, so we'll get an error like:
`KeyError: amateurCTF{..} isn't in dict`
and yeiiii ez win.
Censorship lite++ was a lot more harder, so read it aswell!
