# Introduction of Buffer Overflow

---
## Simple Buffer Overflow Vulnerable Code
```c
// vuln.c
#include <stdio.h>
#include <string.h>

int main(void)
{
    char buffer[16];

    printf("Give me data: \n");
    gets(buffer);
    
    return 0;
}
```

---
## Explaination of Code
According to the code, a character array variable called "buffer" that had 16 bytes of storage was defined.
Not only that, the program is using `gets()` function, which is a vunerable function in C programming language.

Here is the description in manual of `man` command.
```bash
$ man gets
```

### Output
```text
BUGS
       Never use gets().  Because it is impossible to tell without knowing the data in advance how many characters gets() will read, and because
       gets()  will  continue  to store characters past the end of the buffer, it is extremely dangerous to use.  It has been used to break com‐
       puter security.  Use fgets() instead.

       For more information, see CWE-242 (aka "Use of Inherently Dangerous Function") at http://cwe.mitre.org/data/definitions/242.html
```

---
## Experiment

### Compilation
```bash
$ gcc vuln.c -o vuln -fno-stack-protector -z execstack -no-pie -m32
```

#### Output
```text
vuln.c: In function ‘main’:
vuln.c:9:5: warning: implicit declaration of function ‘gets’; did you mean ‘fgets’? [-Wimplicit-function-declaration]
    9 |     gets(buffer);
      |     ^~~~
      |     fgets
/usr/bin/ld: /tmp/cc177Qua.o: in function `main':
vuln.c:(.text+0x37): warning: the `gets' function is dangerous and should not be used.
```

### Checksum
```bash
$ checksec vuln
```

#### Output
```text
[*] '/home/s/Binary-Exploitation-Notes/000_Introduction_of_Buffer_Overflow/vuln'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

### Check File Type
```bash
$ file vuln
```

#### Output
```text
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=2ada1af7d9dcfe5a160f4b68c26d1b90bd0c427b,
for GNU/Linux 3.2.0, not stripped
```

### Gain Privilege
```bash
$ sudo chmod +x vuln
$ ls -l
```

#### Output
```text
-rwxr-xr-x 1 s s 14832 Dec 28 16:35 vuln
```

### Execute
```bash
$ ./vuln
```

#### Output
```text
Give me data:
aaaa
```

### Perform Buffer Overflow
```bash
$ ./vuln
Give me data:
AAAAAAAAAAAAAAAA
```

#### Output
```bash
Segmentation fault
```

