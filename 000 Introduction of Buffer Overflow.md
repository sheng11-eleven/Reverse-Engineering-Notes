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
According to the code, a character array variable called *"buffer"* that had 16 bytes of storage was defined.
Not only that, the program is using `gets()` function, which is a vunerable function in **C programming language**.

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
Command Explaination:
1. `gcc` = Invoke **GNU C/C++ compiler**.
2. `vuln.c` = **Source file** to compile.
3. `-o vuln` = Specify the name of **output file**.
4. `-fno-stack-protector` = Option to **disable stack protection mechanisms**, which is used for *stack buffer overflows prevention*.
5. `-z execstack` = Option to marks the stack as **executable**.
6. `-no-pie` = Option to produce a **non-Position Independent Executable (non-PIE)** in a compiler. PIE are designed to *load program at random memory addressess* to make attackers harder to predict the location of payload execution.
7. `-m32` = Option to instructs compiler to generate a **32-bit executable binary file**.

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
Output Explaination:
* `Arch:i386-32-little` = The **Intel 32-bit architecture binary**, *little* refers to the endianness.
* `RELRO:Partial RELRO` = RELocation Read-Only makes **certain sections of memory read-only after initialized**. *Partial RELRO* means some sections of the binary are protected.
* `Stack:No canary found` = The binary does not use **stack canaries**, which are security mechanisms designed to *detect stack buffer overflows*.
* `NX:NX unknown - GNU_STACK missing` = **No eXecute (NX)** marks certain areas of memory as **non-executable**, *unknown* due to `GNU_STACK` section is missing.
* `PIE:No PIE (0x8048000)` = Position Independent Executable (PIE) allows executables to loaded at **random memory addresses**, *No PIE* means the binary is not position-independent, *0x8048000* is **fixed base address** that refers to a specific memory address at which a binary is loaded into memory when it is executed.
* `Stack:Executable` = Stack is marked as **executable**, means attackers can execute code that is placed on the stack, this is a *requirement for exploiting buffer overflow vulnerabilities*.
* `RWX:Has RWX segments` = The segments memory of binary are both **readable, writable, and executable (RWX)**.
* `Stripped:No` = The binary is **not stripped**, means it *contains symbol information* (such as function names and variable names). 

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
Output Explaination:
* `vuln` = **Name** of analyzed file.
* `ELF 32-bit LSB executable`:
    * `ELF` = **Executable and Linkable Format**, common standard file format for executables, object code, shared libraries, and core dumps in Unix-like operating system.
    * `32-bit` = The executable is compiled for a **32-bit architecture**.
    * `LSB` = **Least Significant Byte first**, indicates the *endianness of the binary*. LSB means the least significant byte is stored first in memory, typical for **Intel architectures**.
* `Intel 80386` = Specify the **target architecture** for the binary was compiled. The Intel 80386 is a **32-bit microprocessor**, and indicates the binary is intended to run on **x86 architecture**.
* `version 1 (SYSV)` = Indicates the **version of ELF** specification. SYSV refers to **System V ABI (Application Binary Interface)**, a standard for binary compatibility.
* `dynamically linked` = The binary file is **linked to shared libraries** at *runtime* rather than being statically linked. This allows the program to use shared code from libraries, which can *save memory and disk space*.
* `interpreter /lib/ld-linux.so.2` = Specify the **dynamic linker/loader** that will be used to *load the binary file into memory* and **link with the necessary shared libraries**. The `/lib/ld-linux.so.2` is the library for 32-bit binaries on Linux.
* `BuildID[sha1]=2ada1af7d9dcfe5a160f4b68c26d1b90bd0c427b` = A **unique identifier** for the build of binary file, represented as **SHA-1 hash**.
* `for GNU/Linux 3.2.0` = Indicates the binary file is intended to **run on the GNU/Linux operating system**, *version 3.2.0 or later*.
* `not stripped` = The binary file contains **all of the symbol information**, includes function names, variable names, and debugging information. A **stripped** binary will *remove these information for reducing the size* and make *reverse engineering more difficult*.

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

