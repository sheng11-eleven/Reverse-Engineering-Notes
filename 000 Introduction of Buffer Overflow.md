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

## Analysis
### PwnGDB Analysis
```bash
$ gdb vuln
```

#### Output
```text
GNU gdb (Ubuntu 12.1-0ubuntu1~22.04.2) 12.1
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 177 pwndbg commands and 47 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $base, $hex2ptr, $argv, $envp, $argc, $environ, $bn_sym, $bn_var, $bn_eval, $ida GDB functions (can be used with print/break)
Reading symbols from vuln...
(No debugging symbols found in vuln)
------- tip of the day (disable with set show-tips off) -------
Use GDB's dprintf command to print all calls to given function. E.g. dprintf malloc, "malloc(%p)\n", (void*)$rdi will print all malloc calls
pwndbg>
```

### Check Function
```bash
pwndbg> info functions
```

#### Output
```text
All defined functions:

Non-debugging symbols:
0x08049000  _init
0x08049040  __libc_start_main@plt
0x08049050  gets@plt
0x08049060  puts@plt
0x08049070  _start
0x080490b0  _dl_relocate_static_pie
0x080490c0  __x86.get_pc_thunk.bx
0x080490d0  deregister_tm_clones
0x08049110  register_tm_clones
0x08049150  __do_global_dtors_aux
0x08049180  frame_dummy
0x08049186  main
0x080491d4  _fini
```

### Disassembly Main Function
```bash
pwndbg> disassembly main
```

#### Output
```text
Dump of assembler code for function main:
   0x08049186 <+0>:     lea    ecx,[esp+0x4]
   0x0804918a <+4>:     and    esp,0xfffffff0
   0x0804918d <+7>:     push   DWORD PTR [ecx-0x4]
   0x08049190 <+10>:    push   ebp                                    // Save old base pointer
   0x08049191 <+11>:    mov    ebp,esp                                // Set new base pointer to stack pointer
   0x08049193 <+13>:    push   ebx                                    // Save ebx register
   0x08049194 <+14>:    push   ecx                                    // Save ecx register
   0x08049195 <+15>:    sub    esp,0x10                               // Allocate 16 bytes on the stack (buffer array variable)
   0x08049198 <+18>:    call   0x80490c0 <__x86.get_pc_thunk.bx>      // Get current Program Counter (PC)
   0x0804919d <+23>:    add    ebx,0x2e63                             // Adjust the value in ebx by adding an offset, string to be printed is stored
   0x080491a3 <+29>:    sub    esp,0xc                                // Allocate 12 bytes on the stack
   0x080491a6 <+32>:    lea    eax,[ebx-0x1ff8]                       // Lot the address of string
   0x080491ac <+38>:    push   eax                                    // Push the address of string to the stack
   0x080491ad <+39>:    call   0x8049060 <puts@plt>                   // Print the string
   0x080491b2 <+44>:    add    esp,0x10                               // Clean up the stack by adjusting the stack pointer
   0x080491b5 <+47>:    sub    esp,0xc                                // Allocates 12 bytes of space on the stack
   0x080491b8 <+50>:    lea    eax,[ebp-0x18]                         // (Load Effective Address) instruction loads the address of the local variable (or buffer) into the eax register
   0x080491bb <+53>:    push   eax                                    // Pushes the address of the buffer onto the stack.
   0x080491bc <+54>:    call   0x8049050 <gets@plt>                   // Call gets() function
   0x080491c1 <+59>:    add    esp,0x10                               // Clean up the stack pointer
   0x080491c4 <+62>:    mov    eax,0x0                                // Set 0 to eax
   0x080491c9 <+67>:    lea    esp,[ebp-0x8]                          // Adjust the stack pointer esp back to the location of the base pointer minus 8 bytes
   0x080491cc <+70>:    pop    ecx                                    // Clean up
   0x080491cd <+71>:    pop    ebx                                    // Clean up
   0x080491ce <+72>:    pop    ebp                                    // Clean up
   0x080491cf <+73>:    lea    esp,[ecx-0x4]                          // Adjusts the stack pointer esp to point to the address stored in ecx minus 4 bytes
   0x080491d2 <+76>:    ret                                           // Return from the function
End of assembler dump.
```

### Set Breakpoint at Main
```bash
pwndbg> break main
```

#### Output
```text
Breakpoint 1 at 0x8049195
```

### Run
```bash
pwndbg> run
```

#### Output
```text
Starting program: /home/s/Binary-Exploitation-Notes/000_Introduction_of_Buffer_Overflow/vuln
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x08049195 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────
 EAX  0x8049186 (main) ◂— lea ecx, [esp + 4]
 EBX  0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 ECX  0xffffccd0 ◂— 1
 EDX  0xffffccf0 —▸ 0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffcd84 —▸ 0xffffced4 ◂— '/home/s/Binary-Exploitation-Notes/000_Introduction_of_Buffer_Overflow/vuln'
 EBP  0xffffccb8 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0
 ESP  0xffffccb0 —▸ 0xffffccd0 ◂— 1
 EIP  0x8049195 (main+15) ◂— sub esp, 0x10
───────────────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────────────
 ► 0x8049195 <main+15>    sub    esp, 0x10     ESP => 0xffffcca0 (0xffffccb0 - 0x10)
   0x8049198 <main+18>    call   __x86.get_pc_thunk.bx       <__x86.get_pc_thunk.bx>

   0x804919d <main+23>    add    ebx, 0x2e63
   0x80491a3 <main+29>    sub    esp, 0xc
   0x80491a6 <main+32>    lea    eax, [ebx - 0x1ff8]
   0x80491ac <main+38>    push   eax
   0x80491ad <main+39>    call   puts@plt                    <puts@plt>

   0x80491b2 <main+44>    add    esp, 0x10
   0x80491b5 <main+47>    sub    esp, 0xc
   0x80491b8 <main+50>    lea    eax, [ebp - 0x18]
   0x80491bb <main+53>    push   eax
───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ esp 0xffffccb0 —▸ 0xffffccd0 ◂— 1
01:0004│-004 0xffffccb4 —▸ 0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
02:0008│ ebp 0xffffccb8 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0
03:000c│+004 0xffffccbc —▸ 0xf7d9f519 (__libc_start_call_main+121) ◂— add esp, 0x10
04:0010│+008 0xffffccc0 —▸ 0xffffced4 ◂— '/home/s/Binary-Exploitation-Notes/000_Introduction_of_Buffer_Overflow/vuln'
05:0014│+00c 0xffffccc4 ◂— 0x70 /* 'p' */
06:0018│+010 0xffffccc8 —▸ 0xf7ffd000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x36f2c
07:001c│+014 0xffffcccc —▸ 0xf7d9f519 (__libc_start_call_main+121) ◂— add esp, 0x10
─────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► 0 0x8049195 main+15
   1 0xf7d9f519 __libc_start_call_main+121
   2 0xf7d9f5f3 __libc_start_main+147
   3 0x804909c _start+44
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

### Line-by-line Checking
```bash
pwndbg> n
```

### Continue
```bash
pwndbg> c
```

#### Output
```text
Continuing.
Give me data plz:
AAAAAAAAAAAAAAA
[Inferior 1 (process 3638) exited normally]
```

### Delete Breakpoint
```bash
pwndbg> delete breakpoint
```

### Perform Buffer Overflow
```bash
pwndbg> run
Starting program: /home/s/Binary-Exploitation-Notes/000_Introduction_of_Buffer_Overflow/vuln
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Give me data plz:
AAAAAAAAAAAAAAAAAAAA
```

#### Output
```text
Program received signal SIGSEGV, Segmentation fault.
0x080491d2 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────
 EAX  0
 EBX  0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 ECX  0x41414141 ('AAAA')
 EDX  1
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffcd84 —▸ 0xffffced4 ◂— '/home/s/Binary-Exploitation-Notes/000_Introduction_of_Buffer_Overflow/vuln'
 EBP  0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0
 ESP  0x4141413d ('=AAA')
 EIP  0x80491d2 (main+76) ◂— ret
────────────────────────────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]─────────────────────────────────────────────────────────────────────────
 ► 0x80491d2 <main+76>    ret

   0x80491d3              add    bl, dh








─────────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────────
<Could not read memory at 0x4141413d>
───────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────────
 ► 0 0x80491d2 main+76
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

### Evaluate Stack Pointer
```bash
info stack
```

#### Output
```text
#0  0x080491d2 in main ()
Backtrace stopped: Cannot access memory at address 0x4141413d
```

### Ghidra Analysis
```bash
ghidra
```

#### Output
![image](https://github.com/user-attachments/assets/ecae2c8f-a370-4ace-87b2-280c65173c7c)
![image](https://github.com/user-attachments/assets/3905b4cd-a9d8-4655-8570-a024665591e9)
![image](https://github.com/user-attachments/assets/c291c878-1685-44d0-a51d-1af21f1cd7ba)

### Rename Variable
```bash
Press l 
```

#### Output
![image](https://github.com/user-attachments/assets/d196fc82-671c-49c7-88ce-36f0e9bbf652)

### Details of Main Function
![image](https://github.com/user-attachments/assets/2fec4848-8660-4809-8a90-19aeaf02d368)
