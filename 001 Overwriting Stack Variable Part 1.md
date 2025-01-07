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

1. `Stack: No canary found` is based on the command `-fno-stack-protector`, which
