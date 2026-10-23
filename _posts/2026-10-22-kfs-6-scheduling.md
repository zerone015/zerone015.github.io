---
title: "[KFS] 6. Scheduling"
date: 2026-10-22 02:00:00 +0900
categories: [Projects, KFS]
tags: [kernel, x86, kfs, 42seoul]
math: true
---

## Round Robin

스케줄러는 라운드 로빈으로 구현되었다. 시분할을 위해 PIT를 사용하며, 주기는 1ms다.

모든 태스크의 `struct task_struct`에는 `time_slice_remaining` 멤버가 있고, 이 값은 태스크가 fork될 때와 스케줄될 때 10으로 설정된다. 이후 PIT 인터럽트가 발생할 때마다 핸들러에서 이 값을 1씩 줄이고, 다 쓰면 스케줄러가 다음 태스크로 전환한다. 즉 타임 슬라이스는 10ms다.

Ready 상태의 태스크들은 하나의 원형 연결 리스트에서 대기한다. 태스크를 전환할 때는 현재 태스크의 next 링크에 걸린 태스크를 다음 태스크로 가져온다. 이렇게 원형 연결 리스트를 한 방향으로 돌기 때문에 큐처럼 동작한다.

![원형 연결 리스트로 된 스케줄링 큐](/assets/img/kfs/kfs-ready-queue.png)
_Ready queue_

![current가 리스트 중간에 있을 때의 삽입](/assets/img/kfs/kfs-ready-queue-2.png)
_Enqueue when current is in the middle_

PIT 핸들러 코드: [src/kernel/isr.c](https://github.com/zerone015/kfs/blob/master/src/kernel/isr.c#L145)

스케줄러 코드: [include/sched.h](https://github.com/zerone015/kfs/blob/master/include/sched.h#L28)

## Scheduling Paths

스케줄링이 일어나는 경로는 두 가지다.

- **타임 슬라이스 소진:** PIT 핸들러에서 타임 슬라이스를 다 쓴 태스크를 전환한다.
- **자발적 양보:** 태스크가 블로킹되는 시스템 콜에서 스스로 CPU를 내려놓는다.

예를 들어 한 태스크가 `waitpid`를 호출했는데 대상 자식이 아직 종료되지 않았다면, 태스크는 블로킹된다. 이때 커널은 `sys_waitpid` 안에서 `yield`를 호출해 태스크를 스케줄링 큐에서 빼고 다음 태스크로 전환한다. 이후 자식이 종료되면 블로킹됐던 태스크는 스케줄링 큐의 맨 뒤로 다시 들어가 차례를 기다린다.

## Timer Period

타이머 주기에는 트레이드오프가 있다. 타임 슬라이스가 10ms인데 PIT 주기를 10ms가 아니라 1ms로 설정한 이유는 자발적 양보 때문이다.

PIT는 스케줄러의 상태를 모르고, 정해진 주기마다 인터럽트를 발생시킬 뿐이다. 주기가 10ms라고 해 보자. 한 태스크가 다음 PIT 인터럽트를 1ms 앞두고 자발적으로 양보하면, 새로 스케줄된 태스크는 1ms 만에 PIT 인터럽트를 받고 전환된다. 결국 주기를 10ms로 정하면 타임 슬라이스에 10ms 가까운 오차가 생길 수 있다. 반면 주기를 1ms로 하면 인터럽트가 10배 많이 발생해서 CPU 시간을 더 쓰지만, 오차를 1ms 미만으로 줄일 수 있다.

## Context Switch

PIT 경로를 기준으로, 태스크 전환은 다음 순서로 일어난다.

1. 유저 모드에서 PIT 인터럽트가 발생하면, CPU가 SS, ESP, EFLAGS, CS, EIP를 커널 스택에 넣는다.
2. 진입 코드가 caller-saved 레지스터인 `eax`, `ecx`, `edx`를 넣는다.
3. C 핸들러에서 타임 슬라이스를 다 썼으면 `switch_to`를 호출한다.
4. `switch_to`는 callee-saved 레지스터인 `ebx`, `esi`, `edi`, `ebp`를 넣는다.
5. 현재 커널 스택 주소를 `task_struct`에 저장하고, `current`를 다음 태스크로 바꾼다.
6. 다음 태스크의 커널 스택으로 ESP를 바꾸고, TSS의 `esp0`도 다음 태스크의 커널 스택 주소로 바꾼다. 주소 공간이 다르면 CR3도 바꾼다.
7. 다음 태스크의 스택에서, 그 태스크가 전환될 때 저장해 둔 callee-saved 레지스터를 꺼내고 `ret`한다.
8. 다음 태스크의 C 함수들이 차례로 반환되고, 진입 코드가 caller-saved 레지스터를 꺼낸 뒤 `iret`으로 유저 모드에 돌아간다.

![태스크 전환 시 두 커널 스택](/assets/img/kfs/kfs-context-switch.png)
_Kernel stacks during a context switch_

`switch_to`는 [OSDev Wiki의 Brendan's Multi-tasking Tutorial](https://wiki.osdev.org/Brendan%27s_Multi-tasking_Tutorial)을 참고했다. 처음에는 `task_struct` 안에 모든 범용 레지스터를 담는 구조체를 두고, 전환할 때 현재 태스크의 레지스터를 이 구조체에 저장한 뒤 다음 태스크의 구조체에서 레지스터를 전부 꺼내 `iret`으로 돌아갔다. 그런데 이 방식으로 `yield`를 구현하려니, 시스템 콜 중간에 양보한 태스크와 유저 모드에서 선점된 태스크를 서로 다르게 저장하고 복원해야 했다. 짜다 보니 구조가 점점 복잡해져서, 이건 아닌 것 같다는 생각이 들었다. 다른 방법을 찾다가 이 튜토리얼을 보고 감명을 받아 바로 방식을 바꿨다.

전환 시점에 태스크의 문맥은 이미 커널 스택에 그대로 남아 있으므로, `switch_to`는 callee-saved 레지스터만 보존해서 호출 규약을 지키면 된다. 그러면 이 태스크가 다시 스케줄됐을 때 `switch_to`에서 반환되는 것만으로 하던 일을 그대로 이어 간다. 시스템 콜 중간에 양보한 태스크든 유저 모드에서 선점된 태스크든 똑같이 처리된다.

태스크 전환 코드: [src/kernel/sched.asm](https://github.com/zerone015/kfs/blob/master/src/kernel/sched.asm#L9)

## Non-preemptive Kernel

내 커널은 커널 모드에서 인터럽트를 비활성화하기 때문에, 커널 코드를 실행하는 동안 PIT 인터럽트가 오지 않는다. 따라서 타임 슬라이스 소진에 의한 전환은 유저 모드에서만 일어나고, 커널 모드에서는 `yield`를 호출하는 지점에서만 전환이 일어난다. 이렇게 커널 모드에서는 선점되지 않는 커널을 비선점형 커널이라고 한다.

이 방식은 커널 모드에서 오래 걸리는 처리를 하면 그동안 다른 태스크가 실행되지 못해서, 레이턴시가 높아진다는 문제가 있다. 대신 커널 코드가 중간에 끊기지 않고 쭉 실행되므로 문맥 교환이 줄어들고, 그만큼 전환 비용과 캐시, TLB 오염이 줄어 처리량 면에서는 유리하다.