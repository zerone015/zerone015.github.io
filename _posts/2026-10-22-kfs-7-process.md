---
title: "[KFS] 7. Process"
date: 2026-10-22 22:00:00 +0900
categories: [Projects, KFS]
tags: [kernel, x86, kfs, 42seoul]
math: true
---

## PID

```c
#define PID_MAX     32768
#define PIDMAP_MAX  (PID_MAX / 8 / 4)

extern uint32_t pidmap[PIDMAP_MAX];
```

PID는 비트맵으로 관리하고 있다. PID 개수는 32768개로 정했는데, 구현 당시 리눅스의 기본 PID 개수가 이 값이라 그대로 따라갔었다.

PID 할당 코드: [include/pid.h](https://github.com/zerone015/kfs/blob/master/include/pid.h)

### PID Reuse

PID 할당에는 재할당 문제가 있다. 어떤 프로세스가 다른 프로세스의 PID를 기억해 뒀다가 나중에 `kill`로 시그널을 보낸다고 해 보자. 그사이 원래 프로세스가 종료되어 회수되고 새 프로세스가 같은 PID를 받았다면, 관련 없는 프로세스가 시그널을 받게 된다.

리눅스는 마지막으로 할당한 PID를 기억해 두고 그다음 PID부터 순환하며 할당한다. 이를 통해 최근에 해제된 PID일수록 최대한 늦게 재사용하려고 노력한다. 하지만 오래된 프로세스가 있고 그사이 프로세스가 많이 생성되어 커서가 한 바퀴 돌아 그 근처에 와 있다고 가정해 보자. 이때 마침 오래된 프로세스가 종료되면 그 PID는 바로 재사용된다. 이런 경우를 어떻게 처리해야 할지 고민하다가 나중으로 미뤘는데, 다른 작업에 밀려 결국 손대지 못했다.

KFS 이후 42의 process-and-memory 과제를 하면서 알게 된 사실인데, 리눅스는 PID를 객체로 다루는 방식으로 이 문제를 해결한다. 리눅스 커널에는 `struct pid`가 있고, 정의된 파일 상단 주석에 바로 이 문제가 언급되어 있다. 숫자는 재사용될 수 있지만 객체는 유일하다. `struct pid`는 참조 카운트로 수명이 관리되기 때문에, 누군가 참조하고 있다면 프로세스가 종료되어도 해제되지 않는다. 그리고 같은 숫자가 재사용되더라도 새 프로세스는 새 `struct pid`를 받는다.

유저 공간에서는 pidfd라는 API로 이 객체를 참조할 수 있다. `pidfd_open`으로 pidfd를 얻으면 내부적으로 `struct pid`의 참조 카운트가 올라가고, 이후 `pidfd_send_signal`처럼 pidfd를 받는 API를 쓰면 재할당 문제가 생기지 않는다. 다만 `pidfd_open`을 하기 전에 이미 종료되어 재할당됐다면 엉뚱한 프로세스를 열게 된다. 그래서 부모가 자식을 회수하기 전에 열거나, `clone`의 `CLONE_PIDFD` 플래그로 자식을 만들면서 바로 pidfd를 받는다. 부모가 아닌 프로세스는 숫자 PID만으로는 안전하게 열 방법이 없으므로, 이렇게 얻은 pidfd를 전달받아 사용해야 한다.

## Process Table

```c
#define PID_HASH_BUCKETS        1024

struct list_head process_list;
struct hlist_head process_table[PID_HASH_BUCKETS];
```

`process_table`은 PID로 `task_struct`를 찾는 해시 테이블이고, `process_list`는 모든 프로세스의 `task_struct`를 잇는 연결 리스트다. 둘을 따로 두는 건 `kill` 시스템 콜 때문으로, 특정 PID로 시그널을 보낼 때 리스트를 전부 순회하지 않기 위해 해시 테이블로 찾는다. 반면 `kill`에는 보낼 수 있는 모든 프로세스에 시그널을 보내는 기능도 있는데, 해시 테이블을 순회하면 빈 버킷까지 다 훑어야 하므로 리스트로 순회한다.

버킷 개수는 1024개로 정했다. 충돌로 인한 최악의 탐색 횟수는 32번이고, 이 정도면 메모리와 성능 사이에서 적절하다고 판단했다.

처음에는 `process_table`을 `task_struct` 포인터의 정적 배열로 구현했었다. 그런데 프로세스가 32768개나 있는 경우는 흔치 않은데 128KB를 항상 들고 있는 건 낭비라는 생각이 들었다. 그러다 리눅스가 해시 테이블을 사용한다는 걸 알게 됐고, 해시 테이블을 쓰면 이 희소한 상황을 어느 정도 해결할 수 있었다. 충돌로 인한 탐색은 감수해야 하지만, 정적으로 할당되는 메모리는 4KB로 확연히 줄어든다. 해시 테이블이 배열만큼 메모리를 쓰려면 프로세스가 약 16000개는 있어야 한다. 대부분의 시스템에서 프로세스가 이만큼 있을 일은 거의 없다.

KFS 이후 리눅스 커널 코드를 보면서 알게 된 사실인데, 최신 리눅스는 XArray라는 기수 트리 기반 자료구조로 이 문제를 더 효율적으로 해결한다. 기수 트리는 키를 비트 단위로 잘라 단계별로 인덱싱하는 트리로, 희소한 상황에 딱 맞는 자료구조다. 예를 들어 PID 32768개는 15비트로 표현할 수 있는데, 이를 상위 3비트, 6비트, 6비트로 자르면 각 단계의 비트를 인덱스로 노드를 따라 내려가 PID를 찾을 수 있다. 사용하지 않는 구간은 아래 노드를 만들지 않아 필요한 만큼만 메모리를 쓰고, 단계 수가 고정이라 배열처럼 빠르게 조회할 수 있다.

![PID 기수 트리](/assets/img/kfs/kfs-pid-radix.png)
_Radix tree for PIDs_

프로세스 테이블 코드: [include/proc.h](https://github.com/zerone015/kfs/blob/master/include/proc.h)

## Process Group

```c
#define PGROUP_HASH_BUCKETS     (PID_HASH_BUCKETS / 2)

struct pgroup {
    int pgid;
    struct hlist_head members;
    struct hlist_node node;
};

struct hlist_head pgroup_table[PGROUP_HASH_BUCKETS];
```

프로세스 그룹도 `kill`로 시그널을 보낼 수 있기 때문에 해시 테이블로 관리한다. 그룹은 일반적으로 프로세스보다 적기 때문에 버킷은 절반만 뒀다. pgid는 그룹을 만든 프로세스의 PID가 되고, fork된 프로세스는 부모의 pgid를 그대로 물려받는다.

프로세스 그룹 코드: [include/proc.h](https://github.com/zerone015/kfs/blob/master/include/proc.h#L10)

## Init Process

부팅 시 프로세스 관련 초기화로 먼저 pidmap에서 PID 0과 1을 예약하고, 프로세스 리스트를 초기화한다. 이후 첫 프로세스인 init 프로세스를 만든다. init 프로세스는 예약해 둔 PID 1을 받으며, 지금은 여러 기능을 테스트하는 용도로 쓰인다.

init 프로세스는 초기화를 마친 뒤 `execve`를 대신하는 함수인 `exec_fn`을 호출한다. 아직 파일 시스템과 ELF 로더가 없어서 프로그램 파일을 실행할 수 없기 때문에, 대신 함수 포인터를 받아 실행한다. `execve`와 비슷하게 기존 가상 주소 공간과 시그널을 초기화한 뒤, 새 가상 주소 공간을 구성하고 함수의 코드를 정해진 코드 영역에 복사한다. 그다음 유저 모드로 전환해 코드 영역으로 점프한다. `exec_fn`이 구성하는 가상 주소 공간은 다음과 같다.

![exec_fn이 구성하는 유저 가상 주소 공간](/assets/img/kfs/kfs-user-vas.png)
_User virtual address space built by exec_fn_

여기서 중요한 점은 인자로 넘기는 함수가 다른 함수를 호출하지 않아야 한다는 것이다. 이 함수는 커널 코드라서 원래 커널 공간에 있는데, `call`은 상대 주소를 쓰는 명령어라서 유저 코드 영역으로 복사하면 오프셋이 엉뚱한 곳을 가리키게 된다. 그래서 테스트 코드에서 쓰는 함수는 모두 `always_inline`으로 정의했다.

init 프로세스 코드: [src/kernel/init.c](https://github.com/zerone015/kfs/blob/master/src/kernel/init.c#L18)

exec_fn 코드: [src/kernel/exec.c](https://github.com/zerone015/kfs/blob/master/src/kernel/exec.c#L128)

## Process Creation

프로세스는 fork로 생성된다. 먼저 자식의 `task_struct`를 할당하고 PID를 받은 뒤, uid와 pgid, sid 같은 값은 부모에게서 그대로 물려받는다. 그다음 자식의 커널 스택을 구성하고 가상 주소 공간을 복제한다. 마지막으로 자식을 부모의 자식 리스트와 프로세스 테이블, 프로세스 그룹에 등록하고 스케줄링 큐에 넣은 뒤, 부모에게 자식의 PID를 반환한다.

fork 코드: [src/kernel/syscall.c](https://github.com/zerone015/kfs/blob/master/src/kernel/syscall.c#L357)

### Kernel Stack

커널 스택은 자식이 처음 스케줄됐을 때 fork에서 돌아오는 것처럼 동작하도록 미리 구성해 둬야 한다. 6편에서 다룬 것처럼 태스크 전환은 `switch_to`에서 반환되는 방식으로 이루어지기 때문에, 이를 기준으로 스택을 쌓아 둬야 한다.

![fork로 구성한 자식의 커널 스택](/assets/img/kfs/kfs-fork-stack.png)
_Child kernel stack built by fork_

자식이 처음 스케줄되면 `switch_to`가 callee-saved 레지스터를 꺼내고 `ret`하는데, 복귀 주소 자리에 `fork_child_trampoline`을 넣어 뒀기 때문에 트램펄린으로 점프한다. 트램펄린은 caller-saved 레지스터를 꺼낸 뒤 `iretd`로 유저 모드로 돌아간다. 레지스터 값은 부모가 fork를 호출했을 때의 값을 그대로 복사했고 `eax`만 0으로 넣어 두었기 때문에, 자식은 fork가 0을 반환한 것처럼 같은 지점부터 실행을 이어 간다.

커널 스택 구성 코드: [src/kernel/syscall.c](https://github.com/zerone015/kfs/blob/master/src/kernel/syscall.c#L333)

### COW

가상 주소 공간은 COW로 복제한다. 물리 페이지는 복사하지 않고 참조 카운트만 올려 부모와 공유하며, 쓰기 가능한 페이지는 읽기 전용으로 보호를 건다.

다만 원래 쓰기 가능한 페이지였다는 사실을 표시해 둬야 한다. 이 표시가 없으면 나중에 페이지 폴트가 났을 때, COW 때문에 막아 둔 페이지에 쓴 건지 원래 읽기 전용인 페이지에 쓴 건지 구분할 수 없다. 그래서 PTE에서 OS가 자유롭게 쓸 수 있는 비트에 COW 플래그를 둬야 한다. 원래 쓰기 가능한 페이지에는 `PG_COW_RDWR`를, 원래 읽기 전용인 페이지에는 `PG_COW_RDONLY`를 표시한다.

```c
#define PG_COW_RDWR     0x200   /* originally writable */
#define PG_COW_RDONLY   0x400   /* originally read-only */
```

COW에는 페이지만 공유하는 방법과 페이지 테이블까지 공유하는 방법이 있다. 내 구현은 페이지 테이블은 fork할 때 모두 복사하고 페이지만 공유한다. 페이지 테이블까지 COW로 공유하면 메모리를 많이 사용하면서 fork를 반복하는 프로세스에서는 유의미한 성능 이점이 있지만, 그에 비해 구현이 너무 복잡해서 하지 않았다.

COW 설정 코드: [src/kernel/syscall.c](https://github.com/zerone015/kfs/blob/master/src/kernel/syscall.c#L236)

## Process Termination

프로세스가 exit를 호출하면 먼저 사용하던 자원을 정리한다. 유저 가상 주소 공간의 매핑과 물리 페이지를 해제하고, 프로세스 그룹에서 빠진다. 자식이 남아 있다면 자식들의 부모를 init 프로세스로 다시 설정한다. 그다음 종료 상태를 보관하고 좀비 상태가 된다.

이후 부모에게 종료를 알린다. 부모가 SIGCHLD에 핸들러를 등록했다면 SIGCHLD를 보내고, 기본 동작이라면 waitpid로 기다리고 있는 부모를 깨운다. 부모가 SIGCHLD를 무시하도록 설정했다면 자식을 회수하지 않겠다는 뜻이므로, 자신의 부모를 init 프로세스로 다시 설정한다. 마지막으로 `yield`를 호출해 CPU를 넘기고, 이후로는 다시 스케줄되지 않는다.

exit할 때 모든 자원을 바로 해제할 수는 없다. 부모가 회수할 때 PID와 종료 상태를 넘겨줘야 하고, 페이지 디렉터리와 커널 스택은 지금 실행 중인 코드가 쓰고 있기 때문이다. 이들은 나중에 부모가 waitpid로 회수할 때 해제된다.

exit 코드: [src/kernel/proc.c](https://github.com/zerone015/kfs/blob/master/src/kernel/proc.c#L82)

## Process Reaping

부모는 waitpid로 종료된 자식을 회수한다. 기다릴 대상은 pid 인자에 따라 다음과 같이 정해진다.

- **`pid > 0`:** PID가 pid인 자식
- **`pid == 0`:** 같은 프로세스 그룹의 자식
- **`pid < -1`:** 프로세스 그룹 ID가 `-pid`인 자식
- **`pid == -1`:** 모든 자식

조건에 맞는 자식이 없으면 `ECHILD`를 반환한다. 조건에 맞는 좀비가 있으면 바로 회수하는데, 종료 상태를 넘겨주고 exit에서 해제하지 못한 자원을 해제한 뒤 자식의 PID를 반환한다. 이때 POSIX 규정에 따라, 회수할 다른 좀비가 없으면 대기 중인 SIGCHLD를 지운다.

종료 상태는 리눅스와 같은 형식으로, exit로 종료하면 상위 바이트에 종료 코드를, 시그널로 종료되면 하위 바이트에 시그널 번호를 저장한다.

```c
#define WTERMSIG(status)     ((status) & 0x7F)
#define WIFEXITED(status)    (!WTERMSIG(status))
#define WEXITSTATUS(status)  (((status) >> 8) & 0xFF)
```

이 값은 인자로 받은 `status` 포인터에 써서 넘겨주는데, 이 포인터는 유저 공간에서 넘어온 값이라 신뢰할 수 없다. 매핑되지 않은 주소면 커널 모드 페이지 폴트로 패닉이 나고, 커널 주소면 커널 메모리를 조작할 수 있다. 그래서 `access_ok`로 매핑된 유저 공간 주소인지 먼저 확인한다.

좀비가 없을 때 `WNOHANG` 옵션을 줬다면 잠들지 않고 바로 0을 반환하는 비차단 방식으로 동작하고, 아니라면 자식이 종료할 때까지 잠든다. 잠들기 전과 깨어난 뒤에는 시그널이 와 있는지 확인하고, 와 있으면 `-EINTR`로 돌아간다. 이 경우 시그널을 처리한 뒤 시스템 콜을 자동으로 다시 시작하도록 구현했다. `sigaction` 없이 `signal`만 구현했고, glibc의 `signal` 동작이 이 방식이다. 옵션은 `WNOHANG`만 구현했다.

![waitpid의 동작 흐름](/assets/img/kfs/kfs-waitpid.png)
_waitpid flow_

waitpid 코드: [src/kernel/syscall.c](https://github.com/zerone015/kfs/blob/master/src/kernel/syscall.c#L441)