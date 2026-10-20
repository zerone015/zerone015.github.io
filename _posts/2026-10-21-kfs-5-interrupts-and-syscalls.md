---
title: "[KFS] 5. Interrupts and System Calls"
date: 2026-10-21 01:00:00 +0900
categories: [Projects, KFS]
tags: [kernel, x86, kfs, 42seoul]
math: true
---

인터럽트는 외부 인터럽트와 내부 인터럽트로 나뉜다. 외부 인터럽트는 장치가 보내는 하드웨어 인터럽트다. 내부 인터럽트는 CPU가 명령어를 실행하다가 발생시키는 예외와, `int` 명령어로 직접 발생시키는 소프트웨어 인터럽트로 다시 나뉜다. 시스템 콜이 소프트웨어 인터럽트에 해당한다.

## Hardware Interrupt

하드웨어 인터럽트는 장치가 CPU에 보내는 비동기 신호다. 전달 방식은 크게 두 가지다. 장치와 인터럽트 컨트롤러를 물리적인 IRQ 라인으로 연결해 신호를 보내는 방식과, 장치가 정해진 MMIO 주소에 메모리 쓰기를 해서 알리는 MSI(Message Signaled Interrupts) 방식이다. MSI는 PCI 2.2에서 도입되어 PCIe에서는 필수가 되었다. 내 커널이 다루는 PIT와 키보드는 ISA 시절의 레거시 장치라서, IRQ 라인 방식만 처리한다.

### PIC

IRQ 라인으로 오는 인터럽트는 곧바로 CPU로 가지 않고, 중간의 인터럽트 컨트롤러인 PIC를 먼저 거친다. PIC는 IRQ를 그에 대응하는 인터럽트 벡터 번호로 바꿔서 CPU에 전달하고, 여러 IRQ가 동시에 오면 우선순위에 따라 하나씩 보낸다. CPU가 `cli`로 인터럽트를 막아 둔 동안에는 요청을 보관해 두었다가, 다시 허용되면 전달한다. CPU는 명령어 하나를 끝낼 때마다 들어온 인터럽트가 있는지 확인한다.

![마스터와 슬레이브 PIC가 연결된 구조](/assets/img/kfs/kfs-pic.png)
_Cascaded master and slave 8259 PICs_

PIC는 칩 두 개가 마스터와 슬레이브로 연결된 구조다. 칩 하나에 IRQ 라인이 8개씩 있어서 총 16개인데, 마스터의 IRQ 2는 슬레이브를 연결하는 데 쓰인다. 따라서 장치가 쓸 수 있는 건 15개다.

- **Master:** CPU의 인터럽트 입력 핀에 직접 연결되어 있고, IRQ 0~7을 담당한다.
- **Slave:** IRQ 8~15를 담당한다. IRQ가 오면 마스터의 IRQ 2로 인터럽트를 보낸다.

IRQ의 우선순위는 번호가 낮을수록 높다. 다만 슬레이브의 IRQ들은 마스터의 IRQ 2 자리 우선순위를 그대로 물려받는다. 그래서 IRQ 3은 슬레이브의 모든 IRQ보다 우선순위가 낮다.

| IRQ | Description |
|---|---|
| 0 | Programmable Interrupt Timer Interrupt |
| 1 | Keyboard Interrupt |
| 2 | Cascade (used internally by the two PICs. never raised) |
| 3 | COM2 (if enabled) |
| 4 | COM1 (if enabled) |
| 5 | LPT2 (if enabled) |
| 6 | Floppy Disk |
| 7 | LPT1 / Unreliable "spurious" interrupt (usually) |
| 8 | CMOS real-time clock (if enabled) |
| 9 | Free for peripherals / legacy SCSI / NIC |
| 10 | Free for peripherals / SCSI / NIC |
| 11 | Free for peripherals / SCSI / NIC |
| 12 | PS2 Mouse |
| 13 | FPU / Coprocessor / Inter-processor |
| 14 | Primary ATA Hard Disk |
| 15 | Secondary ATA Hard Disk |

PIC 안에는 8비트 레지스터가 세 개 있다. 비트 하나가 IRQ 라인 하나를 나타낸다.

- **IRR (Interrupt Request Register):** 요청이 들어온 라인을 표시한다.
- **ISR (In-Service Register):** CPU에 전달되어 지금 처리 중인 라인을 표시한다.
- **IMR (Interrupt Mask Register):** 막아 둔 라인을 표시한다.

동작 순서는 다음과 같다.

1. 장치가 IRQ 라인에 신호를 보내면 IRR의 해당 비트가 켜진다.
2. PIC는 IRR에서 IMR로 막히지 않은 요청 중 우선순위가 가장 높은 것을 고른다. 그 요청이 ISR에서 처리 중인 것보다 우선순위가 높으면 CPU에 인터럽트를 알린다.
3. CPU가 인터럽트를 받으면 해당 비트가 IRR에서 지워지고 ISR에 켜진다. PIC는 벡터 번호를 CPU에 넘긴다.
4. 핸들러가 처리를 마치고 EOI(End Of Interrupt)를 보내면 ISR 비트가 꺼진다. 슬레이브 쪽 인터럽트라면 슬레이브와 마스터 모두에 보내야 한다.

![IRR, IMR, ISR이 바뀌는 과정](/assets/img/kfs/kfs-pic-flow.png)
_How IRR, IMR and ISR change while an IRQ is delivered_

### Edge Trigger vs Level Trigger

PIC는 설정을 통해 IRQ 라인의 신호를 읽는 방식을 엣지 트리거와 레벨 트리거 중에서 고를 수 있다.

- **Edge trigger:** 전압이 높아지는 순간에만 IRR에 기록하고, 전압이 낮아져도 지우지 않는다.
- **Level trigger:** IRR이 현재 전압을 그대로 따라간다. 전압이 높으면 기록하고, 낮아지면 지운다.

장치 중에는 신호를 잠깐 올렸다가 바로 내리는 펄스를 보내는 장치가 있고, 드라이버가 처리해 줄 때까지 신호를 유지하는 장치가 있다. 펄스는 금방 내려가므로 레벨 트리거로 읽으면 CPU에 전달되기 전에 요청이 사라질 수 있다. 그래서 펄스를 보내는 장치는 엣지 트리거로 처리해야 한다. 신호를 유지하는 장치는 두 방식 모두로 처리할 수 있지만, 여러 장치가 IRQ 라인 하나를 공유한다면 레벨 트리거를 써야 한다. 엣지 트리거로 공유하면 다음과 같은 문제가 생긴다.

1. 장치 A와 B가 IRQ 라인 하나를 공유하고, A가 신호를 올린다.
2. CPU가 인터럽트를 받으면서 IRR이 지워지고 ISR이 켜진다.
3. 핸들러가 A의 상태 레지스터를 확인해서 처리하고, 이어서 B의 상태 레지스터도 확인한다. 이때 B는 아직 요청하지 않았다.
4. 핸들러가 B를 확인한 직후에 B가 신호를 올린다. 핸들러는 A의 처리를 마치고 EOI를 보낸다. A는 처리가 끝났으니 신호를 내린다.

A의 신호는 내려갔지만 B가 신호를 올리고 있으므로, 라인은 여전히 높은 상태다. 레벨 트리거라면 PIC는 라인이 아직 높으니 IRR을 다시 켜고, 인터럽트가 한 번 더 들어와서 B가 처리된다. 반면 엣지 트리거라면 IRR이 켜지지 않는다. B는 처리될 때까지 신호를 내리지 않으므로 라인이 계속 높은 채로 남고, 그 뒤로 이 라인의 인터럽트는 영영 전달되지 않는다.

내 커널은 IRQ 라인을 공유하지 않고, 다루는 장치 모두 엣지 트리거를 전제로 동작하는 장치라서 PIC를 엣지 트리거로 설정했다.

참고로 NMI(Non-Maskable Interrupt)라는 인터럽트도 있다. PIC를 거치지 않고 CPU의 NMI 핀으로 직접 들어오며, `cli`로도 막을 수 없다. 주로 메모리 오류 같은 치명적인 하드웨어 오류를 알리는 데 쓰인다.

### PIC Initialization

초기화 코드: [src/kernel/pic.c](https://github.com/zerone015/kfs/blob/master/src/kernel/pic.c#L3)

인터럽트를 처리하려면 먼저 PIC를 올바르게 설정해야 한다. PIC 초기화에는 ICW(Initialization Command Word) 1~4를 순서대로 보내는 정해진 절차가 있고, 초기화는 [OSDev Wiki의 8259 PIC 문서](https://osdev.wiki/wiki/8259_PIC)를 참고했다.

초기화에서 눈여겨볼 부분은 ICW2에서 하는 벡터 오프셋 재매핑이다. 벡터 0~31은 Intel이 CPU 예외용으로 예약한 번호인데, IBM PC는 PIC의 기본 오프셋을 이 범위와 겹치게 잡았다. 그래서 IRQ 0~7은 벡터 32~39로, IRQ 8~15는 벡터 40~47로 재매핑한다. 장치는 지금 PIT와 키보드만 다루기 때문에, IMR에서 IRQ 0과 1을 제외한 모든 IRQ를 막아 둔다.

### PIT


### Keyboard


## IDT

초기화 코드: [src/kernel/idt.c](https://github.com/zerone015/kfs/blob/master/src/kernel/idt.c#L27)

IDT(Interrupt Descriptor Table)는 리얼 모드의 인터럽트 벡터 테이블(IVT)에 해당하는, 보호 모드의 테이블이다. 인터럽트 핸들러의 주소와 속성을 담은 디스크립터의 배열이고, 인터럽트 벡터 번호가 이 배열의 인덱스다. IDT의 시작 주소와 크기는 IDTR 레지스터에 등록한다. CPU는 인터럽트가 발생하면 벡터 번호로 IDT를 인덱싱해서 핸들러로 점프한다.

핸들러를 호출하기 전에 CPU는 커널 스택에 다음 값들을 순서대로 push한다.

1. 유저 모드에서 발생한 경우에만: `SS`, `ESP`
2. 공통: `EFLAGS`, `CS`, `EIP`
3. 일부 예외만: 에러 코드

핸들러가 끝나고 `iret`을 실행하면 CPU가 push했던 값들을 그대로 pop해서 원래 상태로 돌아간다. 에러 코드는 `iret`이 pop하지 않으므로 핸들러가 직접 정리해야 한다.

![인터럽트 발생 시 CPU가 커널 스택에 push하는 값](/assets/img/kfs/kfs-int-stack.png)
_Kernel stack right after the CPU enters an interrupt handler_

IDT의 각 엔트리는 게이트 디스크립터라고 부른다. 구조는 [OSDev Wiki의 IDT 문서](https://osdev.wiki/wiki/Interrupt_Descriptor_Table)를 참고하면 된다. 여기서 주목할 필드는 DPL과 게이트 타입이다.

- **DPL:** 유저 모드에서 `int` 명령어로 이 인터럽트를 직접 발생시킬 수 있는지를 정한다. 하드웨어 인터럽트와 예외에는 적용되지 않는다. 내 커널은 `int 0x80` 방식의 시스템 콜을 사용하므로, 0x80 게이트만 DPL을 3으로 설정했다.
- **게이트 타입:** 인터럽트 게이트, 트랩 게이트, 태스크 게이트가 있다. 태스크 게이트는 하드웨어 태스크 스위칭용이라 거의 쓰이지 않는다. 인터럽트 게이트는 핸들러에 진입할 때 `EFLAGS`의 IF 플래그를 꺼서 인터럽트를 막고, 트랩 게이트는 끄지 않는다. 즉 트랩 게이트는 핸들러가 실행되는 도중에 다른 인터럽트가 끼어드는 중첩 인터럽트를 허용한다. `iret`으로 돌아갈 때는 저장해 둔 `EFLAGS`를 복원하므로 IF도 원래대로 돌아온다.

중첩 인터럽트는 처리가 복잡하고, 실시간성이 엄격하게 요구되는 시스템이 아니면 굳이 필요하지 않다. 그래서 모든 게이트를 인터럽트 게이트로 설정했다.

## TSS

초기화 코드: [src/kernel/gdt.c](https://github.com/zerone015/kfs/blob/master/src/kernel/gdt.c#L51)

유저 모드에서 인터럽트나 시스템 콜로 커널 모드에 진입하면, 스택도 유저 스택에서 커널 스택으로 바뀌어야 한다. TSS(Task State Segment)는 원래 하드웨어 태스크 스위칭용 구조체지만, 지금은 주로 이 용도로 쓰인다. 권한 수준이 바뀌는 인터럽트가 발생하면, CPU는 TSS의 `SS0`와 `ESP0`를 읽어서 커널 스택으로 전환한다.

TSS는 GDT에 TSS 디스크립터로 등록하고, `ltr` 명령어로 그 셀렉터를 태스크 레지스터에 로드한다. TSS에 대한 자세한 내용은 [OSDev Wiki의 TSS 문서](https://osdev.wiki/wiki/Task_State_Segment)를 참고하면 된다.

## GDT

초기화 코드: [src/kernel/gdt.c](https://github.com/zerone015/kfs/blob/master/src/kernel/gdt.c#L37)

GDT(Global Descriptor Table)는 인터럽트와 직접적인 관련은 없지만, 앞에서 본 TSS를 등록하는 곳이라 같이 설명한다. GDT는 메모리를 세그먼트 단위로 나눠 관리하던 세그멘테이션 시절에 쓰던 테이블이다. 지금은 메모리 보호를 페이징으로 하므로 세그멘테이션은 필요 없다. 다만 32비트 x86의 보호 모드에서는 세그멘테이션을 끌 수 없어서, 사실상 꺼진 것과 같은 상태로 만들어야 한다.

방법은 모든 세그먼트의 시작 주소를 0으로, 크기를 4GB로 잡는 것이다. 이를 플랫 메모리 모델이라고 한다. 설정하는 절차는 정해져 있고, [OSDev Wiki의 GDT 문서](https://osdev.wiki/wiki/Global_Descriptor_Table)와 [GDT Tutorial](https://osdev.wiki/wiki/GDT_Tutorial)을 참고하면 된다.

### Segment Selector and Privilege Level

GDT는 사실상 쓰이지 않지만, 세그먼트 셀렉터는 여전히 쓰인다. 셀렉터는 16비트 크기이고, 각 비트는 다음과 같다.

| 비트 | 필드 | 의미 |
|---|---|---|
| 15–3 | Index | GDT(또는 LDT)의 엔트리 번호 |
| 2 | TI | 0이면 GDT, 1이면 LDT |
| 1–0 | RPL | 요청 권한 수준 |

세그먼트 셀렉터는 6개가 있고, 메모리에 접근할 때 명령어에 따라 그중 하나가 암시적으로 쓰인다.

- **CS:** 코드 세그먼트. 명령어를 가져올 때 쓰인다. CS의 하위 2비트가 현재 권한 수준(CPL)이다.
- **SS:** 스택 세그먼트. `push`, `pop`, 그리고 `[esp + 4]`나 `[ebp - 8]`처럼 ESP나 EBP를 기준으로 하는 메모리 접근에 쓰인다.
- **DS:** 데이터 세그먼트. 그 밖의 대부분의 메모리 접근에 기본으로 쓰인다.
- **ES:** 대부분의 경우 DS와 같다. `movs`, `stos` 같은 문자열 명령어에서 사용한다.
- **FS, GS:** 기본 용도가 없는 추가 세그먼트다. 요즘 운영체제는 TLS나 CPU별 데이터에 접근하는 용도로 쓴다.

플랫 메모리 모델에서는 CS만 의미가 있고, TLS로 쓰는 FS, GS를 빼면 나머지는 사실상 효과가 없다.

권한 수준은 0이 가장 높고 3이 가장 낮다. 세그먼트 셀렉터를 바꿀 때 권한 검사가 일어나고, 이때 세 가지 권한 수준이 쓰인다.

- **DPL (Descriptor Privilege Level):** 새로 넣을 셀렉터의 디스크립터에 적힌 권한 수준이다.
- **RPL (Requested Privilege Level):** 새로 넣을 셀렉터의 RPL이다.
- **CPL (Current Privilege Level):** CS의 RPL 필드로, 지금 실행 중인 코드의 권한 수준이다.

Intel 매뉴얼에 따르면, 데이터 세그먼트는 $\max(CPL, RPL) \le DPL$이어야 하고, 스택 세그먼트는 CPL, RPL, DPL이 모두 같아야 한다. 이를 어기면 GPF(General Protection Fault)가 발생한다.

## Exceptions


### Exception Stubs


### Page Fault


### Panic


## Software Interrupt
