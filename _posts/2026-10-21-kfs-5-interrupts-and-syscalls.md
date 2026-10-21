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

인터럽트를 처리하려면 먼저 PIC를 올바르게 설정해야 한다. PIC 초기화에는 ICW(Initialization Command Word) 1~4를 순서대로 보내는 정해진 절차가 있다. 자세한 내용은 [OSDev Wiki의 8259 PIC 문서](https://wiki.osdev.org/8259_PIC)를 참고하면 된다.

초기화에서 눈여겨볼 부분은 ICW2에서 하는 벡터 오프셋 재매핑이다. 벡터 0~31은 Intel이 CPU 예외용으로 예약한 번호인데, IBM PC는 PIC의 기본 오프셋을 이 범위와 겹치게 잡았다. 그래서 IRQ 0~7은 벡터 32~39로, IRQ 8~15는 벡터 40~47로 재매핑한다. 장치는 지금 PIT와 키보드만 다루기 때문에, IMR에서 IRQ 0과 1을 제외한 모든 IRQ를 막아 둔다.

### PIT

초기화 코드: [src/kernel/pit.c](https://github.com/zerone015/kfs/blob/master/src/kernel/pit.c#L5)

PIT(Programmable Interval Timer)는 일정한 주기로 IRQ 0을 발생시키는 타이머다. 주파수가 1,193,182Hz로 고정되어 있어서, 내부 카운터가 이 클럭에 맞춰 1씩 줄어들다가 0이 되면 인터럽트를 보내고 다시 설정한 값부터 센다. 내 커널에서 PIT는 스케줄링에 쓰이는데, 1ms 주기가 필요하다. 따라서 초기화할 때 내부 카운터를 1,193,182 / 1000으로 설정한다. PIT에 대한 자세한 내용은 [OSDev Wiki의 PIT 문서](https://wiki.osdev.org/Programmable_Interval_Timer)를 참고하면 된다.

### Keyboard

핸들러 코드: [src/kernel/isr.c](https://github.com/zerone015/kfs/blob/master/src/kernel/isr.c#L156)

현재 구현에서는 PS/2 키보드만 처리하며, USB 키보드는 펌웨어의 USB 레거시 지원을 통해 PS/2 키보드로 에뮬레이션된다.

PS/2 키보드는 PIC와 바로 연결되지 않고, 그 사이에 PS/2 컨트롤러가 있다. 키를 누르면 키보드가 컨트롤러로 입력을 보내고, 컨트롤러는 그 입력을 1바이트 버퍼에 담은 뒤 PIC에 인터럽트를 보낸다. 핸들러는 컨트롤러의 데이터 포트에서 입력을 읽어 오고, 그러면 키보드 버퍼에 있던 다음 키 입력이 컨트롤러로 전달된다.

![PS/2 키보드, 컨트롤러, PIC, CPU의 연결 구조](/assets/img/kfs/kfs-keyboard.png)
_PS/2 keyboard, controller, PIC and CPU_

키보드가 보내는 값을 스캔코드라고 하는데, 키보드에서 키의 위치를 나타내는 값이다. 키 위치마다 어떤 값을 보낼지 정한 것을 스캔코드 세트라고 하며, 세 가지 버전이 있다. 내 커널은 스캔코드 세트 1을 사용한다. 스캔코드는 키를 누를 때와 뗄 때 따로 온다. 방향키 같은 일부 확장 키는 스캔코드 하나가 아니라 `0xE0`을 먼저 보내고 그다음 실제 스캔코드를 보내는데, 확장 키 처리는 구현되어 있지 않다.

키보드 핸들러의 현재 구현은 아주 단순하다. 스캔코드를 글자로 바꾸는 키맵이 US QWERTY 배열 기준으로 두 개 있는데, 하나는 일반 상태용이고 하나는 Shift를 누른 상태용이다. 인터럽트가 오면 데이터 포트에서 스캔코드를 읽고, 키맵을 인덱싱해 글자를 얻은 뒤 tty 계층을 통해 VGA 텍스트 모드 버퍼에 써서 콘솔에 출력한다. 지금의 tty 계층은 입력을 그대로 출력하는 아주 단순한 I/O 인터페이스다.

PS/2 키보드와 컨트롤러에 대한 자세한 내용은 [OSDev Wiki의 PS/2 Keyboard 문서](https://wiki.osdev.org/PS/2_Keyboard)와 [8042 PS/2 Controller 문서](https://wiki.osdev.org/I8042_PS/2_Controller)를 참고하면 된다.

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

IDT의 각 엔트리는 게이트 디스크립터라고 부른다. 구조는 [OSDev Wiki의 IDT 문서](https://wiki.osdev.org/Interrupt_Descriptor_Table)를 참고하면 된다. 여기서 주목할 필드는 DPL과 게이트 타입이다.

- **DPL:** 유저 모드에서 `int` 명령어로 이 인터럽트를 직접 발생시킬 수 있는지를 정한다. 하드웨어 인터럽트와 예외에는 적용되지 않는다. 내 커널은 `int 0x80` 방식의 시스템 콜을 사용하므로, 0x80 게이트만 DPL을 3으로 설정했다.
- **게이트 타입:** 인터럽트 게이트, 트랩 게이트, 태스크 게이트가 있다. 태스크 게이트는 하드웨어 태스크 스위칭용이라 거의 쓰이지 않는다. 인터럽트 게이트는 핸들러에 진입할 때 `EFLAGS`의 IF 플래그를 꺼서 인터럽트를 막고, 트랩 게이트는 끄지 않는다. 즉 트랩 게이트는 핸들러가 실행되는 도중에 다른 인터럽트가 끼어드는 중첩 인터럽트를 허용한다. `iret`으로 돌아갈 때는 저장해 둔 `EFLAGS`를 복원하므로 IF도 원래대로 돌아온다.

중첩 인터럽트는 처리가 복잡하고, 실시간성이 엄격하게 요구되는 시스템이 아니면 굳이 필요하지 않다. 그래서 모든 게이트를 인터럽트 게이트로 설정했다.

## TSS

초기화 코드: [src/kernel/gdt.c](https://github.com/zerone015/kfs/blob/master/src/kernel/gdt.c#L51)

유저 모드에서 인터럽트나 시스템 콜로 커널 모드에 진입하면, 스택도 유저 스택에서 커널 스택으로 바뀌어야 한다. TSS(Task State Segment)는 원래 하드웨어 태스크 스위칭용 구조체지만, 지금은 주로 이 용도로 쓰인다. 권한 레벨이 바뀌는 인터럽트가 발생하면, CPU는 TSS의 `SS0`와 `ESP0`를 읽어서 커널 스택으로 전환한다.

TSS는 GDT에 TSS 디스크립터로 등록하고, `ltr` 명령어로 그 셀렉터를 태스크 레지스터에 로드한다. TSS에 대한 자세한 내용은 [OSDev Wiki의 TSS 문서](https://wiki.osdev.org/Task_State_Segment)를 참고하면 된다.

## GDT

초기화 코드: [src/kernel/gdt.c](https://github.com/zerone015/kfs/blob/master/src/kernel/gdt.c#L37)

GDT(Global Descriptor Table)는 인터럽트와 직접적인 관련은 없지만, 앞에서 본 TSS를 등록하는 곳이라 같이 설명한다. GDT는 메모리를 세그먼트 단위로 나눠 관리하던 세그멘테이션 시절에 쓰던 테이블이다. 지금은 메모리 보호를 페이징으로 하므로 세그멘테이션은 필요 없다. 다만 32비트 x86의 보호 모드에서는 세그멘테이션을 끌 수 없어서, 사실상 꺼진 것과 같은 상태로 만들어야 한다.

방법은 모든 세그먼트의 시작 주소를 0으로, 크기를 4GB로 잡는 것이다. 이를 플랫 메모리 모델이라고 한다. 설정하는 절차는 정해져 있고, [OSDev Wiki의 GDT 문서](https://wiki.osdev.org/Global_Descriptor_Table)와 [GDT Tutorial](https://wiki.osdev.org/GDT_Tutorial)을 참고하면 된다.

### Segment Selector and Privilege Level

GDT는 사실상 쓰이지 않지만, 세그먼트 셀렉터는 여전히 쓰인다. 셀렉터는 16비트 크기이고, 각 비트는 다음과 같다.

| 비트 | 필드 | 의미 |
|---|---|---|
| 15–3 | Index | GDT(또는 LDT)의 엔트리 번호 |
| 2 | TI | 0이면 GDT, 1이면 LDT |
| 1–0 | RPL | 요청 권한 레벨 |

세그먼트 셀렉터는 6개가 있고, 메모리에 접근할 때 명령어에 따라 그중 하나가 암시적으로 쓰인다.

- **CS:** 코드 세그먼트. 명령어를 가져올 때 쓰인다. CS의 하위 2비트가 현재 권한 레벨(CPL)이다.
- **SS:** 스택 세그먼트. `push`, `pop`, 그리고 `[esp + 4]`나 `[ebp - 8]`처럼 ESP나 EBP를 기준으로 하는 메모리 접근에 쓰인다.
- **DS:** 데이터 세그먼트. 그 밖의 대부분의 메모리 접근에 기본으로 쓰인다.
- **ES:** 대부분의 경우 DS와 같다. `movs`, `stos` 같은 문자열 명령어에서 사용한다.
- **FS, GS:** 기본 용도가 없는 추가 세그먼트다. 요즘 운영체제는 TLS나 CPU별 데이터에 접근하는 용도로 쓴다.

플랫 메모리 모델에서는 CS만 의미가 있고, TLS로 쓰는 FS, GS를 빼면 나머지는 사실상 효과가 없다.

권한 레벨은 0이 가장 높고 3이 가장 낮다. 세그먼트 셀렉터를 바꿀 때 권한 검사가 일어나고, 이때 세 가지 권한 레벨이 쓰인다.

- **DPL (Descriptor Privilege Level):** 새로 넣을 셀렉터의 디스크립터에 적힌 권한 레벨이다.
- **RPL (Requested Privilege Level):** 새로 넣을 셀렉터의 RPL이다.
- **CPL (Current Privilege Level):** CS의 RPL 필드로, 지금 실행 중인 코드의 권한 레벨이다.

Intel 매뉴얼에 따르면, 데이터 세그먼트는 $\max(CPL, RPL) \le DPL$이어야 하고, 스택 세그먼트는 CPL, RPL, DPL이 모두 같아야 한다. 이를 어기면 GPF(General Protection Fault)가 발생한다.

## Exceptions

예외의 종류는 fault, trap, abort 세 가지로 나뉜다. fault는 저장된 EIP가 예외를 일으킨 명령어를 가리켜서, 핸들러가 원인을 해결하면 그 명령어부터 다시 실행할 수 있다. trap은 EIP가 다음 명령어를 가리켜서, 그 명령어를 다시 실행하지 않고 다음 명령어부터 이어서 실행한다. abort는 복구할 수 없는 심각한 오류로, EIP가 원인이 된 명령어를 정확히 가리키지 않을 수 있어서 실행을 이어 갈 수 없다.

예외의 종류와, 어떤 예외가 에러 코드를 스택에 넣는지는 [OSDev Wiki의 Exceptions 문서](https://wiki.osdev.org/Exceptions)를 참고하면 된다.

현재 구현에서 제대로 처리되는 예외는 페이지 폴트 정도다. 나머지 예외들 중 커널 모드에서 발생한 예외는 패닉이 발생하고, 유저 모드에서 발생한 예외는 일부는 시그널로 처리하고 나머지는 패닉이 발생한다.

### Page Fault

페이지 폴트는 매핑되지 않았거나 접근 권한이 없는 메모리에 접근할 때 발생한다. 이때 CR2 레지스터에 접근한 주소가 저장되고, 에러 코드로 원인을 알 수 있다. 자세한 내용은 [OSDev Wiki의 Page Fault 문서](https://wiki.osdev.org/Exceptions#Page_Fault)를 참고하면 된다.

페이지 폴트는 의도한 경우와 의도하지 않은 경우로 나뉜다. 유저 모드에서 커널 영역이나 할당되지 않은 영역에 접근하는 것은 잘못된 접근으로 인한 페이지 폴트다. 이 경우 유저 프로세스에는 SIGSEGV가 전달되어 강제로 종료되고, 커널이 이런 접근을 했다면 커널에 결함이 있는 것이므로 패닉이 발생한다.

반면 일부러 present 비트를 꺼 두어서 발생하는 페이지 폴트는 의도한 경우다. 지연 할당을 위해 가상 주소 공간만 할당해 두고, 접근할 때 페이지 폴트 핸들러에서 물리 메모리를 매핑하는 경우가 그렇다. 페이지 스와핑에도 쓰인다. 또 COW를 위해 일부러 쓰기 불가능하게 보호를 걸어 두고, 쓰기가 일어나면 페이지 폴트 핸들러에서 COW임을 확인하고 페이지를 복제하는 경우도 있다. 페이지 폴트는 fault이기 때문에, 핸들러가 처리하고 돌아오면 같은 명령어가 다시 실행되어 정상적으로 접근이 이루어진다.

내 커널은 의도한 경우를 구분하기 위해 엔트리에 플래그를 표시해 둔다. 지연 할당한 영역은 present가 꺼진 엔트리에 reserved 플래그를 표시하고, COW 페이지는 COW 플래그를 표시한다.

핸들러는 먼저 접근한 주소가 유저 공간인지 커널 공간인지 확인한다. 공간에 따라 처리 방법이 다르기 때문이다.

![페이지 폴트 처리 흐름](/assets/img/kfs/kfs-page-fault.png)
_Page fault handling_

핸들러 코드: [src/kernel/isr.c](https://github.com/zerone015/kfs/blob/master/src/kernel/isr.c#L115)

### Panic

커널에 복구할 수 없는 결함이 발생하면 커널 패닉이 발생한다. 패닉이 발생하면 레지스터와 스택을 덤프하고 원인을 출력한 뒤 시스템을 멈춘다. 윈도우로 치면 그 악명 높은 블루스크린이 커널 패닉이다.

![커널 패닉 화면](/assets/img/kfs/kfs-panic.png)
_Kernel panic_

패닉을 처리하는 `panic` 함수는 레지스터를 덤프하기 위해 다음 구조체를 받는다.

```c
struct panic_info {
    uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;
    uint32_t eip, eflags;
};
```

패닉으로 가는 경로는 두 가지다. 하나는 C 코드에서 패닉을 발생시키는 경우이고, 다른 하나는 인터럽트 핸들러의 진입 코드에서 발생시키는 경우다. 두 경로는 스택 모양이 다르지만, `panic` 함수는 `struct panic_info` 하나로 일관되게 처리한다. 그래서 호출하기 전에 두 경로 모두 구조체 형식에 맞게 패닉 프레임을 구성해야 한다.

C 코드에서는 `do_panic`을 사용한다. EFLAGS가 스택에 없어서 새로 넣고, 복귀 주소를 EIP 자리로 복사한다. 인터럽트 진입 코드에서는 `isr_panic`을 사용하는데, CPU가 이미 EIP와 EFLAGS를 넣어 두었기 때문에 복사한다. 그 뒤 두 경로 모두 범용 레지스터를 넣고, 저장된 esp 값을 패닉 진입 전 값으로 보정한다. 두 경로의 스택 모양은 아래 그림과 같다.

![do_panic과 isr_panic의 패닉 프레임](/assets/img/kfs/kfs-panic-frame.png)
_Panic frame of do_panic and isr_panic_

패닉 진입 코드: [src/kernel/panic.asm](https://github.com/zerone015/kfs/blob/master/src/kernel/panic.asm)

패닉 처리 코드: [src/kernel/panic.c](https://github.com/zerone015/kfs/blob/master/src/kernel/panic.c#L59)

## Software Interrupt

소프트웨어 인터럽트는 `int` 명령어로 명시적으로 발생시키는 인터럽트다. 대표적인 예가 인터럽트 방식의 시스템 콜로, IDT의 한 엔트리를 시스템 콜용 게이트로 사용한다. x86에는 더 빠른 시스템 콜 방법인 `sysenter`도 있다. `sysenter`는 진입할 커널 코드와 커널 스택 주소를 MSR에 미리 저장해 두고, IDT를 조회하거나 스택에 복귀 정보를 넣는 과정을 생략해서 더 빠르다. 내 커널은 인터럽트 방식 시스템 콜을 사용하고, 벡터는 0x80이다.

시스템 콜을 구현하려면 ABI가 필요하다. 시스템 콜 번호와 인자를 커널에 어떻게 전달하고, 반환값을 어떻게 돌려줄지 정해야 한다. 나는 리눅스 기반 libc를 포팅할 계획이었기 때문에 리눅스 x86의 ABI를 그대로 따랐다.

- **시스템 콜 번호:** `eax`
- **인자:** 순서대로 `ebx`, `ecx`, `edx`, `esi`, `edi`, `ebp`
- **반환값:** `eax`. 실패하면 음수 에러 코드를 반환한다.

현재 구현된 시스템 콜은 `exit`, `fork`, `waitpid`, `getpid`, `getuid`, `kill`, `signal`, `sigreturn`이고, 시스템 콜 번호도 리눅스 x86과 같다.

핸들러 코드: [src/kernel/syscall.asm](https://github.com/zerone015/kfs/blob/master/src/kernel/syscall.asm#L18)

분기 코드: [src/kernel/syscall.c](https://github.com/zerone015/kfs/blob/master/src/kernel/syscall.c#L499)