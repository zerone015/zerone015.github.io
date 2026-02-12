---
title: "AT/PS2 Keyboard Driver Source Analysis"
date: 2026-02-12 10:30:00 +0900
categories: [Linux, Driver]
tags: [keyboard, ps2, scancode]
---


## Module Parameters
---
드라이버 로딩 시 사용자가 설정할 수 있는 옵션들이다. `MODULE_PARM_DESC`는 `modinfo` 명령으로 확인할 수 있는 파라미터 설명을 정의한다.

### module_param_named Macro
```c
#define module_param_named(name, value, type, perm)			   \
	param_check_##type(name, &(value));				   \
	module_param_cb(name, &param_ops_##type, &value, perm);		   \
	__MODULE_PARM_TYPE(name, #type)
```

* **name:** 사용자에게 노출되는 파라미터 이름
* **value:** 실제로 값이 저장되는 변수
* **type:** 파라미터 타입
* **perm:** sysfs에서의 접근 권한

변수명과 사용자에게 보이는 이름을 다르게 할 수 있다. 예를 들어 `module_param_named(set, atkbd_set, int, 0)`는 내부적으로는 `atkbd_set` 변수를 사용하지만, 사용자는 `set`이라는 이름으로 접근한다.

### Scancode Set
```c
static int atkbd_set = 2;
module_param_named(set, atkbd_set, int, 0);
MODULE_PARM_DESC(set, "Select keyboard code set (2 = default, 3 = PS/2 native)");
```

부팅 시 키보드는 Set 2 스캔코드를 사용하도록 설정된다. Set 3은 Set 2 이후에 출시되었으나, i8042 컨트롤러가 Set 3에 대한 변환을 지원하지 않아 호환성이 낮다. 이러한 이유로 Set 3은 특수한 용도로만 사용된다.

### Keyboard Reset
```c
#if defined(__i386__) || defined(__x86_64__) || defined(__hppa__) || defined(__loongarch__)
static bool atkbd_reset;
#else
static bool atkbd_reset = true;
#endif
module_param_named(reset, atkbd_reset, bool, 0);
MODULE_PARM_DESC(reset, "Reset keyboard during initialization");
```

하드웨어에 `0xFF` 명령을 보내 자가진단(BAT)을 시키는 것을 리셋이라고 한다. 드라이버 초기화 시 수행할 수 있으나, 이 작업이 오래 걸리므로 현대 x86 시스템에서는 펌웨어가 이미 초기화했다고 가정하고 기본적으로 비활성화한다.

### Software Repeat
```c
static bool atkbd_softrepeat;
module_param_named(softrepeat, atkbd_softrepeat, bool, 0);
MODULE_PARM_DESC(softrepeat, "Use software keyboard repeat");
```

키를 길게 누를 때 반복 입력을 소프트웨어로 처리한다. 키보드마다 하드웨어 반복 속도가 제각각이라 타이머를 사용해 브레이크 코드가 올 때까지 주기적으로 이벤트를 발생시킨다.

### Software Raw Mode
```c
static bool atkbd_softraw = true;
module_param_named(softraw, atkbd_softraw, bool, 0);
MODULE_PARM_DESC(softraw, "Use software generated rawmode");
```

역사적인 이유로, 키보드에서 전달된 스캔코드는 i8042 컨트롤러에서 기본적으로 Set 1 스캔코드로 변환된다. 그러나 일부 소프트웨어는 변환되지 않은 원시 스캔코드 값을 필요로 한다. 이를 위해 커널은 해당 옵션을 제공한다.

### Legacy Features
```c
static bool atkbd_scroll;
module_param_named(scroll, atkbd_scroll, bool, 0);
MODULE_PARM_DESC(scroll, "Enable scroll-wheel on MS Office and similar keyboards");

static bool atkbd_extra;
module_param_named(extra, atkbd_extra, bool, 0);
MODULE_PARM_DESC(extra, "Enable extra LEDs and keys on IBM RapidAcces, EzKey and similar keyboards");

static bool atkbd_terminal;
module_param_named(terminal, atkbd_terminal, bool, 0);
MODULE_PARM_DESC(terminal, "Enable break codes on an IBM Terminal keyboard connected via AT/PS2");
```

2000년대 초반 특수 키보드들을 위한 옵션이다.

* **atkbd_scroll:** MS Office 키보드 등에 달린 휠을 지원한다.
* **atkbd_extra:** IBM RapidAccess, EzKey 등의 멀티미디어 키/LED를 지원한다.
* **atkbd_terminal:** 구형 IBM 터미널 키보드의 비정상적인 브레이크 코드를 처리한다.

## Key Mapping
---
```c
#define SCANCODE(keymap)  ((keymap >> 16) & 0xFFFF)
#define KEYCODE(keymap)   (keymap & 0xFFFF)
```

스캔코드와 키코드는 32비트 `keymap`에 각각 16비트씩 저장된다.

* **스캔코드:** 키보드 컨트롤러가 전송하는 하드웨어 종속적인 코드 (상위 16비트)
* **키코드:** 드라이버가 리눅스 커널 표준 방식으로 변환한 코드 (하위 16비트)
