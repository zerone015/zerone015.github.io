---
title: "nftable subsystem"
date: 2026-05-15 01:00:00 +0900
categories: [Linux Kernel]
tags: [netlink, nfnetlink, nftable]
---

드림핵에서 리눅스 커널 해킹 패스를 수강하면서 CVE-2022-34918 관련 강의를 보는데, nftable 서브시스템에 대한 기반 지식이 부족해서 제대로 이해하기 어려웠습니다. 그래서 CVE-2022-34918을 본격적으로 분석하기에 앞서 nftable에 대해 먼저 정리하고자 합니다.

이 글에서 다루는 범위는 유저 공간 프로그램에서 nftable에 접근하기 위해 netlink API를 사용하는 방법부터 커널 내부 흐름까지입니다. `nft` 명령어 사용법은 다루지 않으며, 이는 리눅스 매뉴얼 페이지에서 확인할 수 있습니다.

## netlink

netlink는 유저 공간과 커널이 서로 통신하기 위해 사용되는 인터페이스입니다. 유저 공간과 커널이 통신하는 또 다른 방법으로는 `ioctl`과 `/proc`이 있습니다. 이 방법들은 유저 공간에서 먼저 요청해야 커널이 응답하는 단방향 구조입니다. netlink는 소켓을 사용하는 양방향 통신으로, 커널이 유저 공간에 이벤트를 먼저 전송하는 것도 가능합니다.

## Netlink API 예제

아래는 netlink API를 사용하여 커널 모듈과 통신하는 예제 프로그램입니다.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_CUSTOM 31  // Custom netlink family for test
#define MAX_PAYLOAD 1024   // Max payload size

int main() 
{
    int sock_fd;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;

    // 1. Create Netlink socket
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_CUSTOM);
    if (sock_fd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // 2. Set source address and bind
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* User process PID */
    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

    // 3. Set destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;       /* 0 means Kernel */
    dest_addr.nl_groups = 0;    /* Unicast */

    // 4. Allocate memory for Netlink header and payload
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    // Write payload data right after the header
    strcpy(NLMSG_DATA(nlh), "Hello!");

    // 5. Setup iovec and msghdr for transmission
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;     // Destination address
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;                    // Message vector (Header + Payload)
    msg.msg_iovlen = 1;

    // 6. Send message to Kernel
    printf("Sending message to kernel...\n");
    sendmsg(sock_fd, &msg, 0);

    // 7. Wait for response from Kernel
    printf("Waiting for kernel response...\n");
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    recvmsg(sock_fd, &msg, 0);

    // 8. Print received message
    printf("Kernel response: %s\n", (char *)NLMSG_DATA(nlh));

    // Free resources
    close(sock_fd);
    free(nlh);

    return 0;
}
```

이 프로그램은 먼저 `socket()`을 호출하여 netlink 소켓을 생성합니다. netlink 소켓을 생성하려면 `socket()`의 첫 번째 인자가 `AF_NETLINK`이어야 하고, 두 번째 인자는 `SOCK_RAW` 혹은 `SOCK_DGRAM`이어야 합니다. 이 두 타입은 netlink 프로토콜에서 동일하게 취급됩니다. 세 번째 인자는 `netlink_family`로, 통신할 커널 서브시스템을 선택하는 데 사용됩니다. 이 예제는 테스트를 위해 예약되지 않은 여분의 `netlink_family`를 사용합니다.

이후 소켓에 주소를 바인드하기 위해 `struct sockaddr_nl`을 사용합니다.

```c
struct sockaddr_nl {
    sa_family_t     nl_family;  /* AF_NETLINK */
    unsigned short  nl_pad;     /* Zero */
    pid_t           nl_pid;     /* Port ID */
    __u32           nl_groups;  /* Multicast groups mask */
};
```

`nl_family`는 항상 `AF_NETLINK`이어야 하고 `nl_pad`는 사용되지 않는 필드입니다. `nl_pid`는 소켓을 식별하는 Port ID입니다. 값이 0이면 목적지가 커널임을 나타냅니다. 수신 측에서는 `bind()` 호출 전에 임의의 값을 지정하거나, 0으로 설정하여 커널에 위임할 수 있습니다. 직접 지정하는 경우 여러 소켓 간 값이 중복되지 않도록 주의해야 합니다. 커널에 위임하는 경우, 첫 번째 소켓에는 유저 프로세스 PID를 할당하고 이후 소켓에는 자동으로 고유한 값을 설정해줍니다.

`nl_groups`는 각 비트가 netlink 그룹 번호를 나타내는 비트 마스크입니다. 0이 아닌 경우 멀티캐스트로 전송하게 됩니다. 예를 들어, 두 번째 비트를 1로 설정하면 2번 그룹에 멀티캐스트로 메시지를 전송하고, 수신 측이라면 해당 그룹의 메시지를 구독하게 됩니다. 멀티캐스트 그룹에 전송하거나 구독하려면 `CAP_NET_ADMIN` 권한이 있거나 `euid`가 0이어야 합니다. 일부 서브시스템에는 예외가 있으나 여기서는 더 이상 다루지 않겠습니다.

바인드 이후에는 메시지를 전송하기 위해 여러 구조체를 세팅합니다. 먼저 `struct nlmsghdr`를 살펴보겠습니다.

```c
struct nlmsghdr {
    __u32 nlmsg_len;    /* Length of message including header */
    __u16 nlmsg_type;   /* Type of message content */
    __u16 nlmsg_flags;  /* Additional flags */
    __u32 nlmsg_seq;    /* Sequence number */
    __u32 nlmsg_pid;    /* Sender port ID */
};
```

netlink 메시지는 한 개 이상의 `nlmsghdr`와 페이로드의 바이트 스트림으로 구성됩니다. 여기서 바이트 스트림이란 `nlmsghdr`와 페이로드, 그리고 여러 메시지들이 메모리 상에서 연속적으로 배치된다는 의미입니다.

`nlmsg_len`은 헤더를 포함한 메시지의 전체 크기입니다. `nlmsg_type`은 메시지 유형을 나타내며, 표준 타입과 각 패밀리가 확장하여 사용하는 전용 타입으로 나뉩니다. 표준 타입은 다음 세 가지입니다.

```c
#define NLMSG_NOOP    0x1  /* Nothing.      */
#define NLMSG_ERROR   0x2  /* Error         */
#define NLMSG_DONE    0x3  /* End of a dump */
```

`NLMSG_NOOP`는 메시지를 무시해야 함을 의미하고, `NLMSG_ERROR`는 오류가 발생했음을 뜻하며 페이로드 위치에 `struct nlmsgerr`가 위치하게 됩니다. `NLMSG_DONE`는 여러 메시지 중 마지막 메시지임을 나타냅니다. 패밀리 전용 타입은 패밀리마다 다르며 보통 `GET`, `NEW`, `DEL` 중 하나로 시작하거나 끝납니다.

`nlmsg_flags`는 비트 플래그로, OR 연산으로 여러 개를 조합할 수 있습니다. 메시지 타입에 따라 표준, GET 요청, NEW 요청용으로 나뉩니다.

```c
/* Flags values */
#define NLM_F_REQUEST   0x01  /* It is request message.                */
#define NLM_F_MULTI     0x02  /* Multipart message, terminated by NLMSG_DONE */
#define NLM_F_ACK       0x04  /* Reply with ack, with zero or error code */
#define NLM_F_ECHO      0x08  /* Receive resulting notifications       */

/* Modifiers to GET request */
#define NLM_F_ROOT      0x100 /* specify tree root    */
#define NLM_F_MATCH     0x200 /* return all matching  */
#define NLM_F_ATOMIC    0x400 /* atomic GET           */
#define NLM_F_DUMP      (NLM_F_ROOT|NLM_F_MATCH)

/* Modifiers to NEW request */
#define NLM_F_REPLACE   0x100 /* Override existing        */
#define NLM_F_EXCL      0x200 /* Do not touch, if it exists */
#define NLM_F_CREATE    0x400 /* Create, if it does not exist */
#define NLM_F_APPEND    0x800 /* Add to end of list       */
```

`NLM_F_REQUEST`는 유저 공간에서 커널로 전송되는 메시지라면 반드시 포함해야 하는 플래그입니다. `NLM_F_ACK`는 신뢰성 있는 전송을 위해 사용됩니다. netlink는 메모리 부족 등의 상황에서 메시지가 유실될 수 있는데, 이를 확인하려면 수신 측이 확인 응답을 해주어야 합니다. `NLM_F_ACK` 플래그를 설정하면 커널은 오류가 없는 경우에도 `NLMSG_ERROR` 메시지에 `error` 필드를 0으로 설정하여 응답해줍니다.

`nlmsg_seq`와 `nlmsg_pid`는 메시지를 식별하기 위해 사용됩니다. `nlmsg_pid`는 송신자의 포트 ID이고, `nlmsg_seq`는 메시지의 순서를 식별하는 데 주로 사용됩니다. 이 두 필드는 커널이 라우팅에 사용하지 않는 값입니다.

netlink 메시지를 다룰 때 사용이 강력히 권장되는 매크로들도 있습니다.

```c
#define NLMSG_ALIGNTO   4U

#define NLMSG_ALIGN(len)    ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_HDRLEN        ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len)   ((len) + NLMSG_HDRLEN)
#define NLMSG_SPACE(len)    NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NLMSG_DATA(nlh)     ((void *)(((char *)nlh) + NLMSG_HDRLEN))
#define NLMSG_NEXT(nlh,len) ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
                             (struct nlmsghdr *)(((char *)(nlh)) + \
                             NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh,len)   ((len) >= (int)sizeof(struct nlmsghdr) && \
                             (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
                             (nlh)->nlmsg_len <= (len))
#define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))
```

가장 자주 쓰이는 것은 `NLMSG_SPACE`와 `NLMSG_DATA`입니다. `NLMSG_SPACE`는 netlink 메시지 할당 크기를 구할 때, `NLMSG_DATA`는 페이로드 시작 위치를 구할 때 사용합니다.

이제 `sendmsg`에서 사용되는 `struct msghdr`를 살펴보겠습니다.

```c
struct msghdr {
    void         *msg_name;       /* Optional address */
    socklen_t     msg_namelen;    /* Size of address */
    struct iovec *msg_iov;        /* Scatter/gather array */
    size_t        msg_iovlen;     /* # elements in msg_iov */
    void         *msg_control;    /* Ancillary data, see below */
    size_t        msg_controllen; /* Ancillary data buffer len */
    int           msg_flags;      /* Flags (unused) */
};
```

`msg_name`과 `msg_namelen`은 비연결형 소켓에서 목적지 주소를 지정할 때 사용됩니다. UDP나 netlink 소켓처럼 비연결형인 경우 목적지 주소가 필요하지만, TCP처럼 연결 지향인 경우 이미 연결 과정에서 목적지 정보가 커널에 저장되므로 이 두 필드를 NULL, 0으로 설정해야 합니다.

`msg_flags`는 사용되지 않는 필드이고, `msg_control`과 `msg_controllen`은 보조 데이터(ancillary data)에 대한 필드입니다.

`msg_iov`는 메시지들을 담는 `struct iovec` 배열의 주소이고, `msg_iovlen`은 배열 원소 개수입니다.

```c
struct iovec {
    void   *iov_base;  /* Starting address */
    size_t  iov_len;   /* Size of the memory pointed to by iov_base. */
};
```

`iov_base`는 메모리 영역의 시작 주소, `iov_len`은 그 크기를 나타냅니다. 이 구조체는 개별적으로 흩어져 있는 메모리 영역들을 하나로 묶어 단 한 번의 시스템 콜로 전달하기 위해 사용됩니다. 예제 프로그램에서는 `struct nlmsghdr` 객체의 시작 주소와 크기가 여기에 저장됩니다.

예제 프로그램은 할당되지 않은 netlink 패밀리를 사용하므로, 실행 전에 아래의 커널 모듈을 먼저 적재해야 합니다.

```c
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("yoson");
MODULE_DESCRIPTION("custom netlink test module");

#define NETLINK_CUSTOM 31

struct sock *nl_sk = NULL;

static void recv_msg(struct sk_buff *skb_in)
{
    struct nlmsghdr *nlh_in, *nlh_out;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    char *user_msg;
    int res;

    nlh_in = (struct nlmsghdr *)skb_in->data;
    user_msg = (char *)nlmsg_data(nlh_in);
    
    pr_info("netlink received from user: %s\n", user_msg);
    
    pid = nlh_in->nlmsg_pid;
    msg_size = strlen(user_msg) + 1;

    skb_out = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb_out) {
        pr_err("failed to allocate new skb\n");
        return;
    }

    nlh_out = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; 
    
    strncpy(nlmsg_data(nlh_out), user_msg, msg_size);

    res = netlink_unicast(nl_sk, skb_out, pid, MSG_DONTWAIT);
    if (res < 0) {
        pr_err("error while echoing back to user\n");
    }
}

static int __init hello_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = recv_msg, 
    };

    pr_info("loading custom netlink module...\n");

    nl_sk = netlink_kernel_create(&init_net, NETLINK_CUSTOM, &cfg);
    if (!nl_sk) {
        pr_err("error creating socket\n");
        return -ENOMEM;
    }

    return 0;
}

static void __exit hello_exit(void)
{
    pr_info("unloading custom netlink module...\n");   
    if (nl_sk) {
        netlink_kernel_release(nl_sk);
    }
}

module_init(hello_init);
module_exit(hello_exit);
```

이 커널 모듈은 적재될 때 커스텀 netlink 패밀리와 콜백 함수를 커널에 등록합니다. 이후 유저 공간에서 해당 패밀리로 메시지를 보내오면 등록한 콜백 함수가 호출됩니다. 이 콜백 함수는 수신한 메시지를 그대로 다시 유저 공간으로 돌려보내는 역할을 합니다.

## sendmsg 시스템 콜의 커널 내부 처리

이제 유저 공간에서 `sendmsg`를 호출했을 때 커널 내부에서 어떻게 처리되는지 호출 순서대로 살펴보겠습니다. 분석 대상 커널 버전은 5.18.9입니다.

### `__sys_sendmsg`

```c
long __sys_sendmsg(int fd, struct user_msghdr __user *msg, unsigned int flags,
                   bool forbid_cmsg_compat)
{
    int fput_needed, err;
    struct msghdr msg_sys;
    struct socket *sock;

    if (forbid_cmsg_compat && (flags & MSG_CMSG_COMPAT))                // (0)
        return -EINVAL;

    sock = sockfd_lookup_light(fd, &err, &fput_needed);                 // (1)
    if (!sock)
        goto out;

    err = ___sys_sendmsg(sock, msg, &msg_sys, flags, NULL, 0);          // (2)

    fput_light(sock->file, fput_needed);                                // (3)
out:
    return err;
}

SYSCALL_DEFINE3(sendmsg, int, fd, struct user_msghdr __user *, msg, unsigned int, flags)
{
    return __sys_sendmsg(fd, msg, flags, true);
}
```

유저 공간에서 `sendmsg` 시스템 콜을 호출하면 공통 진입 프로시저를 거친 뒤 `__sys_sendmsg`가 호출됩니다.

(0)에서는 비정상적인 호출을 감지합니다. 이 함수는 64비트 프로그램 전용이며, `MSG_CMSG_COMPAT` 플래그는 `CONFIG_COMPAT` 옵션이 켜진 상태에서 32비트 프로그램일 때만 사용됩니다. 따라서 정상적인 흐름에서 해당 조건문이 참이 되는 경우는 없습니다.

(1)에서 `sockfd_lookup_light`가 호출됩니다.

#### `sockfd_lookup_light`

```c
static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
    struct fd f = fdget(fd);                            // (4)
    struct socket *sock;

    *err = -EBADF;
    if (f.file) {
        sock = sock_from_file(f.file);                  // (5)
        if (likely(sock)) {
            *fput_needed = f.flags & FDPUT_FPUT;
            return sock;
        }
        *err = -ENOTSOCK;
        fdput(f);                                       // (6)
    }
    return NULL;
}
```

(4)의 `fdget`은 유저 공간에서 넘어온 정수 `fd`로 open fd table에서 `struct file`을 찾아 참조 카운트를 증가시킨 뒤, 이 구조체와 플래그를 포함하는 `struct fd`로 만들어 반환합니다. 즉, 파일 정보가 담긴 구조체를 가져오는 것입니다.

이후 (5)에서 `sock_from_file`이 호출됩니다.

```c
struct socket *sock_from_file(struct file *file)
{
    if (file->f_op == &socket_file_ops)
        return file->private_data;  /* set in sock_map_fd */

    return NULL;
}
```

파일이 소켓 파일인지 검사하여 맞으면 `struct socket`의 주소를, 아니면 NULL을 반환합니다. `struct socket`은 유저 공간에서 `socket()`을 호출할 때 생성되어 `file->private_data`에 저장됩니다.

`sock_from_file`이 반환된 후, 파일이 소켓 파일이 맞다면 나중에 참조 카운트를 감소시킬 수 있도록 표시한 뒤 `struct socket` 주소를 반환합니다. 아니라면 (6)에서 증가시켰던 `struct file`의 참조 카운트를 즉시 감소시키고 NULL을 반환합니다.

`__sys_sendmsg`로 돌아오면, (2)에서 본격적인 작업을 수행하는 `___sys_sendmsg`가 호출됩니다. 이후 (3)에서 참조 카운트를 감소시키고 결과를 반환합니다.

### `___sys_sendmsg`

```c
static int ___sys_sendmsg(struct socket *sock, struct user_msghdr __user *msg,
                          struct msghdr *msg_sys, unsigned int flags,
                          struct used_address *used_address,
                          unsigned int allowed_msghdr_flags)
{
    struct sockaddr_storage address;
    struct iovec iovstack[UIO_FASTIOV], *iov = iovstack;                // (0)
    ssize_t err;

    msg_sys->msg_name = &address;

    err = sendmsg_copy_msghdr(msg_sys, msg, flags, &iov);               // (1)
    if (err < 0)
        return err;

    err = ____sys_sendmsg(sock, msg_sys, flags, used_address,           // (2)
                          allowed_msghdr_flags);
    kfree(iov);
    return err;
}
```

(0)의 `iovstack` 배열은 최적화 용도로, 이후 단계에서 설명합니다. (1)은 유저 공간의 `struct user_msghdr`를 커널 공간으로 안전하게 복사하여 `struct msghdr`로 파싱하고, `iovec`를 `struct iov_iter`로 파싱하는 함수입니다. `struct iov_iter`는 커널 내부에서 다양한 메모리 버퍼들을 단일 인터페이스로 다룰 수 있도록 설계된 구조체입니다. (2)는 이후 단계의 작업을 담당하는 함수입니다.

먼저 `sendmsg_copy_msghdr`를 살펴보겠습니다.

```c
int sendmsg_copy_msghdr(struct msghdr *msg,
                        struct user_msghdr __user *umsg, unsigned flags,
                        struct iovec **iov)
{
    int err;

    if (flags & MSG_CMSG_COMPAT) {
        struct compat_msghdr __user *msg_compat;

        msg_compat = (struct compat_msghdr __user *) umsg;
        err = get_compat_msghdr(msg, msg_compat, NULL, iov);
    } else {
        err = copy_msghdr_from_user(msg, umsg, NULL, iov);              // (0)
    }
    if (err < 0)
        return err;

    return 0;
}
```

64비트 프로그램이므로 (0)이 실행됩니다.

```c
static int copy_msghdr_from_user(struct msghdr *kmsg,
                                 struct user_msghdr __user *umsg,
                                 struct sockaddr __user **save_addr,
                                 struct iovec **iov)
{
    struct user_msghdr msg;
    ssize_t err;

    err = __copy_msghdr_from_user(kmsg, umsg, save_addr, &msg.msg_iov,  // (1)
                                  &msg.msg_iovlen);
    if (err)
        return err;

    err = import_iovec(save_addr ? READ : WRITE,                         // (2)
                       msg.msg_iov, msg.msg_iovlen,
                       UIO_FASTIOV, iov, &kmsg->msg_iter);
    return err < 0 ? err : 0;
}
```

(1)에서 유저 공간의 `struct user_msghdr`를 커널 공간으로 복사하고 `struct msghdr`로 파싱합니다. (2)에서 유저 공간의 `struct iovec` 배열을 커널 공간으로 복사한 뒤 `struct iov_iter`로 파싱합니다.

`__copy_msghdr_from_user`를 살펴보기 전에 `struct msghdr`와 `struct user_msghdr`의 차이를 짚어보겠습니다.

```c
struct msghdr {
    void            *msg_name;
    int              msg_namelen;
    struct iov_iter  msg_iter;          /* 유저의 msg_iov, msg_iovlen 통합 */

    union {
        void        *msg_control;
        void __user *msg_control_user;
    };
    bool             msg_control_is_user : 1;
    __kernel_size_t  msg_controllen;
    unsigned int     msg_flags;
    struct kiocb    *msg_iocb;          /* 비동기 요청용 필드 추가 */
};

struct user_msghdr {
    void            __user *msg_name;
    int              msg_namelen;
    struct iovec    __user *msg_iov;
    __kernel_size_t  msg_iovlen;
    void            __user *msg_control;
    __kernel_size_t  msg_controllen;
    unsigned int     msg_flags;
};
```

유저 공간의 `msg_iov`, `msg_iovlen`이 커널 내부에서는 `msg_iter`로 통합되었습니다. 또한 커널 내부 전용 보조 데이터를 위한 필드와 비동기 요청에서 사용되는 `msg_iocb` 필드가 추가되었습니다. 이제 `__copy_msghdr_from_user`를 살펴보겠습니다.

```c
int __copy_msghdr_from_user(struct msghdr *kmsg,
                            struct user_msghdr __user *umsg,
                            struct sockaddr __user **save_addr,
                            struct iovec __user **uiov, size_t *nsegs)
{
    struct user_msghdr msg;
    ssize_t err;

    if (copy_from_user(&msg, umsg, sizeof(*umsg)))                      // (0)
        return -EFAULT;

    kmsg->msg_control_is_user = true;
    kmsg->msg_control_user = msg.msg_control;
    kmsg->msg_controllen = msg.msg_controllen;
    kmsg->msg_flags = msg.msg_flags;

    kmsg->msg_namelen = msg.msg_namelen;
    if (!msg.msg_name)
        kmsg->msg_namelen = 0;

    if (kmsg->msg_namelen < 0)
        return -EINVAL;

    if (kmsg->msg_namelen > sizeof(struct sockaddr_storage))
        kmsg->msg_namelen = sizeof(struct sockaddr_storage);

    if (save_addr)
        *save_addr = msg.msg_name;

    if (msg.msg_name && kmsg->msg_namelen) {
        if (!save_addr) {
            err = move_addr_to_kernel(msg.msg_name,                     // (1)
                                      kmsg->msg_namelen,
                                      kmsg->msg_name);
            if (err < 0)
                return err;
        }
    } else {
        kmsg->msg_name = NULL;
        kmsg->msg_namelen = 0;
    }

    if (msg.msg_iovlen > UIO_MAXIOV)
        return -EMSGSIZE;

    kmsg->msg_iocb = NULL;
    *uiov = msg.msg_iov;
    *nsegs = msg.msg_iovlen;
    return 0;
}
```

파싱 전 (0)에서 커널 공간으로 안전하게 복사해옵니다. 이후 입력 값을 검증하며 파싱합니다. netlink나 UDP 같은 비연결 지향 소켓으로 전송하는 경우 `msg_name`과 `msg_namelen`이 있으므로 (1)에서 주소를 복사합니다. `save_addr`는 `recvmsg`에서만 사용되며, `sendmsg`에서는 항상 `save_addr == NULL`입니다.

```c
int move_addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr_storage *kaddr)
{
    if (ulen < 0 || ulen > sizeof(struct sockaddr_storage))
        return -EINVAL;
    if (ulen == 0)
        return 0;
    if (copy_from_user(kaddr, uaddr, ulen))                             // (0)
        return -EFAULT;
    return audit_sockaddr(ulen, kaddr);                                 // (1)
}
```

(0)에서 주소 데이터를 안전하게 복사해오고, (1)에서 `CONFIG_AUDITSYSCALL` 옵션이 켜진 경우 현재 태스크의 `audit_context->sockaddr`에 주소 데이터를 복사합니다.

이제 `copy_msghdr_from_user`로 돌아가서 `import_iovec`를 살펴보겠습니다.

```c
ssize_t __import_iovec(int type, const struct iovec __user *uvec,
                       unsigned nr_segs, unsigned fast_segs, struct iovec **iovp,
                       struct iov_iter *i, bool compat)
{
    ssize_t total_len = 0;
    unsigned long seg;
    struct iovec *iov;

    iov = iovec_from_user(uvec, nr_segs, fast_segs, *iovp, compat);    // (0)
    if (IS_ERR(iov)) {
        *iovp = NULL;
        return PTR_ERR(iov);
    }

    for (seg = 0; seg < nr_segs; seg++) {                               // (1)
        ssize_t len = (ssize_t)iov[seg].iov_len;

        if (!access_ok(iov[seg].iov_base, len)) {
            if (iov != *iovp)
                kfree(iov);
            *iovp = NULL;
            return -EFAULT;
        }

        if (len > MAX_RW_COUNT - total_len) {
            len = MAX_RW_COUNT - total_len;
            iov[seg].iov_len = len;
        }
        total_len += len;
    }

    iov_iter_init(i, type, iov, nr_segs, total_len);                    // (2)
    if (iov == *iovp)
        *iovp = NULL;
    else
        *iovp = iov;
    return total_len;
}

ssize_t import_iovec(int type, const struct iovec __user *uvec,
                     unsigned nr_segs, unsigned fast_segs,
                     struct iovec **iovp, struct iov_iter *i)
{
    return __import_iovec(type, uvec, nr_segs, fast_segs, iovp, i,
                          in_compat_syscall());
}
```

(0)에서 유저 공간의 `struct iovec` 배열을 커널 공간으로 복사해옵니다. (1)에서 각 iovec의 메모리 영역 크기를 검사하고 필요시 잘라내어 전체 크기의 합산을 구한 뒤, (2)에서 `struct iov_iter`로 파싱합니다.

`iovec_from_user`를 살펴보겠습니다.

```c
struct iovec *iovec_from_user(const struct iovec __user *uvec,
                              unsigned long nr_segs, unsigned long fast_segs,
                              struct iovec *fast_iov, bool compat)
{
    struct iovec *iov = fast_iov;
    int ret;

    if (nr_segs == 0)
        return iov;
    if (nr_segs > UIO_MAXIOV)
        return ERR_PTR(-EINVAL);
    if (nr_segs > fast_segs) {                                          // (0)
        iov = kmalloc_array(nr_segs, sizeof(struct iovec), GFP_KERNEL);
        if (!iov)
            return ERR_PTR(-ENOMEM);
    }

    if (compat)
        ret = copy_compat_iovec_from_user(iov, uvec, nr_segs);
    else
        ret = copy_iovec_from_user(iov, uvec, nr_segs);                 // (1)
    if (ret) {
        if (iov != fast_iov)
            kfree(iov);
        return ERR_PTR(ret);
    }

    return iov;
}
```

`fast_segs`는 `import_iovec` 호출 시 `UIO_FASTIOV`로 전달되었으며, `fast_iov`는 `___sys_sendmsg`에서 지역 변수로 할당된 `iovstack`입니다. (0)에서 `struct iovec`의 개수가 `UIO_FASTIOV`를 초과하면 동적 할당하고, 그렇지 않으면 `fast_iov`를 재사용하여 오버헤드를 줄입니다. (1)에서 유저 공간의 `uvec` 배열을 커널 공간으로 복사합니다.

`__import_iovec`로 돌아가서, (2)에서 호출되는 `iov_iter_init`를 살펴보겠습니다.

```c
void iov_iter_init(struct iov_iter *i, unsigned int direction,
                   const struct iovec *iov, unsigned long nr_segs,
                   size_t count)
{
    WARN_ON(direction & ~(READ | WRITE));
    *i = (struct iov_iter) {
        .iter_type  = ITER_IOVEC,
        .nofault    = false,
        .data_source = direction,
        .iov        = iov,
        .nr_segs    = nr_segs,
        .iov_offset = 0,
        .count      = count
    };
}
```

`struct iovec` 배열을 `struct iov_iter`로 래핑합니다. 이 `struct iov_iter`는 이후 `struct msghdr`에 저장됩니다.

### `____sys_sendmsg`

```c
static int ____sys_sendmsg(struct socket *sock, struct msghdr *msg_sys,
                           unsigned int flags, struct used_address *used_address,
                           unsigned int allowed_msghdr_flags)
{
    unsigned char ctl[sizeof(struct cmsghdr) + 20]                      // (0)
                __aligned(sizeof(__kernel_size_t));
    /* 20 is size of ipv6_pktinfo */
    unsigned char *ctl_buf = ctl;
    int ctl_len;
    ssize_t err;

    err = -ENOBUFS;

    if (msg_sys->msg_controllen > INT_MAX)
        goto out;
    flags |= (msg_sys->msg_flags & allowed_msghdr_flags);
    ctl_len = msg_sys->msg_controllen;
    if ((MSG_CMSG_COMPAT & flags) && ctl_len) {
        err = cmsghdr_from_user_compat_to_kern(msg_sys, sock->sk, ctl,  // (1)
                                               sizeof(ctl));
        if (err)
            goto out;
        ctl_buf = msg_sys->msg_control;
        ctl_len = msg_sys->msg_controllen;
    } else if (ctl_len) {
        BUILD_BUG_ON(sizeof(struct cmsghdr) !=
                     CMSG_ALIGN(sizeof(struct cmsghdr)));
        if (ctl_len > sizeof(ctl)) {                                    // (2)
            ctl_buf = sock_kmalloc(sock->sk, ctl_len, GFP_KERNEL);
            if (ctl_buf == NULL)
                goto out;
        }
        err = -EFAULT;
        if (copy_from_user(ctl_buf, msg_sys->msg_control_user, ctl_len))
            goto out_freectl;
        msg_sys->msg_control = ctl_buf;
        msg_sys->msg_control_is_user = false;
    }
    msg_sys->msg_flags = flags;

    if (sock->file->f_flags & O_NONBLOCK)
        msg_sys->msg_flags |= MSG_DONTWAIT;

    if (used_address && msg_sys->msg_name &&                            // (3)
        used_address->name_len == msg_sys->msg_namelen &&
        !memcmp(&used_address->name, msg_sys->msg_name,
                used_address->name_len)) {
        err = sock_sendmsg_nosec(sock, msg_sys);
        goto out_freectl;
    }
    err = sock_sendmsg(sock, msg_sys);                                  // (4)

    if (used_address && err >= 0) {                                     // (5)
        used_address->name_len = msg_sys->msg_namelen;
        if (msg_sys->msg_name)
            memcpy(&used_address->name, msg_sys->msg_name,
                   used_address->name_len);
    }

out_freectl:
    if (ctl_buf != ctl)
        sock_kfree_s(sock->sk, ctl_buf, ctl_len);
out:
    return err;
}
```

(0)의 `ctl` 배열은 `___sys_sendmsg`의 `iovstack`과 마찬가지로 최적화 용도입니다. 보조 데이터가 더 큰 버퍼를 요구하는 경우 (1) 또는 (2)에서 동적 할당됩니다. (1)은 호환 모드이면서 보조 데이터가 있는 경우, (2)는 보조 데이터가 있지만 호환 모드가 아닌 경우 실행됩니다. 보조 데이터에 관해서는 여기서 다루지 않겠습니다.

(3)은 `sendmmsg`에서 호출된 경우, 목적지 주소가 이전 요청의 주소와 동일하고 그 요청이 성공했을 때 보안 검사를 건너뛰는 코드입니다. `sendmsg`에서 호출된 경우에는 (4)가 실행됩니다. (5)는 (3)에서 사용할 현재 주소 정보를 보관하는 코드입니다.

#### `sock_sendmsg`

```c
int sock_sendmsg(struct socket *sock, struct msghdr *msg)
{
    int err = security_socket_sendmsg(sock, msg,                        // (0)
                                      msg_data_left(msg));

    return err ?: sock_sendmsg_nosec(sock, msg);                        // (1)
}
```

(0)은 `CONFIG_SECURITY_NETWORK` 옵션이 설정된 경우 `call_int_hook`을 통해 LSM(Linux Security Module)이 등록한 훅 함수들을 호출하여 보안 검사를 수행합니다. 통과하면 (1)에서 실제 전송 함수가 호출됩니다.

```c
static inline int sock_sendmsg_nosec(struct socket *sock, struct msghdr *msg)
{
    int ret = INDIRECT_CALL_INET(sock->ops->sendmsg, inet6_sendmsg,     // (0)
                                 inet_sendmsg, sock, msg,
                                 msg_data_left(msg));
    BUG_ON(ret == -EIOCBQUEUED);                                        // (1)
    return ret;
}
```

(0)은 retpoline으로 인한 오버헤드를 최소화하기 위한 처리입니다. inet6 또는 inet 도메인인 경우 간접 점프 없이 직접 점프합니다. 결국 `sock->ops->sendmsg`에 저장된 함수가 호출되는데, 이 값은 소켓 생성 시 초기화됩니다. netlink 도메인의 경우 `netlink_sendmsg`로 초기화되므로, 최종적으로 `netlink_sendmsg(sock, msg, msg_data_left(msg))`가 호출됩니다.

```c
static inline size_t msg_data_left(struct msghdr *msg)
{
    return iov_iter_count(&msg->msg_iter);
}
```

`msg->msg_iter.count`는 `iov_iter_init`에서 초기화된 값으로, `__import_iovec`에서 구한 iovec들의 메모리 영역 크기의 합산입니다.

### `netlink_sendmsg`

이제 netlink 계층으로 넘어옵니다.

```c
static int netlink_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
    struct sock *sk = sock->sk;
    struct netlink_sock *nlk = nlk_sk(sk);
    DECLARE_SOCKADDR(struct sockaddr_nl *, addr, msg->msg_name);
    u32 dst_portid;
    u32 dst_group;
    struct sk_buff *skb;
    int err;
    struct scm_cookie scm;
    u32 netlink_skb_flags = 0;

    if (msg->msg_flags & MSG_OOB)                                       // (0)
        return -EOPNOTSUPP;

    if (len == 0) {
        pr_warn_once("Zero length message leads to an empty skb\n");
        return -ENODATA;
    }

    err = scm_send(sock, msg, &scm, true);                              // (1)
    if (err < 0)
        return err;

    if (msg->msg_namelen) {                                             // (2)
        err = -EINVAL;
        if (msg->msg_namelen < sizeof(struct sockaddr_nl))
            goto out;
        if (addr->nl_family != AF_NETLINK)
            goto out;
        dst_portid = addr->nl_pid;
        dst_group = ffs(addr->nl_groups);
        err = -EPERM;
        if ((dst_group || dst_portid) &&
            !netlink_allowed(sock, NL_CFG_F_NONROOT_SEND))
            goto out;
        netlink_skb_flags |= NETLINK_SKB_DST;
    } else {
        dst_portid = nlk->dst_portid;
        dst_group = nlk->dst_group;
    }

    /* Paired with WRITE_ONCE() in netlink_insert() */
    if (!READ_ONCE(nlk->bound)) {                                       // (3)
        err = netlink_autobind(sock);
        if (err)
            goto out;
    } else {
        smp_rmb();
    }

    err = -EMSGSIZE;
    if (len > sk->sk_sndbuf - 32)
        goto out;
    err = -ENOBUFS;
    skb = netlink_alloc_large_skb(len, dst_group);                      // (4)
    if (skb == NULL)
        goto out;

    NETLINK_CB(skb).portid    = nlk->portid;
    NETLINK_CB(skb).dst_group = dst_group;
    NETLINK_CB(skb).creds     = scm.creds;
    NETLINK_CB(skb).flags     = netlink_skb_flags;

    err = -EFAULT;
    if (memcpy_from_msg(skb_put(skb, len), msg, len)) {                 // (5)
        kfree_skb(skb);
        goto out;
    }

    err = security_netlink_send(sk, skb);                               // (6)
    if (err) {
        kfree_skb(skb);
        goto out;
    }

    if (dst_group) {
        refcount_inc(&skb->users);
        netlink_broadcast(sk, skb, dst_portid, dst_group, GFP_KERNEL);
    }
    err = netlink_unicast(sk, skb, dst_portid,                          // (7)
                          msg->msg_flags & MSG_DONTWAIT);

out:
    scm_destroy(&scm);
    return err;
}
```

(0)에서 `MSG_OOB`(긴급 패킷) 플래그는 netlink에서 지원되지 않으므로 거부합니다. 이후 길이를 검사하고 (1)에서 `scm_send`가 호출됩니다. 이 함수는 `struct scm_cookie`를 설정하는 데 사용되며, 소켓 계층에서 자격 증명, 보안, 보조 데이터 처리를 위해 쓰입니다.

(2)에서 유효성을 확인하고 이후 전송을 위해 `portid`와 `group`을 저장합니다. (3)은 유저 공간에서 `bind` 없이 곧바로 메시지를 전송한 경우 커널이 자동으로 바인드해주는 처리입니다. 매뉴얼에는 `pid`를 0으로 설정하고 `bind`를 호출하면 자동 바인드된다고 되어 있지만, 코드를 보면 `bind` 호출 자체를 생략해도 자동으로 처리됩니다. 따라서 전송만 할 목적이라면 `bind`를 생략하여 시스템 콜을 1회 줄일 수 있습니다.

(4)에서 메시지를 담을 소켓 버퍼를 할당합니다. 직후 사용되는 `NETLINK_CB` 매크로를 살펴보겠습니다.

```c
struct netlink_skb_parms {
    struct scm_creds  creds;
    __u32             portid;
    __u32             dst_group;
    __u32             flags;
    struct sock      *sk;
    bool              nsid_is_set;
    int               nsid;
};

#define NETLINK_CB(skb) (*(struct netlink_skb_parms*)&((skb)->cb))
```

소켓 버퍼의 `cb` 필드를 `struct netlink_skb_parms`로 캐스팅하여 접근하는 매크로입니다. `cb` 필드는 각 네트워크 계층에서 자유롭게 사용할 수 있는 휘발성 제어 버퍼입니다. 여기서는 portid, group, 자격 증명, flags를 저장합니다.

(5)에서 `struct iov_iter`를 통해 유저 공간의 메시지를 소켓 버퍼로 복사합니다. `struct iov_iter`에 래핑된 `struct iovec` 배열 자체는 이미 커널 공간에 있지만, 각 원소가 가리키는 실제 데이터는 아직 유저 공간에 있으므로 여기서 복사가 이루어집니다. (6)에서 LSM 보안 검사를 수행하고, (7)에서 목적지로 유니캐스트 전송합니다. 목적지 그룹이 지정된 경우에는 멀티캐스트 전송이 먼저 수행됩니다. 멀티캐스트 전송은 여기서 다루지 않겠습니다. 이제 `netlink_unicast` 함수를 살펴보겠습니다.

```c
int netlink_unicast(struct sock *ssk, struct sk_buff *skb,
		    u32 portid, int nonblock)
{
	struct sock *sk;
	int err;
	long timeo;

	skb = netlink_trim(skb, gfp_any());                 // (0)

	timeo = sock_sndtimeo(ssk, nonblock);               // (1)
retry:
	sk = netlink_getsockbyportid(ssk, portid);          // (2)
	if (IS_ERR(sk)) {
		kfree_skb(skb);
		return PTR_ERR(sk);
	}
	if (netlink_is_kernel(sk))
		return netlink_unicast_kernel(sk, skb, ssk);    // (3)

	if (sk_filter(sk, skb)) {
		err = skb->len;
		kfree_skb(skb);
		sock_put(sk);
		return err;
	}

	err = netlink_attachskb(sk, skb, &timeo, ssk);
	if (err == 1)
		goto retry;
	if (err)
		return err;

	return netlink_sendskb(sk, skb);
}
```

(0)은 할당한 소켓 버퍼 크기가 과한 경우 메모리 낭비를 막기 위해 줄이는 함수입니다. 유저 공간에서 전송한 경우에는 이미 메시지 크기를 알고 있으므로 해당되지 않습니다. (1)은 송신자가 차단될 때의 타임아웃입니다. `setsockopt`로 타임아웃 시간을 지정하지 않은 이상 무한정 차단되며, 커널로 전송할 때는 차단될 일이 없으므로 해당되지 않습니다. 이후 (2)에서 수신자 portid에 해당하는 `sock` 구조체를 찾아서 (3)에서 커널로 유니캐스트 전송합니다. 먼저 `netlink_getsockbyportid` 함수를 살펴보겠습니다.

```c
static struct sock *netlink_getsockbyportid(struct sock *ssk, u32 portid)
{
	struct sock *sock;
	struct netlink_sock *nlk;

	sock = netlink_lookup(sock_net(ssk), ssk->sk_protocol, portid);             // (0)
	if (!sock)
		return ERR_PTR(-ECONNREFUSED);

	/* Don't bother queuing skb if kernel socket has no input function */
	nlk = nlk_sk(sock);
	if (sock->sk_state == NETLINK_CONNECTED &&                                  // (1)
	    nlk->dst_portid != nlk_sk(ssk)->portid) {
		sock_put(sock);
		return ERR_PTR(-ECONNREFUSED);
	}
	return sock;
}
```

(0)에서 동일한 네트워크 네임스페이스 내에서 동일한 프로토콜을 사용하는 수신자의 소켓 구조체를 portid로 찾아냅니다. (1)은 `connect`로 송수신자가 서로 고정된 경우, 다른 소켓이 송신하면 연결을 거부하기 위한 검사입니다. 이제 `netlink_unicast_kernel` 함수를 살펴보겠습니다.

```c
static int netlink_unicast_kernel(struct sock *sk, struct sk_buff *skb,
				  struct sock *ssk)
{
	int ret;
	struct netlink_sock *nlk = nlk_sk(sk);

	ret = -ECONNREFUSED;
	if (nlk->netlink_rcv != NULL) {                         // (0)
		ret = skb->len;
		netlink_skb_set_owner_r(skb, sk);                   // (1)
		NETLINK_CB(skb).sk = ssk;                           // (2)
		netlink_deliver_tap_kernel(sk, ssk, skb);           // (3)
		nlk->netlink_rcv(skb);                              // (4)
		consume_skb(skb);
	} else {
		kfree_skb(skb);
	}
	sock_put(sk);
	return ret;
}
```

`struct netlink_sock`의 `netlink_rcv` 필드는 앞서 살펴본 커널 모듈 예제의 초기화 함수에서 `netlink_kernel_create`를 호출할 때 등록한 콜백 함수가 저장되는 필드입니다. (0)에서 수신 콜백 함수가 등록되어 있지 않은 경우 패킷을 조용히 버립니다. 등록된 경우, (1)에서 소켓 버퍼를 수신자의 소켓으로 완전히 귀속시키고, (2)에서 송신자 소켓 정보도 저장합니다. (3)은 netlink 메시지를 모니터링하는 `nlmon` 같은 가상 네트워크 장치에 전달하기 위해 사용됩니다. (4)에서 해당 netlink 패밀리의 수신 콜백 함수를 호출하여 메시지를 처리한 뒤 소켓 버퍼와 소켓을 정리합니다.

## nfnetlink

nfnetlink는 유저 공간에서 netlink를 통해 nftables에 접근하기 위한 인터페이스입니다. nfnetlink는 메시지를 `struct nlmsghdr` -> `struct nfgenmsg` -> `struct nlattr` 형식으로 다룹니다. `struct nlmsghdr`는 이미 살펴봤으므로 나머지 두 구조체를 살펴보겠습니다.

```c
struct nfgenmsg {
	__u8  nfgen_family;		/* AF_xxx */
	__u8  version;		/* nfnetlink version */
	__be16    res_id;		/* resource id */
};
```

`nfgen_family`는 패밀리를 지정합니다. IPv4와 IPv6 공통의 경우 `NFPROTO_INET`이 사용됩니다. `version`은 현재 0만 존재합니다. `res_id`는 nftables의 경우 begin 메시지에만 사용되며, 값으로 `NFNL_SUBSYS_NFTABLES`를 사용합니다.

```c
struct nlattr {
	__u16           nla_len;
	__u16           nla_type;
};
```

`struct nlattr`은 TLV(Type-Length-Value) 형태를 가집니다. `struct nlattr`는 헤더이며, 페이로드는 정렬을 요구하는 경우 패딩과 함께 헤더 바로 뒤에 따라옵니다. `nla_len`은 패딩을 제외한 크기이며, `nla_type`은 서브시스템에서 사용하는 속성 타입입니다.

이제 nfnetlink를 살펴보겠습니다. netlink 메시지가 `NETLINK_NETFILTER` 패밀리로 전송되면 수신 콜백 함수로 `nfnetlink_rcv`가 호출됩니다.

```c
static void nfnetlink_rcv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);          

	if (skb->len < NLMSG_HDRLEN ||
	    nlh->nlmsg_len < NLMSG_HDRLEN ||
	    skb->len < nlh->nlmsg_len)
		return;

	if (!netlink_net_capable(skb, CAP_NET_ADMIN)) {
		netlink_ack(skb, nlh, -EPERM, NULL);
		return;
	}

	if (nlh->nlmsg_type == NFNL_MSG_BATCH_BEGIN)
		nfnetlink_rcv_skb_batch(skb, nlh);
	else
		netlink_rcv_skb(skb, nfnetlink_rcv_msg);
}
```

소켓 버퍼에서 메시지를 꺼낸 후 값들을 검증하고 권한을 확인합니다. netfilter에는 네트워크 관리자만 접근할 수 있으므로, `CAP_NET_ADMIN` 권한이 없는 경우 송신 측에 에러 메시지를 전송합니다. 이후 메시지 타입이 `NFNL_MSG_BATCH_BEGIN`인지에 따라 처리 경로가 갈립니다.

`nfnetlink_rcv_skb_batch` 함수는 여러 메시지를 하나의 트랜잭션으로 묶어 원자적으로 처리합니다. 예를 들어 10개의 명령 메시지 중 9번째가 실패하면 앞서 처리된 8개를 모두 롤백하고 처음부터 다시 시도합니다. 또한 이 경로에서는 `NFNL_CB_BATCH` 타입의 콜백 함수만 처리할 수 있습니다. 반면 `netlink_rcv_skb` 함수는 메시지를 하나씩 단독으로 처리하며, `NFNL_CB_RCU` 및 `NFNL_CB_MUTEX` 타입의 콜백 함수만 처리할 수 있습니다. 여기서는 `nfnetlink_rcv_skb_batch` 함수만 다룹니다.

```c
static void nfnetlink_rcv_skb_batch(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int min_len = nlmsg_total_size(sizeof(struct nfgenmsg));
	struct nlattr *attr = (void *)nlh + min_len;
	struct nlattr *cda[NFNL_BATCH_MAX + 1];
	int attrlen = nlh->nlmsg_len - min_len;
	struct nfgenmsg *nfgenmsg;
	int msglen, err;
	u32 gen_id = 0;
	u16 res_id;

	msglen = NLMSG_ALIGN(nlh->nlmsg_len);
	if (msglen > skb->len)
		msglen = skb->len;

	if (skb->len < NLMSG_HDRLEN + sizeof(struct nfgenmsg))
		return;

	err = nla_parse_deprecated(cda, NFNL_BATCH_MAX, attr, attrlen,          // (0)
				   nfnl_batch_policy, NULL);
	if (err < 0) {
		netlink_ack(skb, nlh, err, NULL);
		return;
	}
	if (cda[NFNL_BATCH_GENID])
		gen_id = ntohl(nla_get_be32(cda[NFNL_BATCH_GENID]));

	nfgenmsg = nlmsg_data(nlh);                                             // (1)
	skb_pull(skb, msglen);                                                  
	/* Work around old nft using host byte order */
	if (nfgenmsg->res_id == NFNL_SUBSYS_NFTABLES)
		res_id = NFNL_SUBSYS_NFTABLES;
	else
		res_id = ntohs(nfgenmsg->res_id);

	nfnetlink_rcv_batch(skb, nlh, res_id, gen_id);
}
```

먼저 netlink 헤더의 `nlmsg_len` 값을 정렬하여 소켓 버퍼 길이를 초과하면 버퍼 길이에 맞게 조정하고, 버퍼 자체가 너무 작으면 처리 없이 반환합니다. 이어서 (0)에서 배치 메시지에 첨부된 `nlattr`를 정책에 따라 `cda` 배열에 파싱하는데, 배치 메시지에 `nlattr`가 없다면 이 단계는 그냥 넘어갑니다. 다음으로 (1)에서는 `nlmsg_data`로 배치 메시지의 `nfgenmsg` 헤더를 읽어오고, `skb_pull`로 소켓 버퍼 포인터를 배치 메시지 직후로 전진시켜 이후 `nfnetlink_rcv_batch`에서 나머지 명령 메시지들을 순서대로 꺼낼 수 있게 준비합니다. 마지막으로 `res_id`를 엔디안 변환한 뒤 `nfnetlink_rcv_batch`를 호출합니다.

`nfnetlink_rcv_batch`의 핵심 코드만 발췌하여 살펴보겠습니다.

```c
    const struct nfnetlink_subsystem *ss;           
    const struct nfnl_callback *nc;
    ...
    ss = nfnl_dereference_protected(subsys_id);			// (0)
    ...
    while (skb->len >= nlmsg_total_size(0)) {
        ...
        type = nlh->nlmsg_type;
        ...
        nc = nfnetlink_find_client(type, ss);           // (1)
        if (!nc) {
            err = -EINVAL;
            goto ack;
        }

        if (nc->type != NFNL_CB_BATCH) {                // (2)
            err = -EINVAL;
            goto ack;
        }

        {
            int min_len = nlmsg_total_size(sizeof(struct nfgenmsg));
            struct nfnl_net *nfnlnet = nfnl_pernet(net);
            struct nlattr *cda[NFNL_MAX_ATTR_COUNT + 1];
            struct nlattr *attr = (void *)nlh + min_len;
            u8 cb_id = NFNL_MSG_TYPE(nlh->nlmsg_type);
            int attrlen = nlh->nlmsg_len - min_len;
            struct nfnl_info info = {
                .net    = net,
                .sk     = nfnlnet->nfnl,
                .nlh    = nlh,
                .nfmsg  = nlmsg_data(nlh),
                .extack = &extack,
            };

            if (ss->cb[cb_id].attr_count > NFNL_MAX_ATTR_COUNT) {
                err = -ENOMEM;
                goto ack;
            }

            err = nla_parse_deprecated(cda,                             // (3)
                           ss->cb[cb_id].attr_count,
                           attr, attrlen,
                           ss->cb[cb_id].policy, NULL);
            if (err < 0)
                goto ack;

            err = nc->call(skb, &info, (const struct nlattr **)cda);    // (4)
            ...
        }
    }
done:
	if (status & NFNL_BATCH_REPLAY) {
        ...
	} else if (status == NFNL_BATCH_DONE) {
		err = ss->commit(net, oskb);                    // (5)
		...
    }
```

(0)에서 `subsys_id`로 해당 `nfnetlink_subsystem`을 참조한 뒤, 소켓 버퍼에 남은 메시지들을 반복문으로 하나씩 처리합니다. 각 메시지마다 (1)에서 메시지 타입으로 `nfnl_callback` 구조체를 찾아오는데, 이 구조체의 `call` 필드에 실제 처리 로직을 담은 콜백 함수가 저장되어 있습니다. 찾아온 콜백의 유형을 (2)에서 `NFNL_CB_BATCH`인지 확인하고 통과하면 현재 메시지 정보를 `nfnl_info`로 구조화합니다. 이어 (3)에서 메시지에 포함된 `nlattr`들을 `cda` 배열에 파싱하고 나면, (4)에서 콜백 함수를 호출해 실제 처리를 수행합니다. 반복문이 끝나고 트랜잭션 내 모든 메시지가 성공적으로 처리됐다면 (5)에서 커밋 콜백 함수가 호출되어 모든 변경 사항이 최종 반영됩니다.

## nftables

nftables는 넷필터의 구성 요소 중 하나로 iptables를 대체하기 위해 도입된 패킷 필터링 및 라우팅 프레임워크입니다. 기본 구성 요소는 다음과 같습니다.

- **table**: chain과 set을 담는 최상위 요소입니다.
- **chain**: 패킷이 순서대로 통과하며 검사받는 rule들의 목록입니다.
- **rule**: expression들로 구성되어 패킷의 처리 방식을 결정합니다.
- **expression**: 패킷 데이터를 실질적으로 평가하는 연산입니다.
- **set**: rule에서 참조할 수 있는 IP 주소, 포트 번호 등의 집합입니다.
- **object**: counter, quota, limit 등 상태를 유지하는 객체입니다.

nftables 서브시스템의 메시지 유형별 콜백 함수 테이블은 다음과 같습니다.

```c
static const struct nfnl_callback nf_tables_cb[NFT_MSG_MAX] = {
	[NFT_MSG_NEWTABLE] = {
		.call		= nf_tables_newtable,
		.type		= NFNL_CB_BATCH,
		.attr_count	= NFTA_TABLE_MAX,
		.policy		= nft_table_policy,
	},
	[NFT_MSG_GETTABLE] = {
		.call		= nf_tables_gettable,
		.type		= NFNL_CB_RCU,
		.attr_count	= NFTA_TABLE_MAX,
		.policy		= nft_table_policy,
	},
	[NFT_MSG_DELTABLE] = {
		.call		= nf_tables_deltable,
		.type		= NFNL_CB_BATCH,
		.attr_count	= NFTA_TABLE_MAX,
		.policy		= nft_table_policy,
	},
	[NFT_MSG_NEWCHAIN] = {
		.call		= nf_tables_newchain,
		.type		= NFNL_CB_BATCH,
		.attr_count	= NFTA_CHAIN_MAX,
		.policy		= nft_chain_policy,
	},
	[NFT_MSG_GETCHAIN] = {
		.call		= nf_tables_getchain,
		.type		= NFNL_CB_RCU,
		.attr_count	= NFTA_CHAIN_MAX,
		.policy		= nft_chain_policy,
	},
	[NFT_MSG_DELCHAIN] = {
		.call		= nf_tables_delchain,
		.type		= NFNL_CB_BATCH,
		.attr_count	= NFTA_CHAIN_MAX,
		.policy		= nft_chain_policy,
	},
	[NFT_MSG_NEWRULE] = {
		.call		= nf_tables_newrule,
		.type		= NFNL_CB_BATCH,
		.attr_count	= NFTA_RULE_MAX,
		.policy		= nft_rule_policy,
	},
	[NFT_MSG_GETRULE] = {
		.call		= nf_tables_getrule,
		.type		= NFNL_CB_RCU,
		.attr_count	= NFTA_RULE_MAX,
		.policy		= nft_rule_policy,
	},
	[NFT_MSG_DELRULE] = {
		.call		= nf_tables_delrule,
		.type		= NFNL_CB_BATCH,
		.attr_count	= NFTA_RULE_MAX,
		.policy		= nft_rule_policy,
	},
	[NFT_MSG_NEWSET] = {
		.call		= nf_tables_newset,
		.type		= NFNL_CB_BATCH,
		.attr_count	= NFTA_SET_MAX,
		.policy		= nft_set_policy,
	},
	[NFT_MSG_GETSET] = {
		.call		= nf_tables_getset,
		.type		= NFNL_CB_RCU,
		.attr_count	= NFTA_SET_MAX,
		.policy		= nft_set_policy,
	},
	[NFT_MSG_DELSET] = {
		.call		= nf_tables_delset,
		.type		= NFNL_CB_BATCH,
		.attr_count	= NFTA_SET_MAX,
		.policy		= nft_set_policy,
	},
	[NFT_MSG_NEWSETELEM] = {
		.call		= nf_tables_newsetelem,
		.type		= NFNL_CB_BATCH,
		.attr_count	= NFTA_SET_ELEM_LIST_MAX,
		.policy		= nft_set_elem_list_policy,
	},
	[NFT_MSG_GETSETELEM] = {
		.call		= nf_tables_getsetelem,
		.type		= NFNL_CB_RCU,
		.attr_count	= NFTA_SET_ELEM_LIST_MAX,
		.policy		= nft_set_elem_list_policy,
	},
	[NFT_MSG_DELSETELEM] = {
		.call		= nf_tables_delsetelem,
		.type		= NFNL_CB_BATCH,
		.attr_count	= NFTA_SET_ELEM_LIST_MAX,
		.policy		= nft_set_elem_list_policy,
	},
	[NFT_MSG_GETGEN] = {
		.call		= nf_tables_getgen,
		.type		= NFNL_CB_RCU,
	},
	[NFT_MSG_NEWOBJ] = {
		.call		= nf_tables_newobj,
		.type		= NFNL_CB_BATCH,
		.attr_count	= NFTA_OBJ_MAX,
		.policy		= nft_obj_policy,
	},
	[NFT_MSG_GETOBJ] = {
		.call		= nf_tables_getobj,
		.type		= NFNL_CB_RCU,
		.attr_count	= NFTA_OBJ_MAX,
		.policy		= nft_obj_policy,
	},
	[NFT_MSG_DELOBJ] = {
		.call		= nf_tables_delobj,
		.type		= NFNL_CB_BATCH,
		.attr_count	= NFTA_OBJ_MAX,
		.policy		= nft_obj_policy,
	},
	[NFT_MSG_GETOBJ_RESET] = {
		.call		= nf_tables_getobj,
		.type		= NFNL_CB_RCU,
		.attr_count	= NFTA_OBJ_MAX,
		.policy		= nft_obj_policy,
	},
	[NFT_MSG_NEWFLOWTABLE] = {
		.call		= nf_tables_newflowtable,
		.type		= NFNL_CB_BATCH,
		.attr_count	= NFTA_FLOWTABLE_MAX,
		.policy		= nft_flowtable_policy,
	},
	[NFT_MSG_GETFLOWTABLE] = {
		.call		= nf_tables_getflowtable,
		.type		= NFNL_CB_RCU,
		.attr_count	= NFTA_FLOWTABLE_MAX,
		.policy		= nft_flowtable_policy,
	},
	[NFT_MSG_DELFLOWTABLE] = {
		.call		= nf_tables_delflowtable,
		.type		= NFNL_CB_BATCH,
		.attr_count	= NFTA_FLOWTABLE_MAX,
		.policy		= nft_flowtable_policy,
	},
};
```

CVE-2022-34918과 관련 있는 메시지 유형은 `NFT_MSG_NEWTABLE`, `NFT_MSG_NEWSET`, `NFT_MSG_NEWSETELEM`입니다. 세 가지 콜백 함수를 순서대로 살펴보겠습니다.

### `nf_tables_newtable`

```c
static int nf_tables_newtable(struct sk_buff *skb, const struct nfnl_info *info,
			      const struct nlattr * const nla[])
{
	struct nftables_pernet *nft_net = nft_pernet(info->net);
	struct netlink_ext_ack *extack = info->extack;
	u8 genmask = nft_genmask_next(info->net);
	u8 family = info->nfmsg->nfgen_family;
	struct net *net = info->net;
	const struct nlattr *attr;
	struct nft_table *table;
	struct nft_ctx ctx;
	u32 flags = 0;
	int err;

	if (!nft_supported_family(family))                          // (0)
		return -EOPNOTSUPP;

	lockdep_assert_held(&nft_net->commit_mutex);
	attr = nla[NFTA_TABLE_NAME];
	table = nft_table_lookup(net, attr, family, genmask,        // (1)
				 NETLINK_CB(skb).portid);
	if (IS_ERR(table)) {
		if (PTR_ERR(table) != -ENOENT)
			return PTR_ERR(table);
	} else {                                                    // (2)
		if (info->nlh->nlmsg_flags & NLM_F_EXCL) {
			NL_SET_BAD_ATTR(extack, attr);
			return -EEXIST;
		}
		if (info->nlh->nlmsg_flags & NLM_F_REPLACE)
			return -EOPNOTSUPP;

		nft_ctx_init(&ctx, net, skb, info->nlh, family, table, NULL, nla);

		return nf_tables_updtable(&ctx);                        // (3)
	}

	if (nla[NFTA_TABLE_FLAGS]) {                                // (4)
		flags = ntohl(nla_get_be32(nla[NFTA_TABLE_FLAGS]));
		if (flags & ~NFT_TABLE_F_MASK)
			return -EOPNOTSUPP;
	}

	err = -ENOMEM;
	table = kzalloc(sizeof(*table), GFP_KERNEL_ACCOUNT);
	if (table == NULL)
		goto err_kzalloc;

	table->name = nla_strdup(attr, GFP_KERNEL_ACCOUNT);
	if (table->name == NULL)
		goto err_strdup;

	if (nla[NFTA_TABLE_USERDATA]) {                             // (5)
		table->udata = nla_memdup(nla[NFTA_TABLE_USERDATA], GFP_KERNEL_ACCOUNT);
		if (table->udata == NULL)
			goto err_table_udata;

		table->udlen = nla_len(nla[NFTA_TABLE_USERDATA]);
	}

	err = rhltable_init(&table->chains_ht, &nft_chain_ht_params);
	if (err)
		goto err_chain_ht;

	INIT_LIST_HEAD(&table->chains);
	INIT_LIST_HEAD(&table->sets);
	INIT_LIST_HEAD(&table->objects);
	INIT_LIST_HEAD(&table->flowtables);
	table->family = family;
	table->flags = flags;
	table->handle = ++table_handle;
	if (table->flags & NFT_TABLE_F_OWNER)                       // (6)
		table->nlpid = NETLINK_CB(skb).portid;

	nft_ctx_init(&ctx, net, skb, info->nlh, family, table, NULL, nla);      
	err = nft_trans_table_add(&ctx, NFT_MSG_NEWTABLE);                       // (7)
	if (err < 0)
		goto err_trans;

	list_add_tail_rcu(&table->list, &nft_net->tables);
	return 0;
	/* ... error cleanup ... */
}
```

먼저, (0)에서 지원되는 패밀리인지 확인합니다. `nft_supported_family`를 보면 `NFPROTO_INET`, `NFPROTO_IPV4`, `NFPROTO_ARP`, `NFPROTO_NETDEV`, `NFPROTO_BRIDGE`, `NFPROTO_IPV6` 등 빌드 설정에 따라 지원 여부가 결정됩니다.

(1)에서 동일한 이름의 테이블이 이미 존재하는지 확인하고, 존재한다면 (2)로 진입하여 플래그를 검사합니다. `NLM_F_EXCL`은 기존 테이블이 있으면 실패하라는 의미이므로 `-EEXIST`를 반환하고, `NLM_F_REPLACE`는 테이블 생성에서 지원하지 않으므로 `-EOPNOTSUPP`를 반환합니다. 두 플래그 모두 없는 경우에는 (3)의 `nf_tables_updtable`을 호출하여 기존 테이블을 업데이트합니다.

존재하지 않는 경우 새로 생성 경로로 진입합니다. (4)에서 플래그를 엔디안 변환 후 유효하지 않은 플래그가 포함되어 있으면 에러를 반환하고, 이후 테이블 구조체를 할당하여 이름을 복사합니다. (5)에서 `NFTA_TABLE_USERDATA`가 있으면 복사하는데, 이 필드는 테이블에 임의의 메타데이터를 첨부할 때 사용됩니다. 이후 체인 해시 테이블을 초기화하고 각 리스트 헤드를 설정합니다. `handle`은 테이블에 고유 번호를 부여하며, (6)에서 `NFT_TABLE_F_OWNER` 플래그가 있으면 테이블을 송신자 portid에 귀속시킵니다. 이 플래그가 설정된 테이블은 해당 프로세스가 종료될 때 함께 삭제됩니다. 마지막으로 (7)에서 트랜잭션 구조체를 할당하고 리스트에 추가합니다.

`nf_tables_updtable`은 기존 테이블의 플래그를 변경하는 함수입니다.

```c
static int nf_tables_updtable(struct nft_ctx *ctx)
{
	struct nft_trans *trans;
	u32 flags;
	int ret;

	if (!ctx->nla[NFTA_TABLE_FLAGS])        // (0)
		return 0;

	flags = ntohl(nla_get_be32(ctx->nla[NFTA_TABLE_FLAGS]));
	if (flags & ~NFT_TABLE_F_MASK)          // (1)
		return -EOPNOTSUPP;

	if (flags == ctx->table->flags)         // (2)
		return 0;

	if ((nft_table_has_owner(ctx->table) &&     // (3)
	     !(flags & NFT_TABLE_F_OWNER)) ||
	    (!nft_table_has_owner(ctx->table) &&
	     flags & NFT_TABLE_F_OWNER))
		return -EOPNOTSUPP;

	trans = nft_trans_alloc(ctx, NFT_MSG_NEWTABLE,  // (4)
				sizeof(struct nft_trans_table));
	if (trans == NULL)
		return -ENOMEM;

	if ((flags & NFT_TABLE_F_DORMANT) &&                // (5)
	    !(ctx->table->flags & NFT_TABLE_F_DORMANT)) {
		ctx->table->flags |= NFT_TABLE_F_DORMANT;
		if (!(ctx->table->flags & __NFT_TABLE_F_UPDATE))
			ctx->table->flags |= __NFT_TABLE_F_WAS_AWAKEN;
	} else if (!(flags & NFT_TABLE_F_DORMANT) &&
		   ctx->table->flags & NFT_TABLE_F_DORMANT) {
		ctx->table->flags &= ~NFT_TABLE_F_DORMANT;
		if (!(ctx->table->flags & __NFT_TABLE_F_UPDATE)) {
			ret = nf_tables_table_enable(ctx->net, ctx->table);
			if (ret < 0)
				goto err_register_hooks;

			ctx->table->flags |= __NFT_TABLE_F_WAS_DORMANT;
		}
	}

	nft_trans_table_update(trans) = true;
	nft_trans_commit_list_add_tail(ctx->net, trans);    // (6)

	return 0;

err_register_hooks:
	nft_trans_destroy(trans);
	return ret;
}
```

(0)에서 플래그가 없으면 업데이트할 내용이 없으므로 바로 반환합니다. (1)에서는 유효하지 않은 플래그를 거부하는데, 허용되는 플래그는 `NFT_TABLE_F_DORMANT`(테이블 일시 휴면)와 `NFT_TABLE_F_OWNER`(프로세스 귀속) 두 가지입니다. (2)에서 현재 플래그와 동일하면 변경 사항이 없으므로 반환하고, (3)에서는 소유 상태를 변경하려는 시도를 차단합니다. 소유 상태는 테이블 생성 시에만 결정되며 이후 변경이 불가합니다.

모든 검사를 통과하면 (4)에서 트랜잭션 구조체를 할당하고, (5)에서 휴면 상태 전환을 처리합니다. 휴면 상태로 전환하는 경우 `NFT_TABLE_F_DORMANT` 플래그를 추가하고, 트랜잭션 내에서 아직 업데이트된 적이 없다면 `__NFT_TABLE_F_WAS_AWAKEN`으로 이전 상태를 기록합니다. 반대로 휴면 상태를 해제하는 경우에는 플래그를 제거하고, 아직 업데이트된 적이 없다면 훅을 활성화한 뒤 `__NFT_TABLE_F_WAS_DORMANT`로 기록합니다. 이 `__NFT_TABLE_F_*` 플래그들은 트랜잭션 롤백 시 이전 상태를 복원하기 위한 커널 내부 전용 플래그입니다. 마지막으로 (6)에서 트랜잭션 구조체를 커밋 리스트에 추가합니다.

### `nf_tables_newset`

```c
static int nf_tables_newset(struct sk_buff *skb, const struct nfnl_info *info,
			    const struct nlattr * const nla[])
{
	u32 ktype, dtype, flags, policy, gc_int, objtype;
	struct netlink_ext_ack *extack = info->extack;
	u8 genmask = nft_genmask_next(info->net);
	u8 family = info->nfmsg->nfgen_family;
	const struct nft_set_ops *ops;
	struct nft_expr *expr = NULL;
	struct net *net = info->net;
	struct nft_set_desc desc;
	struct nft_table *table;
	unsigned char *udata;
	struct nft_set *set;
	struct nft_ctx ctx;
	size_t alloc_size;
	u64 timeout;
	char *name;
	int err, i;
	u16 udlen;
	u64 size;

	if (nla[NFTA_SET_TABLE] == NULL ||                      // (0)
	    nla[NFTA_SET_NAME] == NULL ||
	    nla[NFTA_SET_KEY_LEN] == NULL ||
	    nla[NFTA_SET_ID] == NULL)
		return -EINVAL;

	ktype = NFT_DATA_VALUE;
	if (nla[NFTA_SET_KEY_TYPE] != NULL) {                   // (1)
		ktype = ntohl(nla_get_be32(nla[NFTA_SET_KEY_TYPE]));
		if ((ktype & NFT_DATA_RESERVED_MASK) == NFT_DATA_RESERVED_MASK)
			return -EINVAL;
	}

	desc.klen = ntohl(nla_get_be32(nla[NFTA_SET_KEY_LEN]));
	if (desc.klen == 0 || desc.klen > NFT_DATA_VALUE_MAXLEN)    // (2)
		return -EINVAL;

	flags = 0;
	if (nla[NFTA_SET_FLAGS] != NULL) {                          // (3)
		flags = ntohl(nla_get_be32(nla[NFTA_SET_FLAGS]));
		if (flags & ~(NFT_SET_ANONYMOUS | NFT_SET_CONSTANT |
			      NFT_SET_INTERVAL | NFT_SET_TIMEOUT |
			      NFT_SET_MAP | NFT_SET_EVAL |
			      NFT_SET_OBJECT | NFT_SET_CONCAT | NFT_SET_EXPR))
			return -EOPNOTSUPP;
		if ((flags & (NFT_SET_MAP | NFT_SET_OBJECT)) ==
			     (NFT_SET_MAP | NFT_SET_OBJECT))
			return -EOPNOTSUPP;
		if ((flags & (NFT_SET_EVAL | NFT_SET_OBJECT)) ==
			     (NFT_SET_EVAL | NFT_SET_OBJECT))
			return -EOPNOTSUPP;
	}

	dtype = 0;
	if (nla[NFTA_SET_DATA_TYPE] != NULL) {              // (4)
		if (!(flags & NFT_SET_MAP))
			return -EINVAL;

		dtype = ntohl(nla_get_be32(nla[NFTA_SET_DATA_TYPE]));
		if ((dtype & NFT_DATA_RESERVED_MASK) == NFT_DATA_RESERVED_MASK &&
		    dtype != NFT_DATA_VERDICT)
			return -EINVAL;

		if (dtype != NFT_DATA_VERDICT) {
			if (nla[NFTA_SET_DATA_LEN] == NULL)
				return -EINVAL;
			desc.dlen = ntohl(nla_get_be32(nla[NFTA_SET_DATA_LEN]));
			if (desc.dlen == 0 || desc.dlen > NFT_DATA_VALUE_MAXLEN)
				return -EINVAL;
		} else
			desc.dlen = sizeof(struct nft_verdict);
	} else if (flags & NFT_SET_MAP)
		return -EINVAL;

	if (nla[NFTA_SET_OBJ_TYPE] != NULL) {               // (5)
		if (!(flags & NFT_SET_OBJECT))
			return -EINVAL;

		objtype = ntohl(nla_get_be32(nla[NFTA_SET_OBJ_TYPE]));
		if (objtype == NFT_OBJECT_UNSPEC ||
		    objtype > NFT_OBJECT_MAX)
			return -EOPNOTSUPP;
	} else if (flags & NFT_SET_OBJECT)
		return -EINVAL;
	else
		objtype = NFT_OBJECT_UNSPEC;

	timeout = 0;
	if (nla[NFTA_SET_TIMEOUT] != NULL) {                // (6)
		if (!(flags & NFT_SET_TIMEOUT))
			return -EINVAL;
		err = nf_msecs_to_jiffies64(nla[NFTA_SET_TIMEOUT], &timeout);
		if (err)
			return err;
	}
	gc_int = 0;
	if (nla[NFTA_SET_GC_INTERVAL] != NULL) {
		if (!(flags & NFT_SET_TIMEOUT))
			return -EINVAL;
		gc_int = ntohl(nla_get_be32(nla[NFTA_SET_GC_INTERVAL]));
	}

	policy = NFT_SET_POL_PERFORMANCE;
	if (nla[NFTA_SET_POLICY] != NULL)                                   // (7)
		policy = ntohl(nla_get_be32(nla[NFTA_SET_POLICY]));

	if (nla[NFTA_SET_DESC] != NULL) {                                   // (8)
		err = nf_tables_set_desc_parse(&desc, nla[NFTA_SET_DESC]);
		if (err < 0)
			return err;
	}

	if (nla[NFTA_SET_EXPR] || nla[NFTA_SET_EXPRESSIONS])                // (9)
		desc.expr = true;

	table = nft_table_lookup(net, nla[NFTA_SET_TABLE], family, genmask, // (10)
				 NETLINK_CB(skb).portid);
	if (IS_ERR(table)) {
		NL_SET_BAD_ATTR(extack, nla[NFTA_SET_TABLE]);
		return PTR_ERR(table);
	}

	nft_ctx_init(&ctx, net, skb, info->nlh, family, table, NULL, nla);  // (11)

	set = nft_set_lookup(table, nla[NFTA_SET_NAME], genmask);           // (12)
	if (IS_ERR(set)) {
		if (PTR_ERR(set) != -ENOENT) {
			NL_SET_BAD_ATTR(extack, nla[NFTA_SET_NAME]);
			return PTR_ERR(set);
		}
	} else {
		if (info->nlh->nlmsg_flags & NLM_F_EXCL) {
			NL_SET_BAD_ATTR(extack, nla[NFTA_SET_NAME]);
			return -EEXIST;
		}
		if (info->nlh->nlmsg_flags & NLM_F_REPLACE)
			return -EOPNOTSUPP;
		return 0;
	}

	if (!(info->nlh->nlmsg_flags & NLM_F_CREATE))
		return -ENOENT;

	ops = nft_select_set_ops(&ctx, nla, &desc, policy);                 // (13)
	if (IS_ERR(ops))
		return PTR_ERR(ops);

	udlen = 0;
	if (nla[NFTA_SET_USERDATA])                                         // (14)        
		udlen = nla_len(nla[NFTA_SET_USERDATA]);

	size = 0;
	if (ops->privsize != NULL)                                          // (15)
		size = ops->privsize(nla, &desc);
	alloc_size = sizeof(*set) + size + udlen;
	if (alloc_size < size || alloc_size > INT_MAX)
		return -ENOMEM;
	set = kvzalloc(alloc_size, GFP_KERNEL_ACCOUNT);                     // (16)
	if (!set)
		return -ENOMEM;

	name = nla_strdup(nla[NFTA_SET_NAME], GFP_KERNEL_ACCOUNT);
	if (!name) {
		err = -ENOMEM;
		goto err_set_name;
	}

	err = nf_tables_set_alloc_name(&ctx, set, name);                    // (17)
	kfree(name);
	if (err < 0)
		goto err_set_name;

	udata = NULL;
	if (udlen) {                                                        // (18)
		udata = set->data + size;
		nla_memcpy(udata, nla[NFTA_SET_USERDATA], udlen);
	}

	INIT_LIST_HEAD(&set->bindings);
	INIT_LIST_HEAD(&set->catchall_list);
	set->table = table;
	write_pnet(&set->net, net);
	set->ops = ops;
	set->ktype = ktype;
	set->klen = desc.klen;
	set->dtype = dtype;
	set->objtype = objtype;
	set->dlen = desc.dlen;
	set->flags = flags;
	set->size = desc.size;
	set->policy = policy;
	set->udlen = udlen;
	set->udata = udata;
	set->timeout = timeout;
	set->gc_int = gc_int;

	set->field_count = desc.field_count;
	for (i = 0; i < desc.field_count; i++)
		set->field_len[i] = desc.field_len[i];

	err = ops->init(set, &desc, nla);                       // (19)
	if (err < 0)
		goto err_set_init;

	if (nla[NFTA_SET_EXPR]) {                               // (20)
		expr = nft_set_elem_expr_alloc(&ctx, set, nla[NFTA_SET_EXPR]);
		if (IS_ERR(expr)) {
			err = PTR_ERR(expr);
			goto err_set_expr_alloc;
		}
		set->exprs[0] = expr;
		set->num_exprs++;
	} else if (nla[NFTA_SET_EXPRESSIONS]) {
		struct nft_expr *expr;
		struct nlattr *tmp;
		int left;

		if (!(flags & NFT_SET_EXPR)) {
			err = -EINVAL;
			goto err_set_expr_alloc;
		}
		i = 0;
		nla_for_each_nested(tmp, nla[NFTA_SET_EXPRESSIONS], left) {
			if (i == NFT_SET_EXPR_MAX) {
				err = -E2BIG;
				goto err_set_expr_alloc;
			}
			if (nla_type(tmp) != NFTA_LIST_ELEM) {
				err = -EINVAL;
				goto err_set_expr_alloc;
			}
			expr = nft_set_elem_expr_alloc(&ctx, set, tmp);
			if (IS_ERR(expr)) {
				err = PTR_ERR(expr);
				goto err_set_expr_alloc;
			}
			set->exprs[i++] = expr;
			set->num_exprs++;
		}
	}

	set->handle = nf_tables_alloc_handle(table);                // (21)

	err = nft_trans_set_add(&ctx, NFT_MSG_NEWSET, set);         // (22)
	if (err < 0)
		goto err_set_expr_alloc;

	list_add_tail_rcu(&set->list, &table->sets);
	table->use++;
	return 0;

err_set_expr_alloc:
	for (i = 0; i < set->num_exprs; i++)
		nft_expr_destroy(&ctx, set->exprs[i]);

	ops->destroy(set);
err_set_init:
	kfree(set->name);
err_set_name:
	kvfree(set);
	return err;
}
```

(0)에서 set 생성에 반드시 필요한 `NFTA_SET_TABLE`, `NFTA_SET_NAME`, `NFTA_SET_KEY_LEN`, `NFTA_SET_ID` 속성이 모두 있는지 확인합니다. (1)에서는 키 타입을 검사하는데, set의 키 타입에는 `NFT_DATA_VALUE`만 허용됩니다. (2)에서 키 길이가 0이거나 `NFT_DATA_VALUE_MAXLEN`(64)을 초과하면 에러를 반환합니다. (3)에서는 플래그를 검사하여 정의되지 않은 플래그가 있거나 `NFT_SET_MAP`과 `NFT_SET_OBJECT`, 또는 `NFT_SET_EVAL`과 `NFT_SET_OBJECT`가 동시에 설정된 경우 에러를 반환합니다.

(4)에서 데이터 타입을 처리합니다. map 형식만 데이터를 가질 수 있기 때문에, `NFTA_SET_DATA_TYPE`이 있는데 `NFT_SET_MAP` 플래그가 없는 경우 혹은 `NFTA_SET_DATA_TYPE`이 없는데 `NFT_SET_MAP` 플래그가 있는 경우에 에러를 반환합니다. 유효한 경우 데이터 타입은 `NFT_DATA_VALUE` 혹은 `NFT_DATA_VERDICT`만 허용되며, 다른 값이 들어오면 에러를 반환합니다. `NFT_DATA_VALUE`인 경우 `NFTA_SET_DATA_LEN`이 반드시 필요하므로 길이 값을 검증합니다. `NFT_DATA_VERDICT`인 경우 데이터 크기는 `struct nft_verdict`의 크기로 고정됩니다.

(5)에서 오브젝트 타입을 처리합니다. `NFTA_SET_OBJ_TYPE`이 있는데 `NFT_SET_OBJECT` 플래그가 없거나, `NFT_SET_OBJECT` 플래그가 있는데 `NFTA_SET_OBJ_TYPE`이 없거나, 오브젝트 타입 값이 유효 범위를 벗어나면 에러를 반환합니다.

(6)에서 타임아웃을 처리합니다. `NFTA_SET_TIMEOUT`이 있는데 `NFT_SET_TIMEOUT` 플래그가 없으면 에러를 반환합니다. 타임아웃 값을 밀리초에서 jiffies로 변환하여 저장합니다. GC 주기도 마찬가지로 `NFT_SET_TIMEOUT` 플래그가 없으면 에러를 반환하고, 있으면 값을 저장합니다.

(7)에서 조회 성능 정책을 읽어옵니다. 기본값은 `NFT_SET_POL_PERFORMANCE`입니다. (8)에서 set 크기, 필드 수, 각 필드 길이 등 set 구조 기술자를 파싱합니다. (9)에서 표현식 관련 속성이 있으면 `desc.expr` 플래그를 설정합니다.

(10)에서 대상 테이블을 찾고, (11)에서 트랜잭션 컨텍스트를 초기화합니다. (12)에서 동일한 이름의 set이 이미 존재하는지 확인합니다. 존재하는 경우 `nf_tables_newtable`과 마찬가지로 `NLM_F_EXCL`이면 에러, `NLM_F_REPLACE`는 미지원이므로 에러를 반환하며, 두 플래그 모두 없으면 그대로 반환합니다. set 업데이트는 테이블과 달리 별도 처리 없이 종료됩니다.

(13)에서 set의 내부 구현 방식을 선택합니다. 이 함수는 플래그와 정책을 고려하여 해시, rbtree, bitmap 등 적합한 자료구조를 선택합니다.

이후 (14)에서 유저 데이터가 있으면 이후 set 할당 시 함께 복사할 수 있도록 길이를 저장해둡니다. (15)의 `privsize`는 선택한 내부 구현체에서 사용할 공간의 크기로, (16)에서 set 구조체와 `privsize`, 유저 데이터 크기를 합산하여 한 번에 할당합니다. (17)은 set에 이름을 할당하는 함수로, 유저가 이름 자동 할당을 요청한 경우 이를 처리합니다. (18)에서는 유저 데이터가 있었다면 set 구조체의 `data` 필드 뒤에 복사합니다. set 구조체를 살펴보겠습니다.

```c
struct nft_set {
	struct list_head		list;
	struct list_head		bindings;
	struct nft_table		*table;
	possible_net_t			net;
	char				*name;
	u64				handle;
	u32				ktype;
	u32				dtype;
	u32				objtype;
	u32				size;
	u8				field_len[NFT_REG32_COUNT];
	u8				field_count;
	u32				use;
	atomic_t			nelems;
	u32				ndeact;
	u64				timeout;
	u32				gc_int;
	u16				policy;
	u16				udlen;
	unsigned char			*udata;
	/* runtime data below here */
	const struct nft_set_ops	*ops ____cacheline_aligned;
	u16				flags:14,
					genmask:2;
	u8				klen;
	u8				dlen;
	u8				num_exprs;
	struct nft_expr			*exprs[NFT_SET_EXPR_MAX];
	struct list_head		catchall_list;
	unsigned char			data[]
		__attribute__((aligned(__alignof__(u64))));
};
```

`data` 필드는 구조체 맨 뒤에 위치하므로, 유저 데이터가 있다면 구조체 끝에 저장됩니다. (19)에서는 내부 구현체를 초기화하는데, (15)에서 구했던 `privsize`가 여기서 사용됩니다. (20)은 expression들을 set에 할당하고, (21)은 고유 번호를 부여합니다. 마지막으로 (22)에서 트랜잭션 구조체를 할당하고 리스트에 추가합니다.

### `nf_tables_newsetelem`

```c
static int nf_tables_newsetelem(struct sk_buff *skb,
				const struct nfnl_info *info,
				const struct nlattr * const nla[])
{
	struct nftables_pernet *nft_net = nft_pernet(info->net);
	struct netlink_ext_ack *extack = info->extack;
	u8 genmask = nft_genmask_next(info->net);
	u8 family = info->nfmsg->nfgen_family;
	struct net *net = info->net;
	const struct nlattr *attr;
	struct nft_table *table;
	struct nft_set *set;
	struct nft_ctx ctx;
	int rem, err;

	if (nla[NFTA_SET_ELEM_LIST_ELEMENTS] == NULL)                           // (0)
		return -EINVAL;

	table = nft_table_lookup(net, nla[NFTA_SET_ELEM_LIST_TABLE], family,    // (1)
				 genmask, NETLINK_CB(skb).portid);
	if (IS_ERR(table)) {
		NL_SET_BAD_ATTR(extack, nla[NFTA_SET_ELEM_LIST_TABLE]);
		return PTR_ERR(table);
	}

	set = nft_set_lookup_global(net, table, nla[NFTA_SET_ELEM_LIST_SET],    // (2)
				    nla[NFTA_SET_ELEM_LIST_SET_ID], genmask);
	if (IS_ERR(set))
		return PTR_ERR(set);

	if (!list_empty(&set->bindings) && set->flags & NFT_SET_CONSTANT)       // (3)
		return -EBUSY;

	nft_ctx_init(&ctx, net, skb, info->nlh, family, table, NULL, nla);      // (4)

	nla_for_each_nested(attr, nla[NFTA_SET_ELEM_LIST_ELEMENTS], rem) {      // (5)
		err = nft_add_set_elem(&ctx, set, attr, info->nlh->nlmsg_flags);
		if (err < 0)
			return err;
	}

	if (nft_net->validate_state == NFT_VALIDATE_DO)                         // (6)
		return nft_table_validate(net, table);

	return 0;
}
```

(0)에서 추가할 원소 목록이 있는지 확인한 후, (1),(2)에서 원소를 추가할 테이블과 set을 가져옵니다. (3)에서는 set이 체인에 고정 상태로 바인드되어 있으면서 `NFT_SET_CONSTANT` 플래그가 설정된 경우를 검사하는데, 이 경우 원소를 추가할 수 없으므로 에러를 반환합니다. (4)에서는 이전 함수들과 마찬가지로 현재 컨텍스트를 담는 구조체를 초기화합니다. 이후 (5)에서 반복문을 돌며 원소들을 하나씩 꺼내어 추가하고, (6)에서 표현식 검증이 필요한 경우 검증을 수행합니다. 이제 원소를 추가하는 `nft_add_set_elem` 함수를 살펴보겠습니다.

```c
static int nft_add_set_elem(struct nft_ctx *ctx, struct nft_set *set,
			    const struct nlattr *attr, u32 nlmsg_flags)
{
	struct nft_expr *expr_array[NFT_SET_EXPR_MAX] = {};
	struct nlattr *nla[NFTA_SET_ELEM_MAX + 1];
	u8 genmask = nft_genmask_next(ctx->net);
	u32 flags = 0, size = 0, num_exprs = 0;
	struct nft_set_ext_tmpl tmpl;
	struct nft_set_ext *ext, *ext2;
	struct nft_set_elem elem;
	struct nft_set_binding *binding;
	struct nft_object *obj = NULL;
	struct nft_userdata *udata;
	struct nft_data_desc desc;
	enum nft_registers dreg;
	struct nft_trans *trans;
	u64 timeout;
	u64 expiration;
	int err, i;
	u8 ulen;

	err = nla_parse_nested_deprecated(nla, NFTA_SET_ELEM_MAX, attr,                 // (0)
					  nft_set_elem_policy, NULL);
	if (err < 0)
		return err;

	nft_set_ext_prepare(&tmpl);                                                     // (1)

	err = nft_setelem_parse_flags(set, nla[NFTA_SET_ELEM_FLAGS], &flags);           // (2)
	if (err < 0)
		return err;

	if (!nla[NFTA_SET_ELEM_KEY] && !(flags & NFT_SET_ELEM_CATCHALL))                // (3)
		return -EINVAL;

	if (flags != 0)                                                                 // (4)
		nft_set_ext_add(&tmpl, NFT_SET_EXT_FLAGS);

	if (set->flags & NFT_SET_MAP) {                                                 // (5)
		if (nla[NFTA_SET_ELEM_DATA] == NULL &&
		    !(flags & NFT_SET_ELEM_INTERVAL_END))
			return -EINVAL;
	} else {
		if (nla[NFTA_SET_ELEM_DATA] != NULL)
			return -EINVAL;
	}

	if ((flags & NFT_SET_ELEM_INTERVAL_END) &&                                      // (6)
	     (nla[NFTA_SET_ELEM_DATA] ||
	      nla[NFTA_SET_ELEM_OBJREF] ||
	      nla[NFTA_SET_ELEM_TIMEOUT] ||
	      nla[NFTA_SET_ELEM_EXPIRATION] ||
	      nla[NFTA_SET_ELEM_USERDATA] ||
	      nla[NFTA_SET_ELEM_EXPR] ||
	      nla[NFTA_SET_ELEM_EXPRESSIONS]))
		return -EINVAL;

	timeout = 0;
	if (nla[NFTA_SET_ELEM_TIMEOUT] != NULL) {                                       // (7)
		if (!(set->flags & NFT_SET_TIMEOUT))
			return -EINVAL;
		err = nf_msecs_to_jiffies64(nla[NFTA_SET_ELEM_TIMEOUT],
					    &timeout);
		if (err)
			return err;
	} else if (set->flags & NFT_SET_TIMEOUT) {
		timeout = set->timeout;
	}

	expiration = 0;
	if (nla[NFTA_SET_ELEM_EXPIRATION] != NULL) {                                    // (8)
		if (!(set->flags & NFT_SET_TIMEOUT))
			return -EINVAL;
		err = nf_msecs_to_jiffies64(nla[NFTA_SET_ELEM_EXPIRATION],
					    &expiration);
		if (err)
			return err;
	}

	if (nla[NFTA_SET_ELEM_EXPR]) {                                              // (9)
		struct nft_expr *expr;

		if (set->num_exprs && set->num_exprs != 1)
			return -EOPNOTSUPP;

		expr = nft_set_elem_expr_alloc(ctx, set,
					       nla[NFTA_SET_ELEM_EXPR]);
		if (IS_ERR(expr))
			return PTR_ERR(expr);

		expr_array[0] = expr;
		num_exprs = 1;

		if (set->num_exprs && set->exprs[0]->ops != expr->ops) {
			err = -EOPNOTSUPP;
			goto err_set_elem_expr;
		}
	} else if (nla[NFTA_SET_ELEM_EXPRESSIONS]) {
		struct nft_expr *expr;
		struct nlattr *tmp;
		int left;

		i = 0;
		nla_for_each_nested(tmp, nla[NFTA_SET_ELEM_EXPRESSIONS], left) {
			if (i == NFT_SET_EXPR_MAX ||
			    (set->num_exprs && set->num_exprs == i)) {
				err = -E2BIG;
				goto err_set_elem_expr;
			}
			if (nla_type(tmp) != NFTA_LIST_ELEM) {
				err = -EINVAL;
				goto err_set_elem_expr;
			}
			expr = nft_set_elem_expr_alloc(ctx, set, tmp);
			if (IS_ERR(expr)) {
				err = PTR_ERR(expr);
				goto err_set_elem_expr;
			}
			expr_array[i] = expr;
			num_exprs++;

			if (set->num_exprs && expr->ops != set->exprs[i]->ops) {
				err = -EOPNOTSUPP;
				goto err_set_elem_expr;
			}
			i++;
		}
		if (set->num_exprs && set->num_exprs != i) {
			err = -EOPNOTSUPP;
			goto err_set_elem_expr;
		}
	} else if (set->num_exprs > 0) {
		err = nft_set_elem_expr_clone(ctx, set, expr_array);
		if (err < 0)
			goto err_set_elem_expr_clone;

		num_exprs = set->num_exprs;
	}

	if (nla[NFTA_SET_ELEM_KEY]) {                                       // (10)
		err = nft_setelem_parse_key(ctx, set, &elem.key.val,
					    nla[NFTA_SET_ELEM_KEY]);
		if (err < 0)
			goto err_set_elem_expr;

		nft_set_ext_add_length(&tmpl, NFT_SET_EXT_KEY, set->klen);
	}

	if (nla[NFTA_SET_ELEM_KEY_END]) {                                   // (11)
		err = nft_setelem_parse_key(ctx, set, &elem.key_end.val,
					    nla[NFTA_SET_ELEM_KEY_END]);
		if (err < 0)
			goto err_parse_key;

		nft_set_ext_add_length(&tmpl, NFT_SET_EXT_KEY_END, set->klen);
	}

	if (timeout > 0) {                                                  // (12)
		nft_set_ext_add(&tmpl, NFT_SET_EXT_EXPIRATION);
		if (timeout != set->timeout)
			nft_set_ext_add(&tmpl, NFT_SET_EXT_TIMEOUT);
	}

	if (num_exprs) {                                                    // (13)
		for (i = 0; i < num_exprs; i++)
			size += expr_array[i]->ops->size;

		nft_set_ext_add_length(&tmpl, NFT_SET_EXT_EXPRESSIONS,
				       sizeof(struct nft_set_elem_expr) +
				       size);
	}

	if (nla[NFTA_SET_ELEM_OBJREF] != NULL) {                            // (14)
		if (!(set->flags & NFT_SET_OBJECT)) {
			err = -EINVAL;
			goto err_parse_key_end;
		}
		obj = nft_obj_lookup(ctx->net, ctx->table,
				     nla[NFTA_SET_ELEM_OBJREF],
				     set->objtype, genmask);
		if (IS_ERR(obj)) {
			err = PTR_ERR(obj);
			goto err_parse_key_end;
		}
		nft_set_ext_add(&tmpl, NFT_SET_EXT_OBJREF);
	}

	if (nla[NFTA_SET_ELEM_DATA] != NULL) {                                      // (15)
		err = nft_setelem_parse_data(ctx, set, &desc, &elem.data.val,
					     nla[NFTA_SET_ELEM_DATA]);
		if (err < 0)
			goto err_parse_key_end;

		dreg = nft_type_to_reg(set->dtype);
		list_for_each_entry(binding, &set->bindings, list) {
			struct nft_ctx bind_ctx = {
				.net	= ctx->net,
				.family	= ctx->family,
				.table	= ctx->table,
				.chain	= (struct nft_chain *)binding->chain,
			};

			if (!(binding->flags & NFT_SET_MAP))
				continue;

			err = nft_validate_register_store(&bind_ctx, dreg,
							  &elem.data.val,
							  desc.type, desc.len);
			if (err < 0)
				goto err_parse_data;

			if (desc.type == NFT_DATA_VERDICT &&
			    (elem.data.val.verdict.code == NFT_GOTO ||
			     elem.data.val.verdict.code == NFT_JUMP))
				nft_validate_state_update(ctx->net,
							  NFT_VALIDATE_NEED);
		}

		nft_set_ext_add_length(&tmpl, NFT_SET_EXT_DATA, desc.len);
	}

	/* The full maximum length of userdata can exceed the maximum
	 * offset value (U8_MAX) for following extensions, therefor it
	 * must be the last extension added.
	 */
	ulen = 0;
	if (nla[NFTA_SET_ELEM_USERDATA] != NULL) {                  // (16)
		ulen = nla_len(nla[NFTA_SET_ELEM_USERDATA]);
		if (ulen > 0)
			nft_set_ext_add_length(&tmpl, NFT_SET_EXT_USERDATA,
					       ulen);
	}

	err = -ENOMEM;
	elem.priv = nft_set_elem_init(set, &tmpl, elem.key.val.data,        // (17)
				      elem.key_end.val.data, elem.data.val.data,
				      timeout, expiration, GFP_KERNEL_ACCOUNT);
	if (elem.priv == NULL)
		goto err_parse_data;

	ext = nft_set_elem_ext(set, elem.priv);                             // (18)
	if (flags)
		*nft_set_ext_flags(ext) = flags;
	if (ulen > 0) {
		udata = nft_set_ext_userdata(ext);
		udata->len = ulen - 1;
		nla_memcpy(&udata->data, nla[NFTA_SET_ELEM_USERDATA], ulen);
	}
	if (obj) {
		*nft_set_ext_obj(ext) = obj;
		obj->use++;
	}
	err = nft_set_elem_expr_setup(ctx, ext, expr_array, num_exprs);
	if (err < 0)
		goto err_elem_expr;

	trans = nft_trans_elem_alloc(ctx, NFT_MSG_NEWSETELEM, set);         // (19)
	if (trans == NULL) {
		err = -ENOMEM;
		goto err_elem_expr;
	}

	ext->genmask = nft_genmask_cur(ctx->net) | NFT_SET_ELEM_BUSY_MASK;

	err = nft_setelem_insert(ctx->net, set, &elem, &ext2, flags);       // (20)
	if (err) {
		if (err == -EEXIST) {
			if (nft_set_ext_exists(ext, NFT_SET_EXT_DATA) ^
			    nft_set_ext_exists(ext2, NFT_SET_EXT_DATA) ||
			    nft_set_ext_exists(ext, NFT_SET_EXT_OBJREF) ^
			    nft_set_ext_exists(ext2, NFT_SET_EXT_OBJREF))
				goto err_element_clash;
			if ((nft_set_ext_exists(ext, NFT_SET_EXT_DATA) &&
			     nft_set_ext_exists(ext2, NFT_SET_EXT_DATA) &&
			     memcmp(nft_set_ext_data(ext),
				    nft_set_ext_data(ext2), set->dlen) != 0) ||
			    (nft_set_ext_exists(ext, NFT_SET_EXT_OBJREF) &&
			     nft_set_ext_exists(ext2, NFT_SET_EXT_OBJREF) &&
			     *nft_set_ext_obj(ext) != *nft_set_ext_obj(ext2)))
				goto err_element_clash;
			else if (!(nlmsg_flags & NLM_F_EXCL))
				err = 0;
		} else if (err == -ENOTEMPTY) {
			/* ENOTEMPTY reports overlapping between this element
			 * and an existing one.
			 */
			err = -EEXIST;
		}
		goto err_element_clash;
	}

	if (!(flags & NFT_SET_ELEM_CATCHALL) && set->size &&
	    !atomic_add_unless(&set->nelems, 1, set->size + set->ndeact)) {
		err = -ENFILE;
		goto err_set_full;
	}

	nft_trans_elem(trans) = elem;
	nft_trans_commit_list_add_tail(ctx->net, trans);                        // (21)
	return 0;

err_set_full:
	nft_setelem_remove(ctx->net, set, &elem);
err_element_clash:
	kfree(trans);
err_elem_expr:
	if (obj)
		obj->use--;

	nf_tables_set_elem_destroy(ctx, set, elem.priv);
err_parse_data:
	if (nla[NFTA_SET_ELEM_DATA] != NULL)
		nft_data_release(&elem.data.val, desc.type);
err_parse_key_end:
	nft_data_release(&elem.key_end.val, NFT_DATA_VALUE);
err_parse_key:
	nft_data_release(&elem.key.val, NFT_DATA_VALUE);
err_set_elem_expr:
	for (i = 0; i < num_exprs && expr_array[i]; i++)
		nft_expr_destroy(ctx, expr_array[i]);
err_set_elem_expr_clone:
	return err;
}
```

먼저, 하나의 원소는 아래와 같은 속성을 가질 수 있습니다.

```c
/**
 * enum nft_set_elem_attributes - nf_tables set element netlink attributes
 *
 * @NFTA_SET_ELEM_KEY: key value (NLA_NESTED: nft_data)
 * @NFTA_SET_ELEM_DATA: data value of mapping (NLA_NESTED: nft_data_attributes)
 * @NFTA_SET_ELEM_FLAGS: bitmask of nft_set_elem_flags (NLA_U32)
 * @NFTA_SET_ELEM_TIMEOUT: timeout value (NLA_U64)
 * @NFTA_SET_ELEM_EXPIRATION: expiration time (NLA_U64)
 * @NFTA_SET_ELEM_USERDATA: user data (NLA_BINARY)
 * @NFTA_SET_ELEM_EXPR: expression (NLA_NESTED: nft_expr_attributes)
 * @NFTA_SET_ELEM_OBJREF: stateful object reference (NLA_STRING)
 * @NFTA_SET_ELEM_KEY_END: closing key value (NLA_NESTED: nft_data)
 * @NFTA_SET_ELEM_EXPRESSIONS: list of expressions (NLA_NESTED: nft_list_attributes)
 */
enum nft_set_elem_attributes {
	NFTA_SET_ELEM_UNSPEC,
	NFTA_SET_ELEM_KEY,
	NFTA_SET_ELEM_DATA,
	NFTA_SET_ELEM_FLAGS,
	NFTA_SET_ELEM_TIMEOUT,
	NFTA_SET_ELEM_EXPIRATION,
	NFTA_SET_ELEM_USERDATA,
	NFTA_SET_ELEM_EXPR,
	NFTA_SET_ELEM_PAD,
	NFTA_SET_ELEM_OBJREF,
	NFTA_SET_ELEM_KEY_END,
	NFTA_SET_ELEM_EXPRESSIONS,
	__NFTA_SET_ELEM_MAX
};
```

(0)에서는 `nla_parse_nested_deprecated` 함수를 호출하여 원소 속성들을 지역 변수 `nla` 배열에 파싱합니다. 이 함수를 살펴보겠습니다.

```c
int __nla_parse(struct nlattr **tb, int maxtype,
		const struct nlattr *head, int len,
		const struct nla_policy *policy, unsigned int validate,
		struct netlink_ext_ack *extack)
{
	return __nla_validate_parse(head, len, maxtype, policy, validate,
				    extack, tb, 0);
}

static inline int nla_parse_nested_deprecated(struct nlattr *tb[], int maxtype,
					      const struct nlattr *nla,
					      const struct nla_policy *policy,
					      struct netlink_ext_ack *extack)
{
	return __nla_parse(tb, maxtype, nla_data(nla), nla_len(nla), policy,
			   NL_VALIDATE_LIBERAL, extack);
}
```

이 함수는 결국 `__nla_validate_parse`를 호출합니다.

```c
static int __nla_validate_parse(const struct nlattr *head, int len, int maxtype,
				const struct nla_policy *policy,
				unsigned int validate,
				struct netlink_ext_ack *extack,
				struct nlattr **tb, unsigned int depth)
{
	const struct nlattr *nla;
	int rem;

	if (depth >= MAX_POLICY_RECURSION_DEPTH) {                  // (0)
		NL_SET_ERR_MSG(extack,
			       "allowed policy recursion depth exceeded");
		return -EINVAL;
	}

	if (tb)
		memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));

	nla_for_each_attr(nla, head, len, rem) {                    // (1)
		u16 type = nla_type(nla);

		if (type == 0 || type > maxtype) {
			if (validate & NL_VALIDATE_MAXTYPE) {
				NL_SET_ERR_MSG_ATTR(extack, nla,
						    "Unknown attribute type");
				return -EINVAL;
			}
			continue;
		}
		if (policy) {
			int err = validate_nla(nla, maxtype, policy,        // (2)
					       validate, extack, depth);

			if (err < 0)
				return err;
		}

		if (tb)
			tb[type] = (struct nlattr *)nla;
	}

	if (unlikely(rem > 0)) {
		pr_warn_ratelimited("netlink: %d bytes leftover after parsing attributes in process `%s'.\n",
				    rem, current->comm);
		NL_SET_ERR_MSG(extack, "bytes leftover after parsing attributes");
		if (validate & NL_VALIDATE_TRAILING)
			return -EINVAL;
	}

	return 0;
}
```

(0)에서 재귀 깊이를 제한합니다. 이 함수는 (2)에서 재귀적으로 호출될 수 있는데, 악의적인 요청에 의해 재귀가 지나치게 깊어지는 것을 방지하기 위함입니다. (1)에서는 원소 속성들을 하나씩 가져와 검사하고 배열에 담으며, (2)에서는 속성들이 정책에 맞는 형식을 갖추고 있는지 검사합니다.

다시 `nft_add_set_elem` 함수로 돌아가서, (1)에서 `struct nft_set_ext`를 위한 사전 준비를 하는 `nft_set_ext_prepare` 함수를 호출합니다. 먼저 `struct nft_set_ext_tmpl`과 `struct nft_set_ext`를 살펴보겠습니다.

```c
struct nft_set_ext_tmpl {
	u16	len;
	u8	offset[NFT_SET_EXT_NUM];
};

struct nft_set_ext {
	u8	genmask;
	u8	offset[NFT_SET_EXT_NUM];
	char	data[];
};
```

`struct nft_set_ext_tmpl`은 `struct nft_set_ext`를 할당하기 전에 임시로 사용하는 구조체입니다. 원소의 속성들 크기를 모두 파악해야 `nft_set_ext`를 할당할 수 있으므로, 그 이전까지 임시로 크기와 오프셋을 누적합니다. `len`에 전체 크기를 합산하고, 속성들은 메모리에 연속적으로 배치되므로 `offset` 배열에 각 속성의 시작 오프셋을 저장합니다.

함수를 살펴보겠습니다.

```c
static inline void nft_set_ext_prepare(struct nft_set_ext_tmpl *tmpl)
{
	memset(tmpl, 0, sizeof(*tmpl));
	tmpl->len = sizeof(struct nft_set_ext);
}
```

구조체를 0으로 초기화하고 초기 길이를 헤더 크기로 설정합니다.

다시 돌아가서, (2)에서는 플래그 속성을 변수 `flags`에 파싱하고 유효성을 검사하여, 유효하지 않은 플래그가 있으면 에러를 반환합니다. (3)은 키가 없으면서 CATCHALL 원소도 아닌 경우 에러를 반환하는데, CATCHALL 원소는 다른 원소들과 매칭되지 않는 나머지 전부를 키로 지정하는 특수 원소입니다. (4)에서는 플래그가 있었다면 해당 크기만큼 템플릿 합산 크기에 추가합니다. `nft_set_ext_add` 함수를 살펴보겠습니다.

```c
static inline void nft_set_ext_add_length(struct nft_set_ext_tmpl *tmpl, u8 id,
					  unsigned int len)
{
	tmpl->len	 = ALIGN(tmpl->len, nft_set_ext_types[id].align);
	BUG_ON(tmpl->len > U8_MAX);
	tmpl->offset[id] = tmpl->len;
	tmpl->len	+= nft_set_ext_types[id].len + len;
}

static inline void nft_set_ext_add(struct nft_set_ext_tmpl *tmpl, u8 id)
{
	nft_set_ext_add_length(tmpl, id, 0);
}
```

오프셋을 저장하고 크기를 누적합니다. 플래그는 1바이트 공간이 필요하므로 1이 더해집니다.

다시 돌아가서, (5)에서는 set이 map 형식인 경우 data가 없고 구간 끝 플래그도 없다면 에러를 반환하며, 반대로 map이 아닌데 데이터가 포함되었다면 에러를 반환합니다. (6)에서는 구간 끝 플래그가 존재하면서 함께 존재할 수 없는 속성들이 있는지 확인합니다. (7)에서는 원소의 타임아웃이 있으면 검사하고 값을 가져오며, 원소에 타임아웃이 없더라도 set에 타임아웃이 지정되어 있으면 그 값을 사용합니다. (8)에서는 원소의 만료 시간이 있으면 검사하고 값을 가져오는데, 만료 시간은 타임아웃 중 남은 시간을 의미합니다. (9)는 표현식 속성이 있으면 검사 후 할당하고, 없더라도 set 자체에 표현식이 있으면 복제하여 할당합니다. 표현식 구조체의 주소들은 지역 변수로 선언된 `expr_array` 배열에 저장됩니다.

(10)에서는 키를 파싱하고 템플릿 합산 크기에 키 크기를 더하며 오프셋을 저장합니다. (11)은 범위를 지정하는 원소인 경우 끝점 역할의 키를 (10)과 동일하게 처리하고, (12)에서는 타임아웃이 있는 경우 타임아웃과 만료 시간에 필요한 크기를 더하고 오프셋을 저장합니다. (13)에서는 표현식이 있으면 필요한 크기를 더하고 오프셋을 저장하며, (14)에서는 공유 객체 참조가 있으면 객체를 찾고 마찬가지로 크기와 오프셋을 저장합니다.

(15)에서는 먼저 data 속성을 파싱한 후, 이 set을 사용하는 체인들에서 데이터 값이 적절한지 검사하고 검증 상태를 업데이트합니다. 이후 템플릿에 데이터 길이를 더하고 오프셋을 저장합니다. `nft_setelem_parse_data` 함수를 살펴보겠습니다.

```c
static int nft_setelem_parse_data(struct nft_ctx *ctx, struct nft_set *set,
				  struct nft_data_desc *desc,
				  struct nft_data *data,
				  struct nlattr *attr)
{
	int err;

	err = nft_data_init(ctx, data, NFT_DATA_VALUE_MAXLEN, desc, attr);		// (0)
	if (err < 0)
		return err;

	if (desc->type != NFT_DATA_VERDICT && desc->len != set->dlen) {		// (1)
		nft_data_release(data, desc->type);
		return -EINVAL;
	}

	return 0;
}
```

(0)에서 데이터를 파싱하는데, `NFT_DATA_VALUE_MAXLEN`은 데이터 값의 최대 크기를 나타내는 매크로로 64입니다. (1)에서는 유효성을 검사하여, verdict 타입이 아닌데 데이터의 크기가 set 생성 시 정해진 크기와 다르면 에러를 반환합니다. `nft_data_init` 함수를 살펴보겠습니다.

```c
int nft_data_init(const struct nft_ctx *ctx,
		  struct nft_data *data, unsigned int size,
		  struct nft_data_desc *desc, const struct nlattr *nla)
{
	struct nlattr *tb[NFTA_DATA_MAX + 1];
	int err;

	err = nla_parse_nested_deprecated(tb, NFTA_DATA_MAX, nla,		// (0)
					  nft_data_policy, NULL);
	if (err < 0)
		return err;

	if (tb[NFTA_DATA_VALUE])								// (1)
		return nft_value_init(ctx, data, size, desc,
				      tb[NFTA_DATA_VALUE]);
	if (tb[NFTA_DATA_VERDICT] && ctx != NULL)
		return nft_verdict_init(ctx, data, desc, tb[NFTA_DATA_VERDICT]);
	return -EINVAL;
}
```

(0)에서 배열 `tb`에 파싱한 후, (1)에서 데이터 타입에 따라 분기합니다. `nft_value_init`과 `nft_verdict_init`를 살펴보겠습니다.

```c
static int nft_value_init(const struct nft_ctx *ctx,
			  struct nft_data *data, unsigned int size,
			  struct nft_data_desc *desc, const struct nlattr *nla)
{
	unsigned int len;

	len = nla_len(nla);
	if (len == 0)
		return -EINVAL;
	if (len > size)
		return -EOVERFLOW;

	nla_memcpy(data->data, nla, len);
	desc->type = NFT_DATA_VALUE;
	desc->len  = len;
	return 0;
}
```

nla의 value 부분을 원소 구조체 `data`에 복사하고, `desc`에 복사한 크기와 데이터 유형을 저장합니다.

```c
static int nft_verdict_init(const struct nft_ctx *ctx, struct nft_data *data,
			    struct nft_data_desc *desc, const struct nlattr *nla)
{
	u8 genmask = nft_genmask_next(ctx->net);
	struct nlattr *tb[NFTA_VERDICT_MAX + 1];
	struct nft_chain *chain;
	int err;

	err = nla_parse_nested_deprecated(tb, NFTA_VERDICT_MAX, nla,
					  nft_verdict_policy, NULL);
	if (err < 0)
		return err;

	if (!tb[NFTA_VERDICT_CODE])
		return -EINVAL;
	data->verdict.code = ntohl(nla_get_be32(tb[NFTA_VERDICT_CODE]));

	switch (data->verdict.code) {
	default:
		switch (data->verdict.code & NF_VERDICT_MASK) {
		case NF_ACCEPT:
		case NF_DROP:
		case NF_QUEUE:
			break;
		default:
			return -EINVAL;
		}
		fallthrough;
	case NFT_CONTINUE:
	case NFT_BREAK:
	case NFT_RETURN:
		break;
	case NFT_JUMP:
	case NFT_GOTO:
		if (tb[NFTA_VERDICT_CHAIN]) {
			chain = nft_chain_lookup(ctx->net, ctx->table,
						 tb[NFTA_VERDICT_CHAIN],
						 genmask);
		} else if (tb[NFTA_VERDICT_CHAIN_ID]) {
			chain = nft_chain_lookup_byid(ctx->net,
						      tb[NFTA_VERDICT_CHAIN_ID]);
			if (IS_ERR(chain))
				return PTR_ERR(chain);
		} else {
			return -EINVAL;
		}

		if (IS_ERR(chain))
			return PTR_ERR(chain);
		if (nft_is_base_chain(chain))
			return -EOPNOTSUPP;

		chain->use++;
		data->verdict.chain = chain;
		break;
	}

	desc->len = sizeof(data->verdict);
	desc->type = NFT_DATA_VERDICT;
	return 0;
}
```

verdict는 중첩 파싱 후 원소 구조체 `data`에 코드를 저장하고, 코드가 점프 명령어인 경우 대상 체인을 찾아 검증한 뒤 저장합니다. `desc`에는 크기와 타입도 함께 저장하며, verdict 타입의 길이는 `sizeof(struct nft_verdict)`, 즉 16바이트로 고정됩니다.

다시 돌아가서, (16)에서는 유저 데이터 속성이 있으면 크기를 템플릿 합산 크기에 더하고 오프셋을 저장합니다. (17)에서 원소를 할당하는데, `nft_set_elem_init` 함수를 살펴보겠습니다.

```c
void *nft_set_elem_init(const struct nft_set *set,
			const struct nft_set_ext_tmpl *tmpl,
			const u32 *key, const u32 *key_end,
			const u32 *data, u64 timeout, u64 expiration, gfp_t gfp)
{
	struct nft_set_ext *ext;
	void *elem;

	elem = kzalloc(set->ops->elemsize + tmpl->len, gfp);		// (0)
	if (elem == NULL)
		return NULL;

	ext = nft_set_elem_ext(set, elem);						// (1)
	nft_set_ext_init(ext, tmpl);

	if (nft_set_ext_exists(ext, NFT_SET_EXT_KEY))				// (2)	
		memcpy(nft_set_ext_key(ext), key, set->klen);
	if (nft_set_ext_exists(ext, NFT_SET_EXT_KEY_END))
		memcpy(nft_set_ext_key_end(ext), key_end, set->klen);
	if (nft_set_ext_exists(ext, NFT_SET_EXT_DATA))
		memcpy(nft_set_ext_data(ext), data, set->dlen);
	if (nft_set_ext_exists(ext, NFT_SET_EXT_EXPIRATION)) {
		*nft_set_ext_expiration(ext) = get_jiffies_64() + expiration;
		if (expiration == 0)
			*nft_set_ext_expiration(ext) += timeout;
	}
	if (nft_set_ext_exists(ext, NFT_SET_EXT_TIMEOUT))
		*nft_set_ext_timeout(ext) = timeout;

	return elem;
}
```

`set->ops->elemsize`는 set 생성 시 선택된 내부 구현체가 원소마다 필요로 하는 내부 공간 크기입니다. (0)에서 이 크기와 지금까지 속성들에 필요한 크기의 합산으로 원소를 할당하고, (1)에서 `elem + set->ops->elemsize`를 반환하여 `ext`의 시작 주소를 가져옵니다. 이후 `ext`를 초기화하는데, 해당 함수를 살펴보겠습니다.

```c
static inline void nft_set_ext_init(struct nft_set_ext *ext,
				    const struct nft_set_ext_tmpl *tmpl)
{
	memcpy(ext->offset, tmpl->offset, sizeof(ext->offset));
}
```

템플릿에 지금까지 저장해둔 속성들의 오프셋을 모두 복사합니다. 

다시 `nft_set_elem_init` 함수로 돌아가서, (2)부터는 복사된 오프셋 값들로 속성의 존재 여부를 확인한 후, 존재하는 속성들을 모두 `elem`에 복사합니다.

다시 `nft_add_set_elem` 함수로 돌아가서, (18)에서 `elem`의 `ext`를 가져온 뒤 플래그, 유저 데이터, 오브젝트, 표현식을 복사합니다. (19)에서 트랜잭션을 생성하고 (20)에서 생성한 원소를 set에 삽입한 뒤, (21)에서 트랜잭션을 커밋 리스트에 추가합니다. (20)에서 호출한 `nft_setelem_insert` 함수를 살펴보겠습니다.

```c
static int nft_setelem_insert(const struct net *net,
			      struct nft_set *set,
			      const struct nft_set_elem *elem,
			      struct nft_set_ext **ext, unsigned int flags)
{
	int ret;

	if (flags & NFT_SET_ELEM_CATCHALL)
		ret = nft_setelem_catchall_insert(net, set, elem, ext);
	else
		ret = set->ops->insert(net, set, elem, ext);

	return ret;
}
```

set에 원소를 삽입하는 동작은 CATCHALL 원소인지 여부에 따라 분기됩니다. CATCHALL이 아닌 경우, set 생성 시 선택된 구현체의 삽입 함수를 호출합니다. CATCHALL 원소일 때 호출되는 `nft_setelem_catchall_insert` 함수를 살펴보겠습니다.

```c
static int nft_setelem_catchall_insert(const struct net *net,
				       struct nft_set *set,
				       const struct nft_set_elem *elem,
				       struct nft_set_ext **pext)
{
	struct nft_set_elem_catchall *catchall;
	u8 genmask = nft_genmask_next(net);
	struct nft_set_ext *ext;

	list_for_each_entry(catchall, &set->catchall_list, list) {      // (0)
		ext = nft_set_elem_ext(set, catchall->elem);
		if (nft_set_elem_active(ext, genmask)) {
			*pext = ext;
			return -EEXIST;
		}
	}

	catchall = kmalloc(sizeof(*catchall), GFP_KERNEL);
	if (!catchall)
		return -ENOMEM;

	catchall->elem = elem->priv;
	list_add_tail_rcu(&catchall->list, &set->catchall_list);

	return 0;
}
```

CATCHALL은 그 외의 전부를 의미하므로, 하나의 set 안에 활성화된 CATCHALL 원소는 하나만 존재할 수 있습니다. 다만 새 원소로 교체할 때 기존 원소가 현재 사용 중이라면 즉시 해제할 수 없어 리스트가 필요합니다.

(0)에서 set에 현재 활성화된 CATCHALL 원소가 이미 존재하는지 검사하여, 존재한다면 해당 원소의 `ext`를 외부 포인터 `pext`에 저장하고 에러를 반환합니다. 활성화된 CATCHALL 원소가 없다면 구조체를 할당하고 리스트에 추가합니다.