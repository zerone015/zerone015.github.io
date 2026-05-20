---
title: "(임시)nftable subsystem"
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

nfnetlink는 유저 공간에서 netlink를 통해 iptables나 nftables에 접근하기 위한 인터페이스입니다. nfnetlink는 메시지를 `struct nlmsghdr` -> `struct nfgenmsg` -> `struct nlattr` 형식으로 다룹니다. `struct nlmsghdr`는 이미 살펴봤으므로 나머지 두 구조체를 살펴보겠습니다.

```c
struct nfgenmsg {
	__u8  nfgen_family;		/* AF_xxx */
	__u8  version;		/* nfnetlink version */
	__be16    res_id;		/* resource id */
};
```

`nfgen_family`는 방화벽을 설정할 주소 패밀리를 지정합니다. IPv4와 IPv6 공통의 경우 `NFPROTO_INET`이 사용됩니다. `version`은 현재 0만 존재합니다. `res_id`는 nftables의 경우 begin 메시지에만 사용되며, 값으로 `NFNL_SUBSYS_NFTABLES`를 사용합니다.

```c
struct nlattr {
	__u16           nla_len;
	__u16           nla_type;
};
```

`struct nlattr`은 TLV(Type-Length-Value) 형태를 가집니다. `struct nlattr`는 헤더이며, 페이로드가 정렬을 요구하는 경우 패딩과 함께 바로 뒤에 따라옵니다. `nla_len`은 패딩을 제외한 크기이며, `nla_type`은 서브시스템에서 사용하는 속성 타입입니다.

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

먼저 netlink 헤더의 `nlmsg_len` 값을 정렬한 뒤, 정렬된 크기가 소켓 버퍼 길이를 초과하면 버퍼 길이에 맞게 조정합니다. 소켓 버퍼가 너무 작으면 처리 없이 반환합니다. (0)의 `nla_parse_deprecated`는 배치 메시지의 `nlattr`를 정책에 따라 `cda` 배열에 파싱하는데, 배치 메시지에 `nlattr`가 없는 경우에는 해당되지 않습니다. 이후 (1)에서 `nlmsg_data`로 배치 메시지의 `nfgenmsg` 헤더를 읽어온 뒤, `skb_pull`을 호출하여 소켓 버퍼가 배치 메시지 다음 메시지를 가리키도록 합니다. `res_id`가 `NFNL_SUBSYS_NFTABLES`인 경우를 제외하고 엔디안 변환 후 `nfnetlink_rcv_batch`를 호출합니다.

```c
static void nfnetlink_rcv_batch(struct sk_buff *skb, struct nlmsghdr *nlh,
				u16 subsys_id, u32 genid)
{
	struct sk_buff *oskb = skb;
	struct net *net = sock_net(skb->sk);
	const struct nfnetlink_subsystem *ss;
	const struct nfnl_callback *nc;
	struct netlink_ext_ack extack;
	LIST_HEAD(err_list);
	u32 status;
	int err;

	if (subsys_id >= NFNL_SUBSYS_COUNT)
		return netlink_ack(skb, nlh, -EINVAL, NULL);
replay:
	status = 0;
replay_abort:
	skb = netlink_skb_clone(oskb, GFP_KERNEL);
	if (!skb)
		return netlink_ack(oskb, nlh, -ENOMEM, NULL);

	nfnl_lock(subsys_id);
	ss = nfnl_dereference_protected(subsys_id);
	if (!ss) {
#ifdef CONFIG_MODULES
		nfnl_unlock(subsys_id);
		request_module("nfnetlink-subsys-%d", subsys_id);
		nfnl_lock(subsys_id);
		ss = nfnl_dereference_protected(subsys_id);
		if (!ss)
#endif
		{
			nfnl_unlock(subsys_id);
			netlink_ack(oskb, nlh, -EOPNOTSUPP, NULL);
			return kfree_skb(skb);
		}
	}

	if (!ss->valid_genid || !ss->commit || !ss->abort) {
		nfnl_unlock(subsys_id);
		netlink_ack(oskb, nlh, -EOPNOTSUPP, NULL);
		return kfree_skb(skb);
	}

	if (!try_module_get(ss->owner)) {
		nfnl_unlock(subsys_id);
		netlink_ack(oskb, nlh, -EOPNOTSUPP, NULL);
		return kfree_skb(skb);
	}

	if (!ss->valid_genid(net, genid)) {
		module_put(ss->owner);
		nfnl_unlock(subsys_id);
		netlink_ack(oskb, nlh, -ERESTART, NULL);
		return kfree_skb(skb);
	}

	nfnl_unlock(subsys_id);

	while (skb->len >= nlmsg_total_size(0)) {
		int msglen, type;

		if (fatal_signal_pending(current)) {
			nfnl_err_reset(&err_list);
			err = -EINTR;
			status = NFNL_BATCH_FAILURE;
			goto done;
		}

		memset(&extack, 0, sizeof(extack));
		nlh = nlmsg_hdr(skb);
		err = 0;

		if (nlh->nlmsg_len < NLMSG_HDRLEN ||
		    skb->len < nlh->nlmsg_len ||
		    nlmsg_len(nlh) < sizeof(struct nfgenmsg)) {
			nfnl_err_reset(&err_list);
			status |= NFNL_BATCH_FAILURE;
			goto done;
		}

		/* Only requests are handled by the kernel */
		if (!(nlh->nlmsg_flags & NLM_F_REQUEST)) {
			err = -EINVAL;
			goto ack;
		}

		type = nlh->nlmsg_type;
		if (type == NFNL_MSG_BATCH_BEGIN) {
			/* Malformed: Batch begin twice */
			nfnl_err_reset(&err_list);
			status |= NFNL_BATCH_FAILURE;
			goto done;
		} else if (type == NFNL_MSG_BATCH_END) {
			status |= NFNL_BATCH_DONE;
			goto done;
		} else if (type < NLMSG_MIN_TYPE) {
			err = -EINVAL;
			goto ack;
		}

		/* We only accept a batch with messages for the same
		 * subsystem.
		 */
		if (NFNL_SUBSYS_ID(type) != subsys_id) {
			err = -EINVAL;
			goto ack;
		}

		nc = nfnetlink_find_client(type, ss);
		if (!nc) {
			err = -EINVAL;
			goto ack;
		}

		if (nc->type != NFNL_CB_BATCH) {
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
				.net	= net,
				.sk	= nfnlnet->nfnl,
				.nlh	= nlh,
				.nfmsg	= nlmsg_data(nlh),
				.extack	= &extack,
			};

			/* Sanity-check NFTA_MAX_ATTR */
			if (ss->cb[cb_id].attr_count > NFNL_MAX_ATTR_COUNT) {
				err = -ENOMEM;
				goto ack;
			}

			err = nla_parse_deprecated(cda,
						   ss->cb[cb_id].attr_count,
						   attr, attrlen,
						   ss->cb[cb_id].policy, NULL);
			if (err < 0)
				goto ack;

			err = nc->call(skb, &info, (const struct nlattr **)cda);

			/* The lock was released to autoload some module, we
			 * have to abort and start from scratch using the
			 * original skb.
			 */
			if (err == -EAGAIN) {
				status |= NFNL_BATCH_REPLAY;
				goto done;
			}
		}
ack:
		if (nlh->nlmsg_flags & NLM_F_ACK || err) {
			/* Errors are delivered once the full batch has been
			 * processed, this avoids that the same error is
			 * reported several times when replaying the batch.
			 */
			if (nfnl_err_add(&err_list, nlh, err, &extack) < 0) {
				/* We failed to enqueue an error, reset the
				 * list of errors and send OOM to userspace
				 * pointing to the batch header.
				 */
				nfnl_err_reset(&err_list);
				netlink_ack(oskb, nlmsg_hdr(oskb), -ENOMEM,
					    NULL);
				status |= NFNL_BATCH_FAILURE;
				goto done;
			}
			/* We don't stop processing the batch on errors, thus,
			 * userspace gets all the errors that the batch
			 * triggers.
			 */
			if (err)
				status |= NFNL_BATCH_FAILURE;
		}

		msglen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (msglen > skb->len)
			msglen = skb->len;
		skb_pull(skb, msglen);
	}
done:
	if (status & NFNL_BATCH_REPLAY) {
		ss->abort(net, oskb, NFNL_ABORT_AUTOLOAD);
		nfnl_err_reset(&err_list);
		kfree_skb(skb);
		module_put(ss->owner);
		goto replay;
	} else if (status == NFNL_BATCH_DONE) {
		err = ss->commit(net, oskb);
		if (err == -EAGAIN) {
			status |= NFNL_BATCH_REPLAY;
			goto done;
		} else if (err) {
			ss->abort(net, oskb, NFNL_ABORT_NONE);
			netlink_ack(oskb, nlmsg_hdr(oskb), err, NULL);
		}
	} else {
		enum nfnl_abort_action abort_action;

		if (status & NFNL_BATCH_FAILURE)
			abort_action = NFNL_ABORT_NONE;
		else
			abort_action = NFNL_ABORT_VALIDATE;

		err = ss->abort(net, oskb, abort_action);
		if (err == -EAGAIN) {
			nfnl_err_reset(&err_list);
			kfree_skb(skb);
			module_put(ss->owner);
			status |= NFNL_BATCH_FAILURE;
			goto replay_abort;
		}
	}
	if (ss->cleanup)
		ss->cleanup(net);

	nfnl_err_deliver(&err_list, oskb);
	kfree_skb(skb);
	module_put(ss->owner);
}
```

트랜잭션 처리와 각종 예외 처리가 포함된 함수입니다. 먼저 `struct nfnetlink_subsystem`을 살펴보겠습니다.

```c
struct nfnetlink_subsystem {
	const char *name;
	__u8 subsys_id;			/* nfnetlink subsystem ID */
	__u8 cb_count;			/* number of callbacks */
	const struct nfnl_callback *cb;	/* callback for individual types */
	struct module *owner;
	int (*commit)(struct net *net, struct sk_buff *skb);
	int (*abort)(struct net *net, struct sk_buff *skb,
		     enum nfnl_abort_action action);
	void (*cleanup)(struct net *net);
	bool (*valid_genid)(struct net *net, u32 genid);
};
```

nfnetlink의 각 서브시스템을 나타내는 구조체입니다. `name`은 서브시스템 이름, `subsys_id`는 고유 ID입니다. `cb_count`는 콜백 함수의 수이며, `cb`는 콜백 함수 포인터를 가지는 구조체 배열입니다. `owner`는 서브시스템을 담당하는 모듈을 나타냅니다. 나머지 함수 포인터들은 배치 트랜잭션 처리 전용입니다. nfnetlink에는 이 서브시스템별 구조체들을 담는 테이블이 있습니다.

```c
static struct {
	struct mutex				mutex;
	const struct nfnetlink_subsystem __rcu	*subsys;
} table[NFNL_SUBSYS_COUNT];
```

이 배열의 인덱스는 `nfnetlink_subsystem`의 `subsys_id` 값입니다. `nfnetlink_subsystem`은 해당 서브시스템 모듈이 적재될 때, 혹은 빌트인 드라이버인 경우 부팅 시에 이 배열에 등록됩니다.

이제 `nfnetlink_rcv_batch`의 핵심 코드만 발췌하여 살펴보겠습니다.

```c
        const struct nfnetlink_subsystem *ss;           // (0)
        const struct nfnl_callback *nc;
        ...
        ss = nfnl_dereference_protected(subsys_id);
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
```

(0)에서 `subsys_id`에 해당하는 `nfnetlink_subsystem`을 참조합니다. (1)에서 해당 서브시스템에서 메시지 타입에 맞는 `nfnl_callback` 구조체를 찾습니다. 이 구조체의 `call` 필드에 해당 메시지를 처리할 콜백 함수가 저장되어 있습니다. (2)에서 콜백 함수의 유형이 `NFNL_CB_BATCH`인지 검사합니다. 유형이 맞다면 필요한 정보들을 구조화하고, (3)에서 `nlattr`들을 `cda` 배열에 파싱한 뒤, (4)에서 콜백 함수를 호출합니다.