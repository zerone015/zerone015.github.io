---
title: "(임시)nftable subsystem"
date: 2026-05-15 01:00:00 +0900
categories: [Linux Kernel]
tags: [nftable, netlink]
---

드림핵에서 리눅스 커널 해킹 패스를 수강하면서 CVE-2022-34918 관련 강의를 보는데 nftable 서브 시스템에 대한 기반 지식이 부족해서인지 제대로 이해하기 어려웠습니다. 그래서 CVE-2022-34918를 본격적으로 분석하기에 앞서 먼저 nftable에 대해 간단히 분석하고 정리하고자 합니다. 이 글에서 다루는 범위는 유저 공간 프로그램에서 nftable에 접근하기 위해 netlink API를 사용하는 방법부터 커널 내부 구조와 동작입니다. nft 명령어를 사용하는 방법은 다루지 않으며 이는 리눅스 메뉴얼 페이지에서 확인할 수 있습니다.  

## netlink
netlink는 유저 공간과 커널이 서로 통신하기 위해 사용되는 인터페이스 입니다. 유저 공간과 커널이 통신하기 위한 또 다른 방법으로는 ioctl, /proc이 있습니다. 이 방법들은 유저 공간에서 먼저 요청해야 커널이 응답하는 구조이므로 단방향 통신입니다. netlink는 소켓을 사용하는 양방향 통신으로 커널이 유저공간에 이벤트를 먼저 전송할 수 있습니다.

### 머라하지...
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
이 프로그램은 먼저 socket()을 호출하여 netlink 소켓을 생성합니다. netlink 소켓을 생성하기 위해 socket()의 첫 번째 인자는 AF_NETLINK이 되어야 하고 두 번째 인자는 SOCK_RAW 혹은 SOCK_DGRAM이 되어야 합니다. 이 두 타입은 netlink 프로토콜에서 동일한 것으로 취급 됩니다. 세 번째 인자는 netlink_family이며 이 것은 통신할 커널 서브시스템을 선택하기 위해 사용됩니다. 이 프로그램은 테스트를 위해 예약되지 않은 여분의 netlink_family를 사용합니다.

이후 소켓에 주소를 바인드 하기 위해 struct sockaddr_nl을 사용합니다. 이 구조체를 살펴보겠습니다.

```c
struct sockaddr_nl {
    sa_family_t     nl_family;  /* AF_NETLINK */
    unsigned short  nl_pad;     /* Zero */
    pid_t           nl_pid;     /* Port ID */
    __u32           nl_groups;  /* Multicast groups mask */
};
```
nl_family는 항상 AF_NETLINK이 되어야 하고 nl_pad은 사용되지 않는 멤버입니다. nl_pid는 소켓을 식별하기 위한 Port ID입니다. 0은 목적지가 커널임을 나타냅니다. 수신 측에서의 이 값은 bind() 하기 전에 유저 프로그램에서 임의로 지정하거나 0으로 설정하여 커널에게 맡길 수 있습니다. 임의로 지정하는 경우, 소켓이 여러개 일 때 값들이 유일하도록 신경써야 합니다. 커널에게 맡기는 경우, 첫 번째로 생성한 소켓에 유저 프로세스 PID를 설정하고 이후에 생성되는 소켓에 유일한 값들을 알아서 설정해줍니다. 

nl_groups는 각 비트들이 netlink 그룹 번호를 나타내는 비트 마스크입니다. 이 값이 0이 아닌 경우 멀티캐스트로 전송하게 됩니다. 예를 들어, 두 번째 비트를 1로 설정하는 것은 2번 그룹에 멀티캐스트로 메세지를 전송합니다. 수신 측이라면 2번 그룹으로 보내지는 메세지들을 구독하게 됩니다. 멀티캐스트 그룹에 전송하거나 구독하려면 CAP_NET_ADMIN 권한을 갖고 있거나 euid가 0이어야 합니다. 구독 권한은 일부 예외가 있는 서브시스템이 있으며 여기서는 더 이상 자세히 다루지 않겠습니다.

바인드 이후 단계에서는 메세지를 전송하기 위해 여러 구조체들을 세팅하게 됩니다. 먼저, 구조체 nlmsghdr부터 살펴보겠습니다.
```c
struct nlmsghdr {
    __u32 nlmsg_len;    /* Length of message including header */
    __u16 nlmsg_type;   /* Type of message content */
    __u16 nlmsg_flags;  /* Additional flags */
    __u32 nlmsg_seq;    /* Sequence number */
    __u32 nlmsg_pid;    /* Sender port ID */
};
```
netlink 메세지는 한 개 이상의 nlmsghdr와 페이로드의 바이트 스트림으로 구성됩니다. 여기서 바이트 스트림이란 nlmsghdr와 페이로드 그리고 여러 개의 메세지가 메모리 상 서로 접한다는 것을 의미합니다. nlmsghdr는 메세지의 헤더로, 5개의 멤버를 가지고 있습니다. nlmsg_len는 헤더를 포함한 메세지의 전체 크기입니다. nlmsg_type는 메세지의 유형을 나타내며 메세지 유형은 또 다시 표준 타입과 패밀리들이 확장하여 사용하는 전용 타입으로 나뉩니다. 표준 타입은 3가지가 있고 다음과 같이 정의되어 있습니다. 

```c
#define NLMSG_NOOP		0x1	/* Nothing.		*/
#define NLMSG_ERROR		0x2	/* Error		*/
#define NLMSG_DONE		0x3	/* End of a dump	*/
```
NLMSG_NOOP는 메세지가 무시되어야 한다는 것을 의미합니다. NLMSG_ERROR은 오류가 발생했음을 뜻하고 원래 페이로드가 위치해야 할 곳에 구조체 nlmsgerr가 위치하게 됩니다. NLMSG_DONE는 메세지가 여러 개 일때 마지막 메세지임을 의미합니다. 구조체 nlmsgerr은 여기서는 더이상 자세히 다루지 않겠습니다. 패밀리 전용 타입은 패밀리 별로 다르며 보통 GET, NEW, DEL중 하나로 시작하거나 끝납니다. 

nlmsg_flags는 한 비트를 차지하는 메세지 플래그이며 or 연산으로 여러 개를 설정할 수 있습니다. 플래그는 메세지 타입에 따라 보통 표준, GET 요청, NEW 요청으로 나뉘며 다음과 같이 정의되어 있습니다.
```c
/* Flags values */
#define NLM_F_REQUEST		0x01	/* It is request message. 	*/
#define NLM_F_MULTI		0x02	/* Multipart message, terminated by NLMSG_DONE */
#define NLM_F_ACK		0x04	/* Reply with ack, with zero or error code */
#define NLM_F_ECHO		0x08	/* Receive resulting notifications */

/* Modifiers to GET request */
#define NLM_F_ROOT	0x100	/* specify tree	root	*/
#define NLM_F_MATCH	0x200	/* return all matching	*/
#define NLM_F_ATOMIC	0x400	/* atomic GET		*/
#define NLM_F_DUMP	(NLM_F_ROOT|NLM_F_MATCH)

/* Modifiers to NEW request */
#define NLM_F_REPLACE	0x100	/* Override existing		*/
#define NLM_F_EXCL	0x200	/* Do not touch, if it exists	*/
#define NLM_F_CREATE	0x400	/* Create, if it does not exist	*/
#define NLM_F_APPEND	0x800	/* Add to end of list		*/
```
NLM_F_REQUEST은 유저 공간에서 커널로 전송되는 메세지라면 반드시 포함해야 하는 플래그 입니다. NLM_F_ACK는 신뢰성 있는 전송을 위해 사용됩니다. netlink는 메모리가 부족하거나 에러가 발생한 것과 같은 경우에 메세지가 전달되지 않고 유실될 수 있습니다. 이 것을 확인하려면 수신 측에서 메세지가 잘 도착한 경우 확인 응답을 해줘야 합니다. NLM_F_ACK 플래그를 설정하면 커널은 에러가 발생했을 때 뿐만 아니라 잘 처리된 경우에도 NLMSG_ERROR 메세지를 구조체 nlmsgerr의 error 필드 값을 0으로 설정하여 전송해주게 됩니다.

nlmsg_seq와 nlmsg_pid는 메세지를 식별하기 위해 사용됩니다. nlmsg_pid는 송신자의 포트 ID로 주로 메세지를 누가 보냈는지 확인하기 위해 사용됩니다. nlmsg_seq는 주로 몇 번째 메세지인지 식별하기 위해 사용됩니다. 이 두 멤버의 값은 커널이 라우팅할 때는 사용하지 않는 값입니다.

또한 netlink 메세지를 다룰 때 사용이 강력히 권장되는 매크로들이 있습니다.
```c
#define NLMSG_ALIGNTO	4U

#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) ) 
#define NLMSG_HDRLEN	 ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NLMSG_DATA(nlh)  ((void *)(((char *)nlh) + NLMSG_HDRLEN))
#define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
				  (struct nlmsghdr *)(((char *)(nlh)) + \
				  NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len <= (len))
#define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))
```

여기부터 sendmsg에 대해 작성하면 됨