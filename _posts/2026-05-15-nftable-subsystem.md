---
title: "(임시)nftable subsystem"
date: 2026-05-15 01:00:00 +0900
categories: [Linux Kernel]
tags: [nftable, netlink]
---

드림핵에서 리눅스 커널 해킹 패스를 수강하면서 CVE-2022-34918 관련 강의를 보는데 nftable 서브 시스템에 대한 기반 지식이 부족해서인지 제대로 이해하기 어려웠습니다. 그래서 CVE-2022-34918를 본격적으로 분석하기에 앞서 먼저 nftable에 대해 간단히 분석하고 정리하고자 합니다. 이 글에서 다루는 범위는 유저 공간 프로그램에서 nftable에 접근하기 위해 netlink API를 사용하는 방법부터 커널 내부 구조와 동작입니다. nft 명령어를 사용하는 방법은 다루지 않으며 이는 리눅스 메뉴얼 페이지에서 확인할 수 있습니다.  

## netlink
netlink는 유저 공간과 커널이 서로 통신하기 위해 사용되는 인터페이스 입니다. 유저 공간과 커널이 통신하기 위한 또 다른 방법으로는 ioctl, /proc이 있습니다. 이 방법들은 유저 공간에서 먼저 요청해야 커널이 응답하는 구조이므로 단방향 통신입니다. netlink는 소켓을 사용하는 양방향 통신으로 커널이 유저공간에 이벤트를 먼저 전송할 수 있습니다.

## 머라하지...
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
nl_family는 항상 AF_NETLINK이 되어야 하고 nl_pad은 사용되지 않는 필드입니다. nl_pid는 소켓을 식별하기 위한 Port ID입니다. 0은 목적지가 커널임을 나타냅니다. 수신 측에서의 이 값은 bind() 하기 전에 유저 프로그램에서 임의로 지정하거나 0으로 설정하여 커널에게 맡길 수 있습니다. 임의로 지정하는 경우, 소켓이 여러개 일 때 값들이 유일하도록 신경써야 합니다. 커널에게 맡기는 경우, 첫 번째로 생성한 소켓에 유저 프로세스 PID를 설정하고 이후에 생성되는 소켓에 유일한 값들을 알아서 설정해줍니다. 

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
netlink 메세지는 한 개 이상의 nlmsghdr와 페이로드의 바이트 스트림으로 구성됩니다. 여기서 바이트 스트림이란 nlmsghdr와 페이로드 그리고 여러 개의 메세지가 메모리 상 서로 접한다는 것을 의미합니다. nlmsghdr는 메세지의 헤더로, 5개의 필드를 가지고 있습니다. nlmsg_len는 헤더를 포함한 메세지의 전체 크기입니다. nlmsg_type는 메세지의 유형을 나타내며 메세지 유형은 또 다시 표준 타입과 패밀리들이 확장하여 사용하는 전용 타입으로 나뉩니다. 표준 타입은 3가지가 있고 다음과 같이 정의되어 있습니다. 

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

nlmsg_seq와 nlmsg_pid는 메세지를 식별하기 위해 사용됩니다. nlmsg_pid는 송신자의 포트 ID로 주로 메세지를 누가 보냈는지 확인하기 위해 사용됩니다. nlmsg_seq는 주로 몇 번째 메세지인지 식별하기 위해 사용됩니다. 이 두 필드의 값은 커널이 라우팅할 때는 사용하지 않는 값입니다.

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
가장 자주 쓰이는 매크로는 NLMSG_SPACE와 NLMSG_DATA 매크로 입니다. 예를 들면 NLMSG_SPACE는 netlink 메세지를 할당하기 위해 크기를 구할 때 사용되고, NLMSG_DATA는 netlink 메세지의 페이로드 시작 위치를 구할 때 사용합니다.

이제 메세지를 전송하는 함수인 sendmsg에서 사용되는 구조체 msghdr를 살펴보겠습니다.
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
msg_name은 비연결형 도메인으로 생성된 소켓인 경우 주소를 지정하기 위해 사용되고 msg_namelen는 msg_name의 크기입니다. 예를 들어, UDP 소켓이나 netlink 소켓은 비연결형이므로 메세지를 보내기 위해 목적지 주소가 필요합니다. 반면 TCP 소켓의 경우 연결 과정에서 목적지에 대한 정보가 이미 커널에 있기 때문에 필요하지 않습니다. 따라서, 연결지향 프로토콜로 생성된 소켓의 경우 이 두 필드를 NULL, 0으로 지정해야 합니다.

msg_flags는 사용되지 않는 필드이고 msg_control, msg_controllen는 제어 정보에 대한 필드입니다.

msg_iov는 메세지들을 담는 배열인 구조체 iovec의 주소이고 msg_iovlen은 배열의 원소 갯수입니다. 구조체 iovec를 살펴보겠습니다.
```c
struct iovec {
    void   *iov_base;  /* Starting address */
    size_t  iov_len;   /* Size of the memory pointed to by iov_base. */
};
```
iov_base는 메모리 영역의 시작 주소를 나타내고 iov_len은 그 메모리 영역의 크기를 나타냅니다. 이 구조체는 개별적으로 할당되어 흩어져 있는 메모리 영역들을 하나로 묶어 한번의 시스템 콜로 전달하기 위해 사용됩니다. 예를 들어 이 구조체의 배열을 할당한 후 각 구조체에 메모리 영역 정보를 저장하면 시스템 콜은 이 배열을 사용하여 각 메모리 영역에 필요한 작업을 할 수 있습니다. 예제 프로그램에서는 struct nlmsghdr 객체의 시작 주소와 크기가 이 구조체에 저장됩니다.

추가로, 예제 프로그램은 할당되지 않은 넷링크 패밀리를 사용합니다. 따라서 실행하기 전에 먼저 커널 모듈이 적재되어야 합니다. 
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
이 커널 모듈은 적재될 때 커스텀 넷링크 패밀리와 콜백 함수를 커널에 등록합니다. 이후 유저 공간에서 이 패밀리로 메세지를 보내오면 등록한 콜백 함수가 호출됩니다. 이 콜백 함수는 유저 공간에서 전송한 메세지를 수신받아 그대로 다시 전송하는 역할을 합니다. 

## ...머라하지
이제 유저 공간에서 sendmsg를 호출했을 때 커널 내부에서 어떻게 처리하는지 호출 순서대로 하나씩 살펴보겠습니다. 커널 버전은 5.18.9 입니다.

### __sys_sendmsg
```c
long __sys_sendmsg(int fd, struct user_msghdr __user *msg, unsigned int flags,
		   bool forbid_cmsg_compat)
{
	int fput_needed, err;
	struct msghdr msg_sys;
	struct socket *sock;

	if (forbid_cmsg_compat && (flags & MSG_CMSG_COMPAT))                <===== (0)
		return -EINVAL;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);                 <===== (1)
	if (!sock)
		goto out;

	err = ___sys_sendmsg(sock, msg, &msg_sys, flags, NULL, 0);          <===== (2)

	fput_light(sock->file, fput_needed);                                <===== (3)
out:
	return err;
}

SYSCALL_DEFINE3(sendmsg, int, fd, struct user_msghdr __user *, msg, unsigned int, flags)
{
	return __sys_sendmsg(fd, msg, flags, true);
}
```
유저 공간에서 sendmsg 시스템 콜을 호출하면 공통 진입 프로시저를 거친 뒤 __sys_sendmsg가 호출됩니다. 먼저, (0)에서 비정상적인 호출을 감지합니다.  이 구현은 64비트 프로그램 전용 함수이며 COMPAT 전용 구현은 따로 있습니다. MSG_CMSG_COMPAT 플래그는 CONFIG_COMPAT 옵션이 켜진 상태에서 32비트 프로그램일 때만 사용되는 플래그 입니다. 따라서 정상적인 흐름에서는 저 조건문은 true가 될 수 없습니다. 이후 (1)에서 sockfd_lookup_light 함수가 호출됩니다. 이 함수를 살펴보겠습니다.

#### sockfd_lookup_light
```c
static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
	struct fd f = fdget(fd);                            <===== (4)
	struct socket *sock;

	*err = -EBADF;
	if (f.file) {
		sock = sock_from_file(f.file);                  <===== (5)
		if (likely(sock)) {
			*fput_needed = f.flags & FDPUT_FPUT;
			return sock;
		}
		*err = -ENOTSOCK;
		fdput(f);                                       <===== (6)
	}
	return NULL;
}
```
먼저, (4)에서 호출되는 fdget 함수에 대해 간단히 설명하고 넘어가겠습니다. 이 함수는 유저 공간에서 넘어온 정수 fd 값으로 open fd table에서 struct file을 찾은 후 참조 카운트를 증가시키고 이 구조체와 플래그를 필드로 갖는 struct fd로 만들어서 반환하는 역할을 합니다. 결론적으로, 파일 정보가 담긴 구조체를 가져오는 것입니다. 이후 (5)에서 sock_from_file 함수가 호출됩니다. 이 함수를 살펴보겠습니다. 

```c
struct socket *sock_from_file(struct file *file)
{
	if (file->f_op == &socket_file_ops)
		return file->private_data;	/* set in sock_map_fd */

	return NULL;
}
```
이 함수는 파일이 소켓파일인지 검사하고 맞다면 struct socket의 주소를, 아니라면 NULL을 반환합니다. struct socket는 유저 공간에서 socket()을 호출했을 때 생성되어 file->private_data에 저장됩니다. 

sock_from_file가 반환한 후 (5)의 다음 코드로 돌아가면, 파일이 소켓 파일이 맞다면 나중에 작업을 완료한 후 참조 카운트를 다시 감소시킬 수 있도록 표시해둔 이후 struct socket 주소를 반환합니다. 아니라면 증가시켰던 struct file의 참조 카운트를 (6)에서 즉시 감소시키고 NULL을 반환합니다.

이후 __sys_sendmsg로 돌아가면 (2)에서 ___sys_sendmsg을 호출합니다. 이 함수는 본격적인 작업을 담당하는 함수로 실행된 후에는 대부분의 작업이 완료됩니다. 이후 (3)에서 증가시켰던 struct file의 참조 카운트를 감소시키고 유저 공간에 작업 결과를 담은 정수 값을 반환합니다.   

이제 ___sys_sendmsg에서 무엇을 하는지 살펴보겠습니다.

```c
static int ___sys_sendmsg(struct socket *sock, struct user_msghdr __user *msg,
			 struct msghdr *msg_sys, unsigned int flags,
			 struct used_address *used_address,
			 unsigned int allowed_msghdr_flags)
{
	struct sockaddr_storage address;
	struct iovec iovstack[UIO_FASTIOV], *iov = iovstack;                <===== (0)
	ssize_t err;

	msg_sys->msg_name = &address;

	err = sendmsg_copy_msghdr(msg_sys, msg, flags, &iov);               <===== (1)
	if (err < 0)
		return err;

	err = ____sys_sendmsg(sock, msg_sys, flags, used_address,           <===== (2)
				allowed_msghdr_flags);
	kfree(iov);
	return err;
}
```
(0)의 iovstack 배열은 최적화 용도로 사용되는 것으로 이후 단계에서 설명하겠습니다. (1)은 유저 공간에 있는 struct user_msghdr을 커널 공간으로 안전하게 복사한 후 struct msghdr로 파싱하고, iovec을 커널에서 사용하는 구조체인 iov_iter으로 파싱하는 함수입니다. (2)는 다음 작업을 수행하는 함수입니다. sendmsg_copy_msghdr부터 살펴보겠습니다.

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
		err = copy_msghdr_from_user(msg, umsg, NULL, iov);              <===== (0)
	}
	if (err < 0)
		return err;

	return 0;
}
```
64비트 프로그램이므로 (0)을 실행하게 됩니다. 

```c
static int copy_msghdr_from_user(struct msghdr *kmsg,
				 struct user_msghdr __user *umsg,
				 struct sockaddr __user **save_addr,
				 struct iovec **iov)
{
	struct user_msghdr msg;
	ssize_t err;

	err = __copy_msghdr_from_user(kmsg, umsg, save_addr, &msg.msg_iov,          <===== (1)
					&msg.msg_iovlen);
	if (err)
		return err;

	err = import_iovec(save_addr ? READ : WRITE,                                <===== (2)
			    msg.msg_iov, msg.msg_iovlen,
			    UIO_FASTIOV, iov, &kmsg->msg_iter);
	return err < 0 ? err : 0;
}
```
(1)에서 유저 공간에 있는 struct user_msghdr을 커널 공간으로 복사한 후 struct msghdr로 파싱합니다. 이후 (2)에서 유저 공간에 있는 struct iovec들을 커널 공간으로 복사해온 뒤 struct iov_iter으로 파싱합니다. __copy_msghdr_from_user를 살펴보기 전에 struct msghdr와 struct user_msghdr의 차이를 살펴보겠습니다.

```c
struct msghdr {
	void		*msg_name;	/* ptr to socket address structure */
	int		msg_namelen;	/* size of socket address structure */
	struct iov_iter	msg_iter;	/* data */

	/*
	 * Ancillary data. msg_control_user is the user buffer used for the
	 * recv* side when msg_control_is_user is set, msg_control is the kernel
	 * buffer used for all other cases.
	 */
	union {
		void		*msg_control;
		void __user	*msg_control_user;
	};
	bool		msg_control_is_user : 1;
	__kernel_size_t	msg_controllen;	/* ancillary data buffer length */
	unsigned int	msg_flags;	/* flags on received message */
	struct kiocb	*msg_iocb;	/* ptr to iocb for async requests */
};

struct user_msghdr {
	void		__user *msg_name;	/* ptr to socket address structure */
	int		msg_namelen;		/* size of socket address structure */
	struct iovec	__user *msg_iov;	/* scatter/gather array */
	__kernel_size_t	msg_iovlen;		/* # elements in msg_iov */
	void		__user *msg_control;	/* ancillary data */
	__kernel_size_t	msg_controllen;		/* ancillary data buffer length */
	unsigned int	msg_flags;		/* flags on received message */
};
```
먼저, 유저 공간에서 사용되는 msg_iov, msg_iovlen 필드가 msg_iter로 통합되었습니다. 또한 커널 내부 전용으로 사용되는 제어 정보를 위한 필드가 추가 되었습니다. 마지막으로 비동기 요청에서 사용되는 msg_iocb 필드가 추가되었습니다. 나머지는 동일합니다. 이제 __copy_msghdr_from_user를 살펴보겠습니다.

```c
int __copy_msghdr_from_user(struct msghdr *kmsg,
			    struct user_msghdr __user *umsg,
			    struct sockaddr __user **save_addr,
			    struct iovec __user **uiov, size_t *nsegs)
{
	struct user_msghdr msg;
	ssize_t err;

	if (copy_from_user(&msg, umsg, sizeof(*umsg)))                      <===== (0)
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
			err = move_addr_to_kernel(msg.msg_name,                     <===== (1)
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
파싱하기 전 먼저, (0)에서 커널 공간으로 안전하게 복사해옵니다. 이후 입력 값 검증을 수행하며 파싱합니다. netlink나 udp같은 비연결지향 도메인의 소켓으로 전송하는 경우 msg_name, msg_namelen가 있으므로 복사를 위해 (1)이 호출됩니다. save_addr는 recvmsg에서만 사용되며 sendmsg에서는 항상 save_addr == NULL이 됩니다. 이제 move_addr_to_kernel를 살펴보겠습니다.

```c
int move_addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr_storage *kaddr)
{
	if (ulen < 0 || ulen > sizeof(struct sockaddr_storage))
		return -EINVAL;
	if (ulen == 0)
		return 0;
	if (copy_from_user(kaddr, uaddr, ulen))                 <===== (0)
		return -EFAULT;
	return audit_sockaddr(ulen, kaddr);                     <===== (1)
}
```
(0)에서 주소 데이터를 안전하게 복사해옵니다. (1)은 CONFIG_AUDITSYSCALL 옵션이 켜진 경우, 감사를 위해 현재 요청 스레드의 task_struct->audit_context->sockaddr에 kaddr의 데이터를 복사합니다. 

이제 copy_msghdr_from_user로 돌아가서, 함수 import_iovec를 살펴보겠습니다

```c
ssize_t __import_iovec(int type, const struct iovec __user *uvec,
		 unsigned nr_segs, unsigned fast_segs, struct iovec **iovp,
		 struct iov_iter *i, bool compat)
{
	ssize_t total_len = 0;
	unsigned long seg;
	struct iovec *iov;

	iov = iovec_from_user(uvec, nr_segs, fast_segs, *iovp, compat);                 <===== (0)
	if (IS_ERR(iov)) {
		*iovp = NULL;
		return PTR_ERR(iov);
	}

	/*
	 * According to the Single Unix Specification we should return EINVAL if
	 * an element length is < 0 when cast to ssize_t or if the total length
	 * would overflow the ssize_t return value of the system call.
	 *
	 * Linux caps all read/write calls to MAX_RW_COUNT, and avoids the
	 * overflow case.
	 */
	for (seg = 0; seg < nr_segs; seg++) {                                           <===== (1)
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

	iov_iter_init(i, type, iov, nr_segs, total_len);                                <===== (2)
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
먼저, (0)에서 유저 공간에 있는 struct iovec들을 커널 공간으로 복사해옵니다. 이후 (1)에서, 각 iovec들의 크기를 검사하고 필요하다면 잘라서 크기의 총 합을 구한후 (2)에서 struct iov_iter로 파싱합니다. iovec_from_user 함수를 살펴보겠습니다.

```c
static int copy_iovec_from_user(struct iovec *iov,
		const struct iovec __user *uvec, unsigned long nr_segs)
{
	unsigned long seg;

	if (copy_from_user(iov, uvec, nr_segs * sizeof(*uvec)))
		return -EFAULT;
	for (seg = 0; seg < nr_segs; seg++) {
		if ((ssize_t)iov[seg].iov_len < 0)
			return -EINVAL;
	}

	return 0;
}

struct iovec *iovec_from_user(const struct iovec __user *uvec,
		unsigned long nr_segs, unsigned long fast_segs,
		struct iovec *fast_iov, bool compat)
{
	struct iovec *iov = fast_iov;
	int ret;

	/*
	 * SuS says "The readv() function *may* fail if the iovcnt argument was
	 * less than or equal to 0, or greater than {IOV_MAX}.  Linux has
	 * traditionally returned zero for zero segments, so...
	 */
	if (nr_segs == 0)
		return iov;
	if (nr_segs > UIO_MAXIOV)
		return ERR_PTR(-EINVAL);
	if (nr_segs > fast_segs) {                                              <===== (0)
		iov = kmalloc_array(nr_segs, sizeof(struct iovec), GFP_KERNEL);
		if (!iov)
			return ERR_PTR(-ENOMEM);
	}

	if (compat)
		ret = copy_compat_iovec_from_user(iov, uvec, nr_segs);
	else
		ret = copy_iovec_from_user(iov, uvec, nr_segs);                     <===== (1)
	if (ret) {
		if (iov != fast_iov)
			kfree(iov);
		return ERR_PTR(ret);
	}

	return iov;
}
```
fast_segs는 copy_msghdr_from_user에서 import_iovec이 호출될 때 UIO_FASTIOV으로 전달되었습니다. 여기서 fast_iov는 ___sys_sendmsg에서 지역 변수로 할당된 iovstack입니다. (0)에서 struct iovec의 갯수가 UIO_FASTIOV를 넘는 경우 버퍼를 동적 할당하고, 넘지 않는 경우 fast_iov을 사용하여 최대한 오버헤드를 제거합니다. 이후 (1)에서 유저 공간의 uvec 배열을 커널 공간으로 복사해옵니다. 

이제 __import_iovec로 돌아가서 (2)에서 호출되는 iov_iter_init를 살펴보겠습니다.
```c
void iov_iter_init(struct iov_iter *i, unsigned int direction,
			const struct iovec *iov, unsigned long nr_segs,
			size_t count)
{
	WARN_ON(direction & ~(READ | WRITE));
	*i = (struct iov_iter) {
		.iter_type = ITER_IOVEC,
		.nofault = false,
		.data_source = direction,
		.iov = iov,
		.nr_segs = nr_segs,
		.iov_offset = 0,
		.count = count
	};
}
```
struct iovec 배열을 struct iov_iter로 래핑하고 있는 모습입니다. 이 struct iov_iter는 struct msghdr에 저장됩니다.

이제 ___sys_sendmsg로 돌아가서, ____sys_sendmsg을 살펴보도록 하겠습니다.
```c
static int ____sys_sendmsg(struct socket *sock, struct msghdr *msg_sys,
			   unsigned int flags, struct used_address *used_address,
			   unsigned int allowed_msghdr_flags)
{
	unsigned char ctl[sizeof(struct cmsghdr) + 20]                          <===== (0)
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
		err =
		    cmsghdr_from_user_compat_to_kern(msg_sys, sock->sk, ctl,
						     sizeof(ctl));                                  <===== (1)
		if (err)
			goto out;
		ctl_buf = msg_sys->msg_control;
		ctl_len = msg_sys->msg_controllen;
	} else if (ctl_len) {                                                   
		BUILD_BUG_ON(sizeof(struct cmsghdr) !=
			     CMSG_ALIGN(sizeof(struct cmsghdr)));
		if (ctl_len > sizeof(ctl)) {                                        <===== (2)
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
	/*
	 * If this is sendmmsg() and current destination address is same as
	 * previously succeeded address, omit asking LSM's decision.
	 * used_address->name_len is initialized to UINT_MAX so that the first
	 * destination address never matches.
	 */
	if (used_address && msg_sys->msg_name &&                                <===== (3)
	    used_address->name_len == msg_sys->msg_namelen &&
	    !memcmp(&used_address->name, msg_sys->msg_name,
		    used_address->name_len)) {
		err = sock_sendmsg_nosec(sock, msg_sys);
		goto out_freectl;
	}
	err = sock_sendmsg(sock, msg_sys);                                      <===== (4)
	/*
	 * If this is sendmmsg() and sending to current destination address was
	 * successful, remember it.
	 */
	if (used_address && err >= 0) {                                         <===== (5)
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
(0)에 선언된 배열 ctl은 ___sys_sendmsg의 iovstack와 같이 최적화 용도로 사용되며 더 큰 버퍼가 필요한 경우 (1), (2)에서 새로운 버퍼가 동적 할당됩니다. (1)은 호환 모드이면서 제어 정보(보조 데이터)가 있는 경우에 실행되고 (2)는 제어 정보는 있지만 호환 모드가 아닌 경우 실행됩니다. 보조 데이터에 관해서는 여기서 다루지 않겠습니다. (3)은 sendmmsg에서 호출되었을 때, 목적지 주소가 이전 요청의 목적지 주소와 동일하며 성공한 요청이었을 때 보안 검사를 건너 뛰게 해주는 코드입니다. sendmsg에서 호출된 경우 (4)가 호출됩니다. (5)는 (3)을 위해 현재 요청의 주소 정보를 보관하는 코드입니다. 이제 드디어 소켓에 메세지를 전송하는 sock_sendmsg 함수를 살펴보겠습니다.

```c
int sock_sendmsg(struct socket *sock, struct msghdr *msg)
{
	int err = security_socket_sendmsg(sock, msg,            <===== (0)
					  msg_data_left(msg));

	return err ?: sock_sendmsg_nosec(sock, msg);            <===== (1)
}
```
(0)은 CONFIG_SECURITY_NETWORK 옵션이 설정된 경우 call_int_hook 함수를 통해 LSM(Linux Security Module)이 등록해둔 Hook 함수들을 호출하여 보안 검사를 실시합니다. 보안 검사에 통과했다면, (1)에서 소켓에 메시지를 전송하기 위한 함수를 호출합니다. sock_sendmsg_nosec 함수를 살펴보겠습니다.

```c
static inline int sock_sendmsg_nosec(struct socket *sock, struct msghdr *msg)
{
	int ret = INDIRECT_CALL_INET(sock->ops->sendmsg, inet6_sendmsg,             <===== (0)
				     inet_sendmsg, sock, msg,
				     msg_data_left(msg));
	BUG_ON(ret == -EIOCBQUEUED);                                                <===== (1)
	return ret;
}
```
(0)은 retpoline으로 인한 오버헤드를 최소화 하기 위한 처리가 되어있습니다. 소켓 도메인이 inet6거나 inet인 경우 함수 포인터로 간접 점프하지않고 바이너리 코드 세그먼트에 있는 주소로 직접 점프합니다. 어쨌든 sock->ops->sendmsg에 저장된 함수를 호출하게 되며, 이 값은 소켓을 생성할 때 초기화 되었습니다. netlink 도메인의 경우 netlink_sendmsg으로 초기화 됩니다. 이제 드디어 netlink 계층으로 넘어가, netlink_sendmsg를 살펴보겠습니다.