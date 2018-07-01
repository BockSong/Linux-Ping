#include "ping.h"

struct proto	proto_v4 = { proc_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP };

#ifdef	IPV6
struct proto	proto_v6 = { proc_v6, send_v6, NULL, NULL, 0, IPPROTO_ICMPV6 };
#endif

int	datalen=56;		/* data that goes with ICMP echo request */


//单词最长最短响应时间
double rtt_min = INFINITY;
double rtt_max = -INFINITY;
//总共响应时间
double rtt_total = 0;

//实际发送接收包数量
long long send_package_count = 0, receive_package_count = 0;

//自己预设数量
int ttl = 0;
int count=0;

//各种信号
int ttl_flag = 0;
int broadcast_flag = 0;
int quiet_flag = 0;
int count_flag = 0;

//全局开始时间
struct timeval tval_start;

int main(int argc, char **argv)
{
	int	c;
	struct addrinfo	*ai;
	opterr = 0;		/* don't want getopt() writing to stderr */
	while ( (c = getopt(argc, argv, "vhbqs:c:t:")) != -1)
	{
		switch (c)
		{
			case 'v':
				verbose++;
				break;
			case 'h':
			  printhelp();
				return 0;
			case 'b':
				broadcast_flag = 1;
				break;
			case 'c':
				if(sscanf(optarg,"%d",&count)==1 && count>= 0)
					count_flag = 1;
				break;
			case 's':
				sscanf(optarg,"%d",&datalen);
				break;
			case 't':
				if(sscanf(optarg, "%d", &ttl)==1 && ttl >= 0 && ttl < 256)
				ttl_flag = 1;
				break;
		  case 'q':
				quiet_flag = 1;
				break;
			 case '?':
				err_quit("unrecognized option: %c", c);
		}
	}
if (optind != argc-1)
		err_quit("usage: ping [ -v ] <hostname>");
	host = argv[optind];

	pid = getpid();
//设置某一信号的对应动作
	signal(SIGALRM, sig_alrm);

	ai = host_serv(host, NULL, 0, 0);

//cannoname :域名
	printf("ping %s (%s): %d data bytes\n", ai->ai_canonname,
		Sock_ntop_host(ai->ai_addr, ai->ai_addrlen), datalen);

	/* 4initialize according to protocol */
	if (ai->ai_family == AF_INET)
	{
		pr = &proto_v4;
#ifdef	IPV6
	} else if (ai->ai_family == AF_INET6)
	{
		pr = &proto_v6;
		if (IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)
			ai->ai_addr)->sin6_addr)))
			err_quit("cannot ping IPv4-mapped IPv6 address");
#endif
	} else
		err_quit("unknown address family %d", ai->ai_family);

//设置某一信号的对应动作
// SIGINT
// 程序终止(interrupt)信号, 在用户键入INTR字符(通常是Ctrl-C)时发出，用于通知前台进程组终止进程。
	signal(SIGINT, sig_interrupt);

//设置ipv4发送接收地址
	pr->sasend = ai->ai_addr;
  pr->sarecv = calloc(1, ai->ai_addrlen);
	pr->salen = ai->ai_addrlen;

	gettimeofday(&tval_start, NULL);
//接收ICMP数据包并处理函数调用
	readloop();
	exit(0);
}

/*ipv4解析下对数据包的解析函数，就是分析接收到的数据包*/
void proc_v4(char *ptr, ssize_t len, struct timeval *tvrecv)
{
	int				hlen1, icmplen,i;
	double			rtt;
	struct ip		*ip;
	struct icmp		*icmp;
	struct timeval	*tvsend;

//IP头部指针
	ip = (struct ip *) ptr;		/* start of IP header */

//IP头部长度。它是以4字节为一个单位计数的，将它乘以4才是以字节为单位的头部长度
	hlen1 = ip->ip_hl << 2;		/* length of IP header */

	icmp = (struct icmp *) (ptr + hlen1);	/* start of ICMP header */
	if ( (icmplen = len - hlen1) < 8)
		err_quit("icmplen (%d) < 8", icmplen);

//如果是ICMP回射响应，那么检查标识符字段，这个响应是不是这个进程发出的请求的响应
	if (icmp->icmp_type == ICMP_ECHOREPLY)
	{
		if (icmp->icmp_id != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (icmplen < 16)
			err_quit("icmplen (%d) < 16", icmplen);

		tvsend = (struct timeval *) icmp->icmp_data;
		tv_sub(tvrecv, tvsend);//将时间写入tvrecv
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		if (rtt < rtt_min) rtt_min = rtt;
		if (rtt > rtt_max) rtt_max = rtt;
		rtt_total += rtt;
		receive_package_count++;

		if( quiet_flag!=1 && ttl<256 )
		{
			printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
				icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp->icmp_seq, ip->ip_ttl, rtt);

			if(icmp->icmp_seq==(count-1))
			{
				struct timeval tval_end;
				double tval_total;
				gettimeofday(&tval_end, NULL);
				tv_sub(&tval_end, &tval_start);
				tval_total = tval_end.tv_sec * 1000.0 + tval_end.tv_usec / 1000.0;

        puts("---  ping  数据分析 ---");
				printf("一共发送%lld个数据包, 接收到%lld个, 丢失率%.0lf%%, 总共发送时间%.2lfms\n",
				send_package_count, receive_package_count, (send_package_count - receive_package_count) * 100.0 / send_package_count, tval_total);

				double rtt_avg = rtt_total / receive_package_count;
				printf("rtt min/avg/max = %.3lf/%.3lf/%.3lf ms\n", rtt_min, rtt_avg, rtt_max);

				close(sockfd);
				exit(0);
			}
		}
	}
	else if (verbose)
	{
		printf("  %d bytes from %s: type = %d, code = %d\n",
			icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
			icmp->icmp_type, icmp->icmp_code);
	}
}

/*ipv6解析下对数据包的解析函数，就是分析接收到的数据包*/
void proc_v6(char *ptr, ssize_t len, struct timeval* tvrecv)
{
#ifdef	IPV6
	int					hlen1, icmp6len;
	double				rtt;
	struct ip6_hdr		*ip6;
		struct icmp6_hdr	*icmp6;
	struct timeval		*tvsend;

	ip6 = (struct ip6_hdr *) ptr;		/* start of IPv6 header */
	hlen1 = sizeof(struct ip6_hdr);
	if (ip6->ip6_nxt != IPPROTO_ICMPV6)
		err_quit("next header not IPPROTO_ICMPV6");
	icmp6 = (struct icmp6_hdr *) (ptr + hlen1);
	if ( (icmp6len = len - hlen1) < 8)
		err_quit("icmp6len (%d) < 8", icmp6len);

	if (icmp6->icmp6_type == ICMP6_ECHO_REPLY)
	{
		if (icmp6->icmp6_id != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (icmp6len < 16)
		err_quit("icmp6len (%d) < 16", icmp6len);
		tvsend = (struct timeval *) (icmp6 + 1);
		tv_sub(tvrecv, tvsend);
	    rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		if (rtt < rtt_min) rtt_min = rtt;
		if (rtt > rtt_max) rtt_max = rtt;
		rtt_total += rtt;
		receive_package_count++;

		if ( quiet_flag!=1 )
			printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
			icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
			icmp->icmp_seq, ip->ip_ttl, rtt);

	}
	else if (verbose)
	{
		printf("  %d bytes from %s: type = %d, code = %d\n",
			icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
			icmp->icmp_type, icmp->icmp_code);
	}
#endif	/* IPV6 */
}

//校验和计算函数
unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short  *w = addr;
	unsigned short  answer = 0;

	/*把ICMP报头二进制数据以二字节为单位累加起来*/
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}
	/* 4mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(unsigned char *)w ;
		sum += answer;
	}
	/* 4add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	sum += (sum >> 16);                     /* add carry将溢出位加入  */
	answer = ~sum;                          /* truncate to 16 bits */
	return(answer);
}

/*IPv4下的填充并发送ICMP报文函数*/
void send_v4(void)
{
	int	len;
	struct icmp	*icmp;
//将sendpacket强制转换成icmp头结构，然后发送
	icmp = (struct icmp *) sendbuf;
//填写报文类型，ping的功能码
	icmp->icmp_type = ICMP_ECHO;
//发送默认
	icmp->icmp_code = 0;
//填写自己的id
	icmp->icmp_id = pid;
//填写ICMP报文序号，并增加序号
	icmp->icmp_seq = nsent++;
//记录发送时间
	gettimeofday((struct timeval *) icmp->icmp_data, NULL);

	len = 8 + datalen;		/* checksum ICMP header and data */
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short *) icmp, len);
//发送IP数据包
	sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
}

//IPv6下的填充并发送ICMP报文函数
void send_v6()
{
#ifdef	IPV6
	int	len;
	struct icmp6_hdr	*icmp6;
//将发送缓冲区强制转换成icmp格式
	icmp6 = (struct icmp6_hdr *) sendbuf;
//报文类型
	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_id = pid;
//填写ICMP报文序号，并增加序号
	icmp6->icmp6_seq = nsent++;
	gettimeofday((struct timeval *) (icmp6 + 1), NULL);
	len = 8 + datalen;		/* 8-byte ICMPv6 header */
//发送ICMP报文
	sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
#endif	/* IPV6 */
}

//接受包含ICMP报文的IP数据包
void readloop(void)
{
	int	size;
	char recvbuf[BUFSIZE];
	socklen_t	len;
	ssize_t	n;
	struct timeval	tval;

//初始化套接字
	sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
//为安全起见，将进程的有效用户ID设成进程的实际用户ID
	setuid(getuid());		/* don't need special permissions any more */

// int setsockopt( int socket, int level, int option_name,const void *option_value, size_t option_len);
// 第一个参数socket是套接字描述符
// 第二个参数level是被设置的选项的级别，如果想要在套接字级别上设置选项，就必须把level设置为 SOL_SOCKET
// option_name指定准备设置的选项，option_name可以有哪些取值，这取决于level

//将套接口接收缓冲区设为61440字节，主要是为了减少接收缓冲区溢出的可能性
	size = 60 * 1024;		/* OK if setsockopt fails */
//设置套接字选项   如果想要在套接字级别上设置选项，就必须把level设置为 SOL_SOCKET
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

//设置生存周期
	if (ttl_flag)
		setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

//设置广播地址 SO_BROADCAST，允许或禁止发送广播数据  当option_value不等于0时，允许，否则，禁止。
	if (broadcast_flag)
		setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast_flag, sizeof(broadcast_flag));

//发送第一个数据包
	sig_alrm(SIGALRM);		/* send first packet */

	//不停的接受icmp数据包
	for ( ; ; )
	{
		len = pr->salen;
		n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			else
				err_sys("recvfrom error");
		}
		gettimeofday(&tval, NULL);
		(*pr->fproc)(recvbuf, n, &tval);
	}
}

/*定时发送数据包*/
void sig_alrm(int signo)
{
	(*pr->fsend)();
	send_package_count++;
	alarm(1);
	return;         /* probably interrupts recvfrom() */
}

void sig_interrupt(int signo)
{
	struct timeval tval_end;
	double tval_total;
	gettimeofday(&tval_end, NULL);
	tv_sub(&tval_end, &tval_start);
	tval_total = tval_end.tv_sec * 1000.0 + tval_end.tv_usec / 1000.0;

	puts("---  ping  数据分析 ---");
	printf("一共发送%lld个数据包, 接收到%lld个, 丢失率%.0lf%%, 总共发送时间%.2lfms\n",
					send_package_count,receive_package_count,(send_package_count - receive_package_count) * 100.0 / send_package_count, tval_total);

	double rtt_avg = rtt_total / receive_package_count;
	printf("rtt min/avg/max = %.3lf/%.3lf/%.3lf ms\n", rtt_min, rtt_avg, rtt_max);
	close(sockfd);
	exit(0);
}

/*两个timeval结构相减，计算时间差*/
void tv_sub(struct timeval *out, struct timeval *in)
{
	if ( (out->tv_usec -= in->tv_usec) < 0) {	/* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}//如果接收时间的usec小于发送时间,从usec域借位
	out->tv_sec -= in->tv_sec;
}


/*这是一个网络字节序的转化函数，为了统一不同系统之间的兼容性，
在网络编程中，都需要将套接字先转换成网络字节序，然后在传输，
以免不同系统的编码规则照成错误解析*/
char * sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
	static char str[128];               /* Unix domain is largest */
	switch (sa->sa_family)
	{
	case AF_INET:
	{
		struct sockaddr_in *sin = (struct sockaddr_in *) sa;
		if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
			return(NULL);
		return(str);
	}
#ifdef  IPV6   //如果在IPv6情况下
	case AF_INET6:
	{
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
		if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL)
			return(NULL);
		return(str);
 	}
#endif
#ifdef  HAVE_SOCKADDR_DL_STRUCT
	case AF_LINK:
	{
		struct sockaddr_dl *sdl = (struct sockaddr_dl *) sa;

		if (sdl->sdl_nlen > 0)
			snprintf(str, sizeof(str), "%*s",
			sdl->sdl_nlen, &sdl->sdl_data[0]);
		else
			snprintf(str, sizeof(str), "AF_LINK, index=%d", sdl->sdl_index);
		return(str);
	 }
#endif
	default:
		snprintf(str, sizeof(str), "sock_ntop_host: unknown AF_xxx: %d, len %d",
		sa->sa_family, salen);
		return(str);
	}
	return (NULL);
}

char * Sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
	char    *ptr;
	if ( (ptr = sock_ntop_host(sa, salen)) == NULL)
		err_sys("sock_ntop_host error");        /* inet_ntop() sets errno */
	return(ptr);
}

//  解析域名对应的 IP
struct addrinfo *host_serv(const char *host, const char *serv, int family, int socktype)   //这是一个填充地址信息结构的函数
{
	int   n;
	struct addrinfo hints, *res;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;  /* always return canonical name */
	hints.ai_family = family;               /* AF_UNSPEC, AF_INET, AF_INET6, etc. */
	hints.ai_socktype = socktype;   /* 0, SOCK_STREAM, SOCK_DGRAM, etc. */
	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
	return(NULL);
	return(res);    /* return pointer to first on linked list */
}

/* end host_serv */
//错误处理函数
static void err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
	int             errno_save, n;
	char    buf[MAXLINE];
	errno_save = errno;             /* value caller might want printed */
#ifdef  HAVE_VSNPRINTF
	vsnprintf(buf, sizeof(buf), fmt, ap);   /* this is safe */
#else
	vsprintf(buf, fmt, ap);                                 /* this is not safe */
#endif
	n = strlen(buf);
	if (errnoflag)
		snprintf(buf+n, sizeof(buf)-n, ": %s", strerror(errno_save));
	strcat(buf, "\n");
	if (daemon_proc) {
		syslog(level, buf,NULL);
	} else {
		fflush(stdout);         /* in case stdout and stderr are the same */
		fputs(buf, stderr);
		fflush(stderr);
	}
	return;
}
/* Fatal error unrelated to a system call.
* Print a message and terminate. */

//错误退出函数
void err_quit(const char *fmt, ...)
{
	va_list         ap;//va_list是在C语言中解决变参问题的一组宏，所在头文件：#include <stdarg.h>
	va_start(ap, fmt);
	//获取可变参数列表的第一个参数的地址
	//（ap是类型为va_list的指针，v是可变参数最左边的参数）
	err_doit(0, LOG_ERR, fmt, ap);
	va_end(ap);//清空va_list可变参数列表
	exit(1);
}

/* Fatal error related to a system call.
* Print a message and terminate. */

void err_sys(const char *fmt, ...)
{
	va_list         ap;

	va_start(ap, fmt);
	err_doit(1, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void printhelp()
{
	printf("-h	         显示帮助信息 \n");
	printf("-c  parameter    发送指定数据包数量\n");
	printf("-s  parameter    指定发送的数据字节数\n");
	printf("-t  parameter    设置ttl值，只用于IPv4\n");
	printf("-b               ping一个广播地址，只用于IPv4\n");
	printf("-q	         安静模式。不显示每个收到的包的分析结果，只在结束时显示汇总结果 \n");
}
//tcpdump -n icmp -v
