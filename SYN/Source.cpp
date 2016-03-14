#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <time.h>//计时用到的头文件
#include "mstcpip.h"
#pragma comment(lib,"ws2_32.lib") //winsock 程序必须用到的库文件
#define SEQ 0x28376839 //自定义数据包的序列号

SOCKET sockRaw = INVALID_SOCKET; //发送数据的 sock 句柄
SOCKET sockListen = INVALID_SOCKET; //接收数据的 sock 句柄
struct sockaddr_in dest; //目标主机地址结构
BOOL ScanOK = FALSE; //扫描是否结束
char *DEST_HOST; //贮存命令行下的目标主机 IP
int DEST_PORT; //开始扫描的端口
int DEST_PORTEND; //结束端口
int play = 0; //用于进度显示
clock_t start, end; //程序运行的起始和结束时间
float costtime; //程序耗时
/*“下面是 IP 和 TCP 头的结构，我们构造的数据包就是贮存在这个结构中。”*/
typedef struct _iphdr
{
	unsigned char h_lenver; //4 位首部长度+4 位 IP 版本号
	unsigned char tos; //8 位服务类型 TOS
	unsigned short total_len; //16 位总长度（字节）
	unsigned short ident; //16 位标识
	unsigned short frag_and_flags; //3 位标志位
	unsigned char ttl; //8 位生存时间 TTL
	unsigned char proto; //8 位协议 (TCP, UDP 或其他)
	unsigned short checksum; //16 位 IP 首部校验和
	unsigned int sourceIP; //32 位源 IP 地址
	unsigned int destIP; //32 位目的 IP 地址
}IP_HEADER;
typedef struct _tcphdr //定义 TCP 首部
{
	USHORT th_sport; //16 位源端口
	USHORT th_dport; //16 位目的端口
	unsigned int th_seq; //32 位序列号
	unsigned int th_ack; //32 位确认号
	unsigned char th_lenres; //4 位首部长度/6 位保留字
	unsigned char th_flag; //6 位标志位
	USHORT th_win; //16 位窗口大小
	USHORT th_sum; //16 位校验和
	USHORT th_urp; //16 位紧急数据偏移量
}TCP_HEADER;
struct //定义 TCP 伪首部
{
	unsigned long saddr; //源地址
	unsigned long daddr; //目的地址
	char mbz;
	char ptcl; //协议类型
	unsigned short tcpl; //TCP 长度
}psd_header;

//SOCK 错误处理程序
void CheckSockError(int iErrorCode, char *pErrorMsg)
{
	if (iErrorCode == SOCKET_ERROR)
	{
		printf("%s Error:%d\n", pErrorMsg, GetLastError());
		closesocket(sockRaw);
		ExitProcess(-1);
	}
}

/*“目标收到 SYN 数据包，要对其进行校验，目的是保证数据包的正确性。我们因
为是自己构造数据包，所以要自己进行计算校验和。利用到的函数如下：*/
//计算检验和
USHORT checksum(USHORT *buffer, int size)
{
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

//“以下是 IP 解包函数，分析接收到的 SYN 数据包来确定目标端口是否开放。”

//IP 解包函数
bool DecodeIPHeader(char *buf, int bytes)
{
	IP_HEADER *iphdr;
	TCP_HEADER *tcphdr;
	unsigned short iphdrlen;
	iphdr = (IP_HEADER *)buf;
	iphdrlen = sizeof(unsigned long) * (iphdr->h_lenver & 0xf);
	tcphdr = (TCP_HEADER*)(buf + iphdrlen);
	//是否来自目标 IP
	if (iphdr->sourceIP != dest.sin_addr.s_addr) 
		return false;
	//序列号是否正确
	if ((ntohl(tcphdr->th_ack) != (SEQ + 1)) && (ntohl(tcphdr->th_ack) != SEQ)) 
		return false;
	//if(tcphdr->th_flag == 20)return true;
	//20 端口关闭的标志，可以不做处理以提高速度
	if (tcphdr->th_flag == 18) //SYN/ACK - 扫描到一个端口
	{
		printf("\t%d\t open \n", ntohs(tcphdr->th_sport));
		return true;
	}
	return true;
}

/*“显示帮助信息的函数”*/
void usage(void)
{
	printf("\t===================SYN portscaner======================\n");
	printf("\t============gxisone@hotmail.com 2004/7/6===========\n");
	printf("\t============Welcome to www.baidu.com============\n");
	printf("\tusage: synscan DomainName[IP] StartPort-EndPort\n");
	printf("\tExample: synscan www.163.com 1-139\n");
	printf("\tExample: synscan 192.168.1.1 8000-9000\n");
}

//“下面是监听的线程函数，主要用到的是 raw sock”
DWORD WINAPI RecvThread(LPVOID para)//接收数据线程函数
{
	int iErrorCode; //sock 错误代码
	struct hostent *hp;
	char RecvBuf[65535] = { 0 }; //接收数据的缓冲区
								 //使用 SOCK_RAW,接收 TCP 数据
	sockListen = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	CheckSockError(sockListen, "socket");//检查错误
										 //设置 IP 头操作选项
	BOOL bOpt = true;
	iErrorCode = setsockopt(sockRaw, IPPROTO_IP, IP_HDRINCL, (char
		*)&bOpt, sizeof(bOpt));
	CheckSockError(iErrorCode, "setsockopt()");
	//获得本地 IP
	SOCKADDR_IN sa;
	unsigned char LocalName[256];
	iErrorCode = gethostname((char*)LocalName, sizeof(LocalName) - 1);
	CheckSockError(iErrorCode, "gethostname()");
	if ((hp = gethostbyname((char*)LocalName)) == NULL)
	{
		CheckSockError(SOCKET_ERROR, "gethostbyname()");
	}
	memcpy(&sa.sin_addr.S_un.S_addr, hp->h_addr_list[0], hp->h_length);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(7000);
	//绑定任意端口
	iErrorCode = bind(sockListen, (PSOCKADDR)&sa, sizeof(sa));
	CheckSockError(iErrorCode, "bind");
	//设置 SOCK_RAW 为 SIO_RCVALL，以便接收所有的 IP 包
	DWORD dwBufferLen[10];
	DWORD dwBufferInLen = 1;
	DWORD dwBytesReturned = 0;
	iErrorCode = WSAIoctl(sockListen, SIO_RCVALL, &dwBufferInLen,
		sizeof(dwBufferInLen), &dwBufferLen, sizeof(dwBufferLen), &dwBytesReturned, NULL,
		NULL);
	CheckSockError(iErrorCode, "Ioctl");
	memset(RecvBuf, 0, sizeof(RecvBuf));
	//接收数据
	for (;;) //for(;;)比 while(true)要快哦，看汇编就会知道
	{
		iErrorCode = recv(sockListen, RecvBuf, sizeof(RecvBuf), 0);
		DecodeIPHeader(RecvBuf, iErrorCode);
	}
	if (ScanOK) //如果扫描完成就关闭套接字并结束本监听线程
	{
		closesocket(sockListen);
		return 0;
	}
}


/*“进度提示函数”*/
void playx(void) // 定义状态提示函数
{
	// 进度条
	char *plays[12] = {
		" | ",
		" / ",
		" - ",
		" \\ ",
		" | ",
		" / ",
		" - ",
		" \\ ",
		" | ",
		" / ",
		" - ",
		" \\ ",
	};
	printf(" =%s=\r", plays[play]);
	play = (play == 11) ? 0 : play + 1;
	Sleep(2);
}
/*“上面显示进度的函数是在主线程发送数据时显示的，这里必须设置一个
Sleep（）函数，因为如果不设置，主线程发送 SYN 包的速度非常快，有可能监
听线程处理返回数据不够快而丢失了 SYN 包，从而令扫描结果出现错误。在机器
配置或网速比较慢的环境里适当提高这个 Sleep（）的数值可以提高扫描的准确
性。大家可以加多一个参数作为这个 Sleep 的值，这就留代大家亲自改进了。”*/

int main()//int argc, char **argv)
{
	int argc = 3;
	char par1[] = "NULL",
		par2[] = "192.168.56.101",
		par3[] = "12233-12234";
	char *argv[3];
	argv[0] = par1;
	argv[1] = par2;
	argv[2] = par3;
	char *p;
	if (argc != 3) //判断参数个数
	{
		usage(); //显示帮助信息
		return 0;
	}
	p = argv[2];//处理端口参数
	if (strstr(argv[2], "-"))
	{
		DEST_PORT = atoi(argv[2]);
		for (; *p;)
			if (*(p++) == '-')break;
		DEST_PORTEND = atoi(p);

		if (DEST_PORT<1 || DEST_PORTEND>65535)
		{
			printf("Port Error!\n");
			return 0;
		}
	}
	DEST_HOST = argv[1];//取得目标主机域名或 IP
	usage();
	int iErrorCode;
	int datasize;
	struct hostent *hp;
	IP_HEADER ip_header;
	TCP_HEADER tcp_header;
	char SendBuf[128] = { 0 };
	//初始化 SOCKET
	WSADATA wsaData;
	iErrorCode = WSAStartup(MAKEWORD(2, 2), &wsaData);
	CheckSockError(iErrorCode, "WSAStartup()");
	sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	CheckSockError(sockRaw, "socket()");
	sockListen = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	CheckSockError(sockListen, "socket");
	//设置 IP 头操作选项
	BOOL bOpt = true;
	iErrorCode = setsockopt(sockRaw, IPPROTO_IP, IP_HDRINCL, (char
		*)&bOpt, sizeof(bOpt));
	CheckSockError(iErrorCode, "setsockopt()");
	//获得本地 IP
	SOCKADDR_IN sa;
	unsigned char LocalName[256];
	iErrorCode = gethostname((char*)LocalName, sizeof(LocalName) - 1);
	CheckSockError(iErrorCode, "gethostname()");
	if ((hp = gethostbyname((char*)LocalName)) == NULL)
	{
		CheckSockError(SOCKET_ERROR, "gethostbyname()");
	}
	memcpy(&sa.sin_addr.S_un.S_addr, hp->h_addr_list[0], hp->h_length);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(7000);
	iErrorCode = bind(sockListen, (PSOCKADDR)&sa, sizeof(sa));
	CheckSockError(iErrorCode, "bind");
	//获得目标主机 IP
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(DEST_PORT);
	if ((dest.sin_addr.s_addr = inet_addr(DEST_HOST)) == INADDR_NONE)
	{
		if ((hp = gethostbyname(DEST_HOST)) != NULL)
		{
			memcpy(&(dest.sin_addr), hp->h_addr_list[0], hp->h_length);
			dest.sin_family = hp->h_addrtype;
			printf("dest.sin_addr = %s\n", inet_ntoa(dest.sin_addr));
		}
		else
		{
			CheckSockError(SOCKET_ERROR, "gethostbyname()");
		}
	}
	//开启监听线程
	HANDLE Thread = CreateThread(NULL, 0, RecvThread, 0, 0, 0);
	//填充 IP 首部
	ip_header.h_lenver = (4 << 4 | sizeof(ip_header) / sizeof(unsigned long));
	//高四位 IP 版本号，低四位首部长度
	ip_header.total_len = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER)); //16 位总长度（字节）
		ip_header.ident = 1; //16 位标识
	ip_header.frag_and_flags = 0; //3 位标志位
	ip_header.ttl = 128; //8 位生存时间 TTL
	ip_header.proto = IPPROTO_TCP; //8 位协议(TCP,UDP…)
	ip_header.checksum = 0; //16 位 IP 首部校验和
	ip_header.sourceIP = sa.sin_addr.s_addr; //32 位源 IP 地址
	ip_header.destIP = dest.sin_addr.s_addr; //32 位目的 IP 地址
											 //填充 TCP 首部
	tcp_header.th_sport = htons(7000); //源端口号
	tcp_header.th_lenres = (sizeof(TCP_HEADER) / 4 << 4 | 0); //TCP 长度和保留位
	tcp_header.th_win = htons(16384); //窗口大小
									  //填充 TCP 伪首部（用于计算校验和，并不真正发送）
	psd_header.saddr = ip_header.sourceIP;
	psd_header.daddr = ip_header.destIP;
	psd_header.mbz = 0;
	psd_header.ptcl = IPPROTO_TCP;
	psd_header.tcpl = htons(sizeof(tcp_header));
	Sleep(100);
	printf("\n");
	printf("Scaning %s\n", DEST_HOST);
	start = clock();//开始计时
	for (; DEST_PORT<DEST_PORTEND; DEST_PORT++)//循环发送 SYN 数据包
	{
		playx(); //显示扫描状态
		tcp_header.th_dport = htons(DEST_PORT); //目的端口号
		tcp_header.th_ack = 0; //ACK 序列号置为 0
		tcp_header.th_flag = 2; //SYN 标志
		tcp_header.th_seq = htonl(SEQ); //SYN 序列号
		tcp_header.th_urp = 0; //偏移
		tcp_header.th_sum = 0; //校验和
							   //计算 TCP 校验和，计算校验和时需要包括 TCP pseudo header
		memcpy(SendBuf, &psd_header, sizeof(psd_header));
		memcpy(SendBuf + sizeof(psd_header), &tcp_header, sizeof(tcp_header));
		tcp_header.th_sum = checksum((USHORT
			*)SendBuf, sizeof(psd_header) + sizeof(tcp_header));
		//计算 IP 校验和
		memcpy(SendBuf, &ip_header, sizeof(ip_header));
		memcpy(SendBuf + sizeof(ip_header), &tcp_header, sizeof(tcp_header));
		memset(SendBuf + sizeof(ip_header) + sizeof(tcp_header), 0, 4);
		datasize = sizeof(ip_header) + sizeof(tcp_header);
		ip_header.checksum = checksum((USHORT *)SendBuf, datasize);
		//填充发送缓冲区
		memcpy(SendBuf, &ip_header, sizeof(ip_header));
		//发送 TCP 报文
		iErrorCode = sendto(sockRaw, SendBuf, datasize, 0, (struct sockaddr*) &dest,
			sizeof(dest));
		CheckSockError(iErrorCode, "sendto()");
	}
	end = clock();//计时结束
	ScanOK = TRUE;//扫描完成
	printf("Closing Thread.....\n");
	WaitForSingleObject(Thread, 5000); //等待监听线程返回
	CloseHandle(Thread); //关闭线程句柄，释放资源
	costtime = (float)(end - start) / CLOCKS_PER_SEC; //转换时间格式
	printf("Cost time:%f Sec", costtime);//显示耗时
										 //退出前清理
	if (sockRaw != INVALID_SOCKET) closesocket(sockRaw);
	WSACleanup();
	system("PAUSE");
	return 0;
}
