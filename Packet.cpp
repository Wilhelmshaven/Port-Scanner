#include "stdafx.h"
#include "Packet.h"

//初始化以太网帧头
ethernet_head::ethernet_head()
{
	memset(dest_mac_add, 0xff, 6);
	memset(source_mac_add, 0xff, 6);
}

//初始化ARP报结构
ARP_head::ARP_head()
{
	memset(dest_mac_add, 0xff, 6);  //初始化为广播地址
	hardware_add_len = 6;
	protocol_add_len = 4;
}

WORD TCP_frame::cks(WORD* buffer, int size)
{
	unsigned long cksum = 0;
	while (size>1)
	{
		cksum += *buffer++;
		size -= sizeof(WORD);                //按双字节（16位）对齐
	}
	if (size)
	{
		cksum += *(BYTE*)buffer;             //二进制反码求和
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);//将高16bit与低16bit相加
	cksum += (cksum >> 16);                  //将进位到高位的16bit与低16bit 再相加
	return (WORD)(~cksum);
}
