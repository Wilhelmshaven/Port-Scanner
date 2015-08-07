#pragma once

//20字节TCP报文段首部
class TCP_head
{
public:
	WORD source_port;     //源端口，2字节
	WORD dest_port;       //目的端口，2字节
	DWORD seq_num;        //序列号，4字节
	DWORD ack_num;        //确认号，4字节
	BYTE len;             //（数据偏移）TCP首部长度，仅4bit，后4bit必须为零
	BYTE flags;           //前2bit为零，后面各位是URG,ACK,PSH,RST,SYN,FIN
	WORD window_size;     //窗口大小，2字节
	WORD checksum;        //校验和，2字节
	WORD URG;             //紧急URG，2字节
	
public:
	TCP_head(){};
	~TCP_head(){};

};

//12字节的TCP伪首部，参与校验和计算
class Psedo_TCP_head
{
public:
	DWORD source_addr;
	DWORD dest_addr;
	BYTE zero;
	BYTE protocol;
	WORD seg_len;

public:
	Psedo_TCP_head()
	{
		zero = 0;
		protocol = 0;
	}
	~Psedo_TCP_head(){};
};

//28字节ARP数据报结构
class ARP_head
{
public:
	WORD hardware_type;      //硬件类型,2字节
	WORD protocol_type;      //协议类型，2字节
	BYTE hardware_add_len;   //硬件地址长度，1字节
	BYTE protocol_add_len;   //协议地址长度，1字节
	WORD operation_field;    //操作字段，2字节
	BYTE source_mac_add[6];  //源mac地址，6字节
	DWORD source_ip_add;     //源ip地址，4字节
	BYTE dest_mac_add[6];    //目的mac地址，6字节
	DWORD dest_ip_add;       //目的ip地址，4字节

public:
	ARP_head();
	~ARP_head(){};
};

//20字节IP数据报头结构
class IP_head
{
public:
	BYTE versionAndIHL;         //版本与首部长度，1字节，前4位后4位分开
	BYTE service;               //区分服务，1字节
	WORD length;                //总长度，2字节
	WORD id;                    //标识，2字节
	WORD flagAndOffset;         //标志和片偏移，2字节，前3位后13位分开
	BYTE TTL;                   //生存时间，1字节
	BYTE protocol;              //协议，1字节
	WORD checksum;              //首部校验和，2字节
	DWORD source_add;           //源地址，4字节
	DWORD dest_add;             //目的地址，4字节

public:
	IP_head(){};
	~IP_head(){};

};

//14字节以太网帧结构
class ethernet_head
{
public:
	BYTE dest_mac_add[6];    //目的mac地址，6字节
	BYTE source_mac_add[6];  //源mac地址，6字节
	WORD type;               //帧类型，2字节

public:
	ethernet_head();
	~ethernet_head(){};
};

//arp数据帧
class ARP_frame
{
public:
	ethernet_head eh;
	ARP_head ah;
	BYTE padding[18];
	//BYTE fcs[4];       //不能有这一段，否则会出错（只能被自动加上）

public:
	ARP_frame(){};
	~ARP_frame(){};

};

//TCP帧
class TCP_frame
{
public:
	ethernet_head eh;
	IP_head ih;
	TCP_head th;

public:
	WORD cks(WORD* buffer, int size);

	TCP_frame(){};
	~TCP_frame(){};
};