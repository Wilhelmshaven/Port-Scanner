#pragma once

//20�ֽ�TCP���Ķ��ײ�
class TCP_head
{
public:
	WORD source_port;     //Դ�˿ڣ�2�ֽ�
	WORD dest_port;       //Ŀ�Ķ˿ڣ�2�ֽ�
	DWORD seq_num;        //���кţ�4�ֽ�
	DWORD ack_num;        //ȷ�Ϻţ�4�ֽ�
	BYTE len;             //������ƫ�ƣ�TCP�ײ����ȣ���4bit����4bit����Ϊ��
	BYTE flags;           //ǰ2bitΪ�㣬�����λ��URG,ACK,PSH,RST,SYN,FIN
	WORD window_size;     //���ڴ�С��2�ֽ�
	WORD checksum;        //У��ͣ�2�ֽ�
	WORD URG;             //����URG��2�ֽ�
	
public:
	TCP_head(){};
	~TCP_head(){};

};

//12�ֽڵ�TCPα�ײ�������У��ͼ���
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

//28�ֽ�ARP���ݱ��ṹ
class ARP_head
{
public:
	WORD hardware_type;      //Ӳ������,2�ֽ�
	WORD protocol_type;      //Э�����ͣ�2�ֽ�
	BYTE hardware_add_len;   //Ӳ����ַ���ȣ�1�ֽ�
	BYTE protocol_add_len;   //Э���ַ���ȣ�1�ֽ�
	WORD operation_field;    //�����ֶΣ�2�ֽ�
	BYTE source_mac_add[6];  //Դmac��ַ��6�ֽ�
	DWORD source_ip_add;     //Դip��ַ��4�ֽ�
	BYTE dest_mac_add[6];    //Ŀ��mac��ַ��6�ֽ�
	DWORD dest_ip_add;       //Ŀ��ip��ַ��4�ֽ�

public:
	ARP_head();
	~ARP_head(){};
};

//20�ֽ�IP���ݱ�ͷ�ṹ
class IP_head
{
public:
	BYTE versionAndIHL;         //�汾���ײ����ȣ�1�ֽڣ�ǰ4λ��4λ�ֿ�
	BYTE service;               //���ַ���1�ֽ�
	WORD length;                //�ܳ��ȣ�2�ֽ�
	WORD id;                    //��ʶ��2�ֽ�
	WORD flagAndOffset;         //��־��Ƭƫ�ƣ�2�ֽڣ�ǰ3λ��13λ�ֿ�
	BYTE TTL;                   //����ʱ�䣬1�ֽ�
	BYTE protocol;              //Э�飬1�ֽ�
	WORD checksum;              //�ײ�У��ͣ�2�ֽ�
	DWORD source_add;           //Դ��ַ��4�ֽ�
	DWORD dest_add;             //Ŀ�ĵ�ַ��4�ֽ�

public:
	IP_head(){};
	~IP_head(){};

};

//14�ֽ���̫��֡�ṹ
class ethernet_head
{
public:
	BYTE dest_mac_add[6];    //Ŀ��mac��ַ��6�ֽ�
	BYTE source_mac_add[6];  //Դmac��ַ��6�ֽ�
	WORD type;               //֡���ͣ�2�ֽ�

public:
	ethernet_head();
	~ethernet_head(){};
};

//arp����֡
class ARP_frame
{
public:
	ethernet_head eh;
	ARP_head ah;
	BYTE padding[18];
	//BYTE fcs[4];       //��������һ�Σ���������ֻ�ܱ��Զ����ϣ�

public:
	ARP_frame(){};
	~ARP_frame(){};

};

//TCP֡
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