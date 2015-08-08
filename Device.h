//�豸��
class Device
{
public:
	pcap_if_t *alldevs;   //�豸�б�
	pcap_t *adhandle;     //��ǰ�豸
	char *ip;             //�Լ���IP
	char *netmask;        //�Լ�����������
	char *mac;            //�Լ���MAC��ַ��ʮ�����ƣ�
	char *macStr;         //�Լ���MAC��ַ���ַ�����
	char *gateway_ip;     //����IP��ַ
	char *gatewayMAC;     //����MAC��ַ��ʮ�����ƣ�
	char *gatewayMACStr;  //����MAC��ַ���ַ�����

private:
	char *errbuf;         //���󻺴�

private:

	int OpenDevice(pcap_if_t *d);//���豸
	void GetInfo(pcap_if_t *d);  //��ø�������IP���������롢MAC��ַ������IP

public:
	void DeviceGetReady(int option); //�������

	//���������͵�IP��ַת�����ַ������͵�
	char *iptos(DWORD in)
	{
		char *ipstr = new char[16];
		BYTE *p;
		p = (BYTE *)&in;//�ⲿ��ͨ��ָ�����͵ĸı�ʵ����ת������
		sprintf_s(ipstr, 16, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
		return ipstr;
	}

	Device();          //���캯��
	~Device();         //�������������ͷű����豸�б��رմ򿪵�����
};

//��װ������׼ȷ��˵Ӧ�����̹߳���������
class sparam
{
public:
	int s_port;       //��ʼ�˿�
	int e_port;       //��ֹ�˿�
	int current_port; //��ǰ����Ķ˿�
	char *dest_ip;    //ɨ��Ŀ��IP
	char *dest_MAC;   //Ŀ��IP��MAC��ַ
	char *dest_MACStr;//Ŀ��IP��MAC��ַ
	HWND handle;
	HWND status;

public:
	sparam()
	{
		s_port = 0;
		e_port = 65535;
		current_port = 0;
		dest_ip = new char[16];
		dest_MAC = new char[6];
		dest_MACStr = new char[18];
		handle = NULL;
		status = NULL;
	}
	~sparam(){};
};