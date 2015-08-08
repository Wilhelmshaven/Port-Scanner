//设备类
class Device
{
public:
	pcap_if_t *alldevs;   //设备列表
	pcap_t *adhandle;     //当前设备
	char *ip;             //自己的IP
	char *netmask;        //自己的子网掩码
	char *mac;            //自己的MAC地址（十六进制）
	char *macStr;         //自己的MAC地址（字符串）
	char *gateway_ip;     //网关IP地址
	char *gatewayMAC;     //网关MAC地址（十六进制）
	char *gatewayMACStr;  //网关MAC地址（字符串）

private:
	char *errbuf;         //错误缓存

private:

	int OpenDevice(pcap_if_t *d);//打开设备
	void GetInfo(pcap_if_t *d);  //获得该网卡的IP、子网掩码、MAC地址和网关IP

public:
	void DeviceGetReady(int option); //功能入口

	//将数字类型的IP地址转换成字符串类型的
	char *iptos(DWORD in)
	{
		char *ipstr = new char[16];
		BYTE *p;
		p = (BYTE *)&in;//这部分通过指针类型的改变实现了转换过程
		sprintf_s(ipstr, 16, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
		return ipstr;
	}

	Device();          //构造函数
	~Device();         //析构函数，并释放本机设备列表及关闭打开的网卡
};

//封装参数表，准确点说应该是线程共享数据域
class sparam
{
public:
	int s_port;       //开始端口
	int e_port;       //终止端口
	int current_port; //当前处理的端口
	char *dest_ip;    //扫描目的IP
	char *dest_MAC;   //目的IP的MAC地址
	char *dest_MACStr;//目的IP的MAC地址
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