/*************************************************************
*   I declare that the assignment here submitted is original *
* except for source material explicitly acknowledged. I also *
* acknowledge that I am aware of University policy and       *
* regulations on honesty in academic work, and of the        *
* disciplinary guidelines and procedures applicable to       *
* breaches of such policy and regulations.                   *
*                                                            *
* Hongjie Li                    2014.11.16                   *
* Signature						Date                         *
*************************************************************/
// Port Scanner.cpp : 定义应用程序的入口点。
//

#include "stdafx.h"
#include "Port Scanner.h"
#include "Packet.h"
#include "Device.h"

//风格变换
#pragma comment(linker, "\"/manifestdependency:type='Win32'\
 name='Microsoft.Windows.Common-Controls' version='6.0.0.0'\
 processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// 全局变量: 
enum CustomDefine
{
	MAX_LOADSTRING = 100,
};
enum CustomMsg
{
	//自定义消息集合
	END_OF_THREAD = WM_APP + 1,
	ERR_ARP = WM_APP + 2,
	ENABLE_CTL = WM_APP + 3,
	INVALID_INPUT = WM_APP + 4
};
enum IPDefine
{
	ETH_IP = 0x0800,         // IP数据包
	TCP = 0x06,              // IP数据报的TCP协议
	UDP = 0x11               // IP数据报的UDP协议
};
enum ARPDefine
{
	ETH_ARP = 0x0806,        // ARP数据包
	ARP_HARDWARE = 1,        // 硬件类型字段值，表示以太网地址
	ARP_REQUEST = 1,         // ARP请求字段
	ARP_REPLY = 2            // ARP应答字段
};
enum TCPDefine
{
	SYN = 0x6002,            // 握手：SYN
	SYN_ACK = 0x12,          // 握手应答：SYN_ACK
	RST_ACK = 0x14,          // 拒绝应答：RST_ACK
	RST = 0x5004,            // 拒绝链接：RST
	MY_PORT = 0xc522         // 我的端口：50466（随意）
};
HINSTANCE hInst;								// 当前实例
TCHAR szTitle[MAX_LOADSTRING];					// 标题栏文本
TCHAR szWindowClass[MAX_LOADSTRING];			// 主窗口类名
HWND myhdlg = NULL;                             // 对话框（用作主窗口）的句柄
Device myDevice;                                // 设备类

HANDLE hBeginALL = CreateEvent(NULL, TRUE, FALSE, NULL);
HANDLE hEndALL = CreateEvent(NULL, TRUE, FALSE, NULL);
HANDLE hBeginTCP = CreateEvent(NULL, TRUE, FALSE, NULL);
HANDLE hMutex_SYN;                   // 使用互斥对象完成SYN发送与接收线程的交替运作
HANDLE hMutex_RST;                  // 使用事件对象完成RST发送与接收线程的交替运作

sparam sp;                                      // 线程共享数据域
char *realIP = new char[16];                    // 存储IP（输入IP或者域名解析出来的IP）
int SelectedNIC;

// 此代码模块中包含的函数的前向声明: 
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    DlgProc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam);         //子窗口消息处理

BOOL CheckInput(char *input, int len, char *start_port, char *end_port);                //检查输入合法性

UINT Send_ARP_Packet(LPVOID lpParameter);                                               //发包方法
UINT Send_TCP_SYN_Packet(LPVOID lpParameter);                                           //发包方法
UINT Send_TCP_RST_Packet(LPVOID lpParameter);                                           //发包方法
UINT Recv_ARP_Packet(LPVOID lpParameter);                                               //收包方法
UINT AnalyzePacket(LPVOID lpParameter);                                                 //收包方法

BOOL AddListViewItems(HWND hwndListView, int portNum, int type);                        //输出结果

//启动线程：这里顺序很关键，关系到同步问题（Mutex）
HANDLE recvARPThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Recv_ARP_Packet, NULL, 0, NULL);
HANDLE AnalyzeThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AnalyzePacket, NULL, 0, NULL);
HANDLE sendARPThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Send_ARP_Packet, NULL, 0, NULL);
HANDLE sendSYNThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Send_TCP_SYN_Packet, NULL, 0, NULL);
HANDLE sendRSTThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Send_TCP_RST_Packet, NULL, 0, NULL);

/*============================== WinMain ==============================*/
int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

 	// TODO:  在此放置代码。
	MSG msg;
	HACCEL hAccelTable;

	// 初始化全局字符串
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_PORTSCANNER, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);

	// 执行应用程序初始化: 
	if (!InitInstance (hInstance, nCmdShow))
	{
		return FALSE;
	}

	hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_PORTSCANNER));

	// 主消息循环: 
	while (GetMessage(&msg, NULL, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int) msg.wParam;
}

//注册窗口类
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_PORTSCANNER));
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_PORTSCANNER);
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassEx(&wcex);
}

//保存实例句柄并创建主窗口
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance; // 将实例句柄存储在全局变量中

   //主窗口不可变大小，同时禁用最大化
   hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
	   CW_USEDEFAULT, 0, 520, 500, NULL, NULL, hInstance, NULL);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//处理主窗口的消息
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	HWND hStatus = NULL;              //在窗口底部创建一个状态栏

	switch (message)
	{
	case WM_CREATE:
	{
		//创建状态栏并设置初始文本
		hStatus = CreateWindow(
			STATUSCLASSNAME,                                       //指定创建的窗口类名
			NULL,                                                  //指定窗口名称，创建状态栏的话，这个可以为空
			WS_CHILD | WS_VISIBLE | CCS_BOTTOM,                    //执行窗口风格
			0, 0, 0, 0,                                            //int x,int y,int nWidth,int nHeight
			hWnd,                                                  //指定一个父窗口句柄
			(HMENU)NULL,                                           //菜单句柄
			(HINSTANCE)GetWindowLong(hWnd, GWL_HINSTANCE),         //模块实例句柄
			NULL
			);
		SendMessage(hStatus, SB_SETBKCOLOR, 0, RGB(199, 237, 204));
		sp.status = hStatus;
		SendMessage(hStatus, SB_SETTEXT, 0, (LPARAM)" Waiting for input...");

		//创建子对话框并将其作为主窗口
		myhdlg = CreateDialog(hInst, MAKEINTRESOURCE(IDD_FORMVIEW), hWnd, (DLGPROC)DlgProc);
		ShowWindow(myhdlg, SW_SHOW);//显示对话框

		//设置标题字体样式：这部分必须放在主窗口处理
		LOGFONT TitleFont;
		ZeroMemory(&TitleFont, sizeof(TitleFont));                    // 这个必须做，清除乱七八糟的初值
		lstrcpy(TitleFont.lfFaceName, "Segoe Script");                // 设置字体
		TitleFont.lfWeight = FW_BOLD;                                 // 粗细，BOLD=700，写过CSS都知道
		TitleFont.lfHeight = -24;                                     // 字体大小，这个很有讲究……
		TitleFont.lfCharSet = DEFAULT_CHARSET;                        // 默认字符集
		TitleFont.lfOutPrecision = OUT_DEVICE_PRECIS;                 // 输出精度

		HFONT hFont = CreateFontIndirect(&TitleFont);
		HWND hWndStatic = GetDlgItem(myhdlg, IDC_TITLE);
		SendMessage(hWndStatic, WM_SETFONT, (WPARAM)hFont, 0);

		//设置类目字体样式
		LOGFONT TextFont;
		ZeroMemory(&TextFont, sizeof(TextFont));
		lstrcpy(TextFont.lfFaceName, "Gabriola");
		TextFont.lfHeight = -16;
		hFont = CreateFontIndirect(&TextFont);

		//设置控件字体
		hWndStatic = GetDlgItem(myhdlg, IDC_STATIC_START);
		SendMessage(hWndStatic, WM_SETFONT, (WPARAM)hFont, 0);
		hWndStatic = GetDlgItem(myhdlg, IDC_STATIC_END);
		SendMessage(hWndStatic, WM_SETFONT, (WPARAM)hFont, 0);
		hWndStatic = GetDlgItem(myhdlg, IDC_STATIC_IP);
		SendMessage(hWndStatic, WM_SETFONT, (WPARAM)hFont, 0);
		hWndStatic = GetDlgItem(myhdlg, IDC_STATIC_NIC);
		SendMessage(hWndStatic, WM_SETFONT, (WPARAM)hFont, 0);
	}
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// 分析菜单选择: 
		switch (wmId)
		{
		case IDM_ABOUT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
			break;
		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

// “关于”框的消息处理程序。
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

//处理对话框消息  
INT_PTR CALLBACK DlgProc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	HWND hButton = NULL;                            //Button
	HWND hEditBox = NULL;                           //Edit Box
	HWND hListview = GetDlgItem(hdlg, IDC_RESULT);  //ListView
	HWND hWndComboBox = GetDlgItem(hdlg, IDC_COMBO);

	switch (msg)
	{
	case WM_INITDIALOG:
	{
		hEditBox = GetDlgItem(hdlg, IDC_INPUT);
		//限制文本输入框的输入长度
		Edit_LimitText(hEditBox, 32);
		//放置一个提示文本：涉及ANSI转宽字符的问题
		char *tmp = new char[];
		strcpy(tmp, "请先选择网卡，并输入IP地址或域名");                                //设置提示文本
		int dwNum = MultiByteToWideChar(CP_ACP, 0, tmp, -1, NULL, 0);     //获得所要转成的宽字符的长度
		wchar_t *tip = new wchar_t[dwNum];                                //用上一步得到的长度进行初始化
		MultiByteToWideChar(CP_ACP, 0, tmp, -1, tip, dwNum);              //多字节转换成宽字节，sizeof不好使的说
		Edit_SetCueBannerText(hEditBox, tip);                             //输出提示文本（这里要求文本为Unicode格式）

		//设置端口最大输入长度为5（<65535）
		hEditBox = GetDlgItem(hdlg, IDC_EDIT_START);
		Edit_LimitText(hEditBox, 5);
		hEditBox = GetDlgItem(hdlg, IDC_EDIT_END);
		Edit_LimitText(hEditBox, 5);

		// 设置ListView的列  
		LVCOLUMN lvc;
		lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
		ListView_SetTextColor(hListview, RGB(0, 0, 255));                //设置文字颜色
		//ListView_SetTextBkColor(hListview, RGB(199, 237, 204));          //设置文字背景颜色
		ListView_SetExtendedListViewStyle(hListview, LVS_EX_GRIDLINES);  //添加导航线

		lvc.pszText = "INFO";                        //列标题  
		lvc.cx = 400;                                 //列宽  
		lvc.iSubItem = 0;                           //子项索引，第一列无子项 (0) 
		lvc.fmt = LVCFMT_LEFT;
		ListView_InsertColumn(hListview, 0, &lvc);  //插入第一列

		//填充下拉列表
		pcap_if_t *d;
		for (d = myDevice.alldevs; d; d = d->next)
		{
			SendMessage(hWndComboBox, CB_ADDSTRING, 0, (LPARAM)d->description);
		}

		//没选择网卡前，不给开始
		hButton = GetDlgItem(hdlg, IDC_BTN_SCAN);
		Button_Enable(hButton, FALSE);

		delete[]tmp;
		break;
	}

	case WM_CREATE:
	{
		//创建按钮
		hButton = CreateWindow(
			"BUTTON",                                               // Predefined class; Unicode assumed 
			"OK",                                                   // Button text 
			WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,  // Styles 
			100,                                                    // x position 
			100,                                                    // y position 
			100,                                                    // Button width
			100,                                                    // Button height
			hdlg,                                                   // Parent window
			(HMENU)IDC_BTN_SCAN,                                   // No menu.
			(HINSTANCE)GetWindowLong(hdlg, GWL_HINSTANCE),
			NULL);                                                  // Pointer not needed.

		hButton = CreateWindow(
			"BUTTON", "OK",
			WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
			100, 100, 100, 100, hdlg, (HMENU)IDC_BTN_CLOSE,
			(HINSTANCE)GetWindowLong(hdlg, GWL_HINSTANCE), NULL);

		break;
	}//WM_CREATE

	case WM_COMMAND:
	{
		wmId = LOWORD(wParam);
		wmEvent = HIWORD(wParam);

		switch (wmId)
		{
			//按钮功能的实现
		case IDC_BTN_SCAN:
		{
			SendMessage(sp.status, SB_SETTEXT, 0, (LPARAM)" Getting Started...");

			//清空上一次的结果
			SendMessage(hListview, LVM_DELETEALLITEMS, 0, 0);
			AddListViewItems(hListview, 0, -1);

			//获取输入并检查输入合法性
			char *input = new char[64];
			BOOL chk = FALSE;
			int len = 0;
			char *start_port = new char[6];
			char *end_port = new char[6];

			ZeroMemory(input, 64);
			hEditBox = GetDlgItem(hdlg, IDC_INPUT);
			Edit_GetText(hEditBox, input, 32);
			len = Edit_GetTextLength(hEditBox);
			hEditBox = GetDlgItem(hdlg, IDC_EDIT_START);
			Edit_GetText(hEditBox, start_port, 5);
			hEditBox = GetDlgItem(hdlg, IDC_EDIT_END);
			Edit_GetText(hEditBox, end_port, 5);

			if (len != 0)
			{
				//合法性检查：若是域名，必须能够解析IP；若是IP，必须符合IP格式
				chk = CheckInput(input, len, start_port, end_port);
			}
			if (!chk)
			{
				//不合法则重新输入
				AddListViewItems(hListview, 0, 0);
				//重置参数
				PostMessage(hdlg, INVALID_INPUT, 0, 0);
				break;
			}

			//获取输入的端口号，然后禁用相关按钮和输入框
			hButton = GetDlgItem(hdlg, IDC_BTN_SCAN);
			Button_Enable(hButton, FALSE);
			hEditBox = GetDlgItem(hdlg, IDC_EDIT_START);
			Edit_Enable(hEditBox, FALSE);
			hEditBox = GetDlgItem(hdlg, IDC_EDIT_END);
			Edit_Enable(hEditBox, FALSE);
			hEditBox = GetDlgItem(hdlg, IDC_INPUT);
			Edit_Enable(hEditBox, FALSE);

			//把解析出来的IP显示在输入框
			hEditBox = GetDlgItem(hdlg, IDC_INPUT);
			sprintf_s(input, 64, "%s (%s)", input, realIP);
			Edit_SetText(hEditBox, input);

			//开启并绑定网卡
			myDevice.DeviceGetReady(SelectedNIC);
			sp.dest_ip = realIP;
			sp.handle = hdlg;
			sp.s_port = atoi(start_port);
			sp.e_port = atoi(end_port);

			//创建新的互斥量
			hMutex_SYN = CreateMutex(NULL, FALSE, NULL);
			hMutex_RST = CreateMutex(NULL, FALSE, NULL);

			//开启线程
			SetEvent(hBeginALL);
			ResetEvent(hBeginALL);

			delete[]input;
			delete[]start_port;
			delete[]end_port;
			break;
		}//IDC_BTN_SCAN
	
		case IDC_BTN_CLOSE:
			//设置事件，终止线程
			SetEvent(hEndALL);
			SetEvent(hBeginALL);
			PostQuitMessage(0);
			break;

		default:
			break;
		}//wmID

		//处理控件消息
		switch (wmEvent)
		{
			// 下拉列表选择发生变化
		case CBN_SELCHANGE:
		{
			//没选择网卡前，不给开始
			hButton = GetDlgItem(hdlg, IDC_BTN_SCAN);
			Button_Enable(hButton, TRUE);

			SelectedNIC = -1;
			SelectedNIC = (int)SendMessage(hWndComboBox, CB_GETCURSEL, 0, 0); // 获得选中的选项编号
			break;
		}
		default:
			break;
		}

		break;
	}//WM_COMMAND

	case INVALID_INPUT:
	{
		SendMessage(sp.status, SB_SETTEXT, 0, (LPARAM)" Invalid input, please check.");
		PostMessage(hdlg, ENABLE_CTL, 0, 0);
		break;
	}
	case ENABLE_CTL:
	{
		//恢复相关按钮和输入框
		hButton = GetDlgItem(hdlg, IDC_BTN_SCAN);
		Button_Enable(hButton, TRUE);
		hEditBox = GetDlgItem(hdlg, IDC_EDIT_START);
		Edit_Enable(hEditBox, TRUE);
		hEditBox = GetDlgItem(hdlg, IDC_EDIT_END);
		Edit_Enable(hEditBox, TRUE);
		hEditBox = GetDlgItem(hdlg, IDC_INPUT);
		Edit_Enable(hEditBox, TRUE);
		break;
	}
	case ERR_ARP:
	{
		//未能获取到MAC地址
		PostMessage(hdlg, ENABLE_CTL, 0, 0);	
		SendMessage(sp.status, SB_SETTEXT, 0, (LPARAM)" Failed to get the MAC address, please retry.");
		break;
	}

	case END_OF_THREAD:
	{
		PostMessage(hdlg, ENABLE_CTL, 0, 0);
		SendMessage(sp.status, SB_SETTEXT, 0, (LPARAM)" Port Scanning finished.");
		break;
	}
	default:
		break;
	}
	return (INT_PTR)FALSE;
}

//检查输入合法性
BOOL CheckInput(char *input, int len, char *start_port, char *end_port)
{
	ZeroMemory(realIP, 16);
	BOOL flag;

	//先处理域名的情况，转成IP，再用IP判断函数。由于域名处理是后面加的，这部分有一点代码冗余
	addrinfo hostInfo;
	addrinfo *res = NULL;
	addrinfo *cur = NULL;
	sockaddr_in *addr;
	int errCode;

	ZeroMemory(&hostInfo, sizeof(hostInfo));
	hostInfo.ai_family = AF_INET;               /* Allow IPv4 */
	hostInfo.ai_flags = AI_PASSIVE;             /* For wildcard IP address */
	hostInfo.ai_protocol = 0;                   /* Any protocol */
	hostInfo.ai_socktype = SOCK_STREAM;

	//必须初始化Winsock
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(1, 1);
	WSAStartup(wVersionRequested, &wsaData);

	errCode = getaddrinfo(input, NULL, &hostInfo, &res);

	//正确会返回0，且资源非空
	if ((errCode == 0) && (res != NULL))
	{
		for (cur = res; cur != NULL; cur = cur->ai_next)
		{
			addr = (sockaddr_in *)cur->ai_addr;
			inet_ntop(AF_INET, &addr->sin_addr, realIP, 16);
		}
	}

	freeaddrinfo(cur);
	freeaddrinfo(res);

	if (*realIP == NULL)flag = FALSE;
	else flag = TRUE;
	/*若输入的是域名，上面已经转成了IP；若输入IP，则上面依旧是IP；若非法（包括非法域名和非法IP，以及合法但是不存在的IP），
	则realIP一定是NULL。也就是说，我用域名解析的方法替代了我原有的差错检测代码，甚是方便*/

	//下面检查端口：第一是在[0, 65535]之间，第二是输入是纯数字
	int sPort = atoi(start_port);
	int ePort = atoi(end_port);

	if ((sPort > ePort) || (sPort > 65535) || (ePort > 65535))flag = FALSE;

	char *tmp = new char[6];
	sprintf_s(tmp, 6, "%d", sPort);
	if (strcmp(tmp, start_port) != 0)flag = FALSE;
	sprintf_s(tmp, 6, "%d", ePort);
	if (strcmp(tmp, end_port) != 0)flag = FALSE;

	delete[]tmp;
	return flag;
}

//发送ARP包获取目标主机的MAC地址
UINT Send_ARP_Packet(LPVOID lpParameter)
{ 
	BYTE *sendbuf = new BYTE[42];                      //缓存大小
	ARP_frame ARPFrame;

	while (1)
	{
		//线程挂起与退出
		WaitForSingleObject(hBeginALL, INFINITE);
		if (WaitForSingleObject(hEndALL, 0) == WAIT_OBJECT_0)break;

		ZeroMemory(sendbuf, 42);

		//填充内容
		memcpy(ARPFrame.eh.source_mac_add, myDevice.mac, 6);
		ARPFrame.eh.type = htons(ETH_ARP);                           //以太网帧头协议类型

		ARPFrame.ah.hardware_type = htons(ARP_HARDWARE);             //硬件地址
		ARPFrame.ah.protocol_type = htons(ETH_IP);                   //ARP包协议类型
		inet_pton(AF_INET, myDevice.ip, &ARPFrame.ah.source_ip_add); //请求方的IP地址为自身的IP地址	        
		memcpy(ARPFrame.ah.source_mac_add, myDevice.mac, 6);
		ARPFrame.ah.operation_field = htons(ARP_REQUEST);            //ARP请求包
		
		//!判断是局域网内地址还是公网地址：若公网则获取网关MAC
		//!原理：自己IP与对方的IP分别和子网掩码按位与，得到的结果一样即说明在同一子网内
		//!若为局域网，则直接获取对方IP，无需MAC。先做这一步，反正都要转。如果确实是局域网内就不用改了，不是就改（覆盖）
		inet_pton(AF_INET, sp.dest_ip, &ARPFrame.ah.dest_ip_add);//目的IP
		
		//!接下来是判断部分。先转换掩码。
		unsigned long NetMask;
		inet_pton(AF_INET, myDevice.netmask, &NetMask);
		
		//判断
		if ((ARPFrame.ah.dest_ip_add & NetMask) != (ARPFrame.ah.source_ip_add&NetMask))
		{
			//如果与出来的值不相等，则把目的IP改写为网关IP（其实都已经有了，不过再发发也没事，不好改）
			inet_pton(AF_INET, myDevice.gateway_ip, &ARPFrame.ah.dest_ip_add);
		}
		//!多加出来的公网部分结束

		//把做好的数据包装入缓存
		memset(sendbuf, 0, sizeof(sendbuf));
		memcpy(sendbuf, &ARPFrame, sizeof(ARPFrame));

		pcap_sendpacket(myDevice.adhandle, sendbuf, 42);            //发包
	}

	//delete[]sendbuf;
	return 0;
}

//接收ARP包
UINT Recv_ARP_Packet(LPVOID lpParameter)
{
	char *source_ip = new char[16];           //用来存放数据包中的源IP
	int res;                                  //数据流
	pcap_pkthdr * pkt_header;
	const BYTE * pkt_data;

	while (1)
	{
		//线程挂起与退出
		WaitForSingleObject(hBeginALL, INFINITE);
		if (WaitForSingleObject(hEndALL, 0) == WAIT_OBJECT_0)break;

		//状态消息
		SendMessage(sp.status, SB_SETTEXT, 0, (LPARAM)" Getting MAC address...");

		int timeOut = 0;

		while (true)
		{
			timeOut++;
			if ((res = pcap_next_ex(myDevice.adhandle, &pkt_header, &pkt_data)) > 0)//使用非回调方法捕获数据包
			{

				if (*(WORD *)(pkt_data + 12) == htons(ETH_ARP))//判断ARP包的第13,14位（Type）是否等于0x0806，目的是滤出ARP包			
				{
					//把流数据装进ARP帧结构
					ARP_frame *recvARP = (ARP_frame *)pkt_data;

					//格式化IP以进行比较
					sprintf_s(source_ip, 16, "%d.%d.%d.%d", recvARP->ah.source_ip_add & 255, recvARP->ah.source_ip_add >> 8 & 255,
						recvARP->ah.source_ip_add >> 16 & 255, recvARP->ah.source_ip_add >> 24 & 255);

					//判断操作符位是否是ARP_REPLY，即滤出ARP应答包并确认是目的地址答复的ARP包
					if (recvARP->ah.operation_field == htons(ARP_REPLY) && (strcmp(source_ip, sp.dest_ip) == 0))
					{
						//保存获取到的MAC地址
						sprintf_s(sp.dest_MACStr, 18, "%02X-%02X-%02X-%02X-%02X-%02X", recvARP->ah.source_mac_add[0],
							recvARP->ah.source_mac_add[1], recvARP->ah.source_mac_add[2], recvARP->ah.source_mac_add[3],
							recvARP->ah.source_mac_add[4], recvARP->ah.source_mac_add[5]);

						BYTE *p;
						p = (BYTE *)&recvARP->ah.source_mac_add;//这部分通过指针类型的改变实现了转换过程
						for (int i = 0; i < 6; i++)sp.dest_MAC[i] = p[i];

						break;//BREAK APR RECV.
					}
				}
			}

			//如果被强退
			if (WaitForSingleObject(hEndALL, 1) == WAIT_OBJECT_0)break;

			if (timeOut > 500)
			{
				//假如超时还收不到ARP应答包，报错
				PostMessage(sp.handle, ERR_ARP, NULL, NULL);
				break;
			}
		}//ARP

		//通知TCP发包线程干活
		SetEvent(hBeginTCP);
	}

	//delete[]source_ip;
	return 0;
}

//发送TCP_SYN数据报
UINT Send_TCP_SYN_Packet(LPVOID lpParameter)
{
	BYTE *sendbuf = new BYTE[54];                     //缓存大小
	TCP_frame TCPFrame;
	char *msg = new char[64];

	while (1)
	{
		//线程挂起与退出
		WaitForSingleObject(hBeginALL, INFINITE);
		if (WaitForSingleObject(hEndALL, 0) == WAIT_OBJECT_0)break;

		char *xip = sp.dest_ip;                       //扫描目的IP
		int port = sp.s_port;                         //要扫描的端口号：初值为起始端口号
		
		//先拿到SYN互斥信号量
		WaitForSingleObject(hMutex_SYN, 1);
		//等待收ARP包线程的通知：开始信号
		WaitForSingleObject(hBeginTCP, INFINITE);

		//获得对方MAC地址后，填写并发送TCP数据报
		while (true)
		{
			//如果被强退
			if (WaitForSingleObject(hEndALL, 1) == WAIT_OBJECT_0)break;

			//输出状态信息
			sprintf_s(msg, 64, " Scanning %s: %d...", xip, port);
			SendMessage(sp.status, SB_SETTEXT, 0, (LPARAM)msg);

			//填充内容
			ZeroMemory(sendbuf, 54);

			//以太网头部
			memcpy(TCPFrame.eh.source_mac_add, myDevice.mac, 6);        //源MAC地址为自己的MAC地址
			memcpy(TCPFrame.eh.dest_mac_add, sp.dest_MAC, 6);           //目的MAC地址
			TCPFrame.eh.type = htons(ETH_IP);                           //以太网帧头协议类型

			//IP头部
			TCPFrame.ih.versionAndIHL = 0x45;                           //IPV4为4，长度0101（20字节）
			TCPFrame.ih.service = 0x00;                                 //区分服务，置零即可
			TCPFrame.ih.length = htons(0x0028);                         //总长度设为40
			TCPFrame.ih.id = htons(GetCurrentProcessId());              //ID，从系统获得
			TCPFrame.ih.flagAndOffset = 0x00;                           //标志和偏移，置零即可
			TCPFrame.ih.TTL = 58;                                       //TTL
			TCPFrame.ih.protocol = TCP;                                 //协议名设置为TCP
			TCPFrame.ih.checksum = 0x0000;                              //校验和置零，填充完头部后计算之
			inet_pton(AF_INET, myDevice.ip, &TCPFrame.ih.source_add);   //源IP地址为自己的IP        
			inet_pton(AF_INET, xip, &TCPFrame.ih.dest_add);             //目的IP地址，由用户给出

			//IP头部校验和
			char *cksbuf = new char[20];
			memcpy(cksbuf, &TCPFrame.ih, 20);
			TCPFrame.ih.checksum = TCPFrame.cks((WORD *)cksbuf, 20);

			//TCP数据
			TCPFrame.th.source_port = htons(MY_PORT);                    //50466
			TCPFrame.th.dest_port = htons(port);                         //当前扫描的端口号
			TCPFrame.th.seq_num = htons(1);
			TCPFrame.th.ack_num = 0;
			TCPFrame.th.len = 0x50;                                      //TCP首部长度（数值*4）
			TCPFrame.th.flags = 0x02;                                    //SYN=====================
			TCPFrame.th.window_size = htons(0xffff);                     //窗口大小
			TCPFrame.th.checksum = 0x0000;                               //校验和先置零
			TCPFrame.th.URG = 0x0000;                                    //URGent Number
			//TCP伪头部填充
			Psedo_TCP_head pth;
			inet_pton(AF_INET, myDevice.ip, &pth.source_addr);           //源IP    
			inet_pton(AF_INET, xip, &pth.dest_addr);                     //目的IP                             
			pth.protocol = TCP;                                          //TCP协议
			pth.seg_len = htons(20);                                     //长度20（6bit）

			//计算TCP首部的校验和：伪首部在前，与首部一起参与计算，随后丢弃伪首部
			char *buf = new char[32];
			memcpy(buf, &pth, 12);
			memcpy(buf + 12, &TCPFrame.th, 20);
			TCPFrame.th.checksum = TCPFrame.cks((WORD *)buf, 32);

			//把做好的数据包装入缓存
			memset(sendbuf, 0, sizeof(sendbuf));
			memcpy(sendbuf, &TCPFrame, 54);

			//记录当前正在处理的端口号
			sp.current_port = port;

			pcap_sendpacket(myDevice.adhandle, sendbuf, 54);//发包

			//让收包线程处理对应端口回包
			ReleaseMutex(hMutex_SYN);
			//等待其处理完毕
			WaitForSingleObject(hMutex_SYN, INFINITE);

			if (port >= sp.e_port)
			{
				ReleaseMutex(hMutex_SYN);
				break;
			}

			//端口加一
			port++;

			delete[]cksbuf;
			delete[]buf;
		}
	}

	//delete[]sendbuf;
	//delete[]msg;
	return 0;
}

//发送TCP_RST数据报中断连接
UINT Send_TCP_RST_Packet(LPVOID lpParameter)
{
	BYTE *sendbuf = new BYTE[54];                     //缓存大小
	TCP_frame TCPFrame;

	while (1)
	{
		//线程挂起与退出
		WaitForSingleObject(hBeginALL, INFINITE);
		if (WaitForSingleObject(hEndALL, 0) == WAIT_OBJECT_0)break;

		char *xip = sp.dest_ip;                       //扫描目的IP
		ZeroMemory(sendbuf, 54);
		int port = 0;                                     //当前端口号

		//等待开始信号
		WaitForSingleObject(hBeginTCP, INFINITE);

		while (true)
		{
			//等待收包线程通知
			WaitForSingleObject(hMutex_RST, INFINITE);
			port = sp.current_port;

			//假如被传递关闭消息，那么可以直接退出了
			if (WaitForSingleObject(hEndALL, 1) == WAIT_OBJECT_0)break;//BREAK TCP_RST

			//发包部分
			ZeroMemory(sendbuf, 54);

			//以太网头部
			memcpy(TCPFrame.eh.source_mac_add, myDevice.mac, 6);        //源MAC地址为自己的MAC地址
			memcpy(TCPFrame.eh.dest_mac_add, sp.dest_MAC, 6);           //目的MAC地址
			TCPFrame.eh.type = htons(ETH_IP);                           //以太网帧头协议类型

			//IP头部
			TCPFrame.ih.versionAndIHL = 0x45;                           //IPV4为4，长度0101（20字节）
			TCPFrame.ih.service = 0x00;                                 //区分服务，置零即可
			TCPFrame.ih.length = htons(0x0028);                         //总长度设为40
			TCPFrame.ih.id = htons(GetCurrentProcessId());              //ID，从系统获得
			TCPFrame.ih.flagAndOffset = 0x00;                           //标志和偏移，置零即可
			TCPFrame.ih.TTL = 58;                                       //TTL
			TCPFrame.ih.protocol = TCP;                                 //协议名设置为TCP
			TCPFrame.ih.checksum = 0x0000;                              //校验和置零，填充完头部后计算之
			inet_pton(AF_INET, myDevice.ip, &TCPFrame.ih.source_add);   //源IP地址为自己的IP

			inet_pton(AF_INET, xip, &TCPFrame.ih.dest_add);             //目的IP地址，由用户给出              

			//IP头部校验和
			char *cksbuf = new char[20];
			memcpy(cksbuf, &TCPFrame.ih, 20);
			TCPFrame.ih.checksum = TCPFrame.cks((WORD *)cksbuf, 20);

			//TCP数据
			TCPFrame.th.source_port = htons(MY_PORT);                    //50466
			TCPFrame.th.dest_port = htons(port);                         //当前扫描的端口号
			TCPFrame.th.seq_num = htons(1);
			TCPFrame.th.ack_num = 0;
			TCPFrame.th.len = 0x50;                                      //TCP首部长度（数值*4）
			TCPFrame.th.flags = 0x04;                                    //RST================
			TCPFrame.th.window_size = htons(0xffff);                     //窗口大小
			TCPFrame.th.checksum = 0x0000;                               //校验和先置零
			TCPFrame.th.URG = 0x0000;                                    //URGent Number
			//TCP伪头部填充
			Psedo_TCP_head pth;
			inet_pton(AF_INET, myDevice.ip, &pth.source_addr);           //源IP    
			inet_pton(AF_INET, xip, &pth.dest_addr);                     //目的IP   
			pth.protocol = TCP;                                          //TCP协议
			pth.seg_len = htons(20);                                     //长度20（6bit）

			//计算TCP首部的校验和：伪首部在前，与首部一起参与计算，随后丢弃伪首部
			char *buf = new char[32];
			memcpy(buf, &pth, 12);
			memcpy(buf + 12, &TCPFrame.th, 20);
			TCPFrame.th.checksum = TCPFrame.cks((WORD *)buf, 32);

			//把做好的数据包装入缓存
			memset(sendbuf, 0, sizeof(sendbuf));
			memcpy(sendbuf, &TCPFrame, 54);

			pcap_sendpacket(myDevice.adhandle, sendbuf, 54);//发包

			ReleaseMutex(hMutex_RST);

			delete[]cksbuf;
			delete[]buf;
		}
	}

	//delete[]sendbuf;
	return 0;
}

UINT AnalyzePacket(LPVOID lpParameter)
{
	HWND hList;
	BYTE *sendbuf = new BYTE[58];             //缓存大小	
	char *dest_ip = new char[16];             //用来存放数据包中的目的IP
	int res;                                  //数据流
	pcap_pkthdr * pkt_header;
	const u_char * pkt_data;

	while (1)
	{
		//线程挂起与退出
		WaitForSingleObject(hBeginALL, INFINITE);
		if (WaitForSingleObject(hEndALL, 0) == WAIT_OBJECT_0)break;

		//先拿住RST互斥变量
		WaitForSingleObject(hMutex_RST, 1);
		//等待收ARP包线程的通知：开始信号
		WaitForSingleObject(hBeginTCP, INFINITE);

		char *xip = sp.dest_ip;
		ZeroMemory(sendbuf, 58);

		TCP_frame *recvTCP = NULL;
		BOOL flag = FALSE;
		int timeOut = 0;

		WaitForSingleObject(hMutex_SYN, INFINITE);
		hList = GetDlgItem(sp.handle, IDC_RESULT);
		//抓取并分析TCP应答包
		while (true)
		{
			//假如被传递关闭消息，那么可以直接退出了
			if (WaitForSingleObject(hEndALL, 1) == WAIT_OBJECT_0 && sp.current_port != sp.e_port)
			{
				AddListViewItems(hList, 0, 0);
				break;//BREAK TCP
			}

			timeOut++;
			if ((res = pcap_next_ex(myDevice.adhandle, &pkt_header, &pkt_data)) > 0)                 //使用非回调方法捕获数据包
			{
				if (*(WORD *)(pkt_data + 12) == htons(ETH_IP) && (*(BYTE *)(pkt_data + 23) == TCP))  //选出发给自己的TCP应答包
				{
					//把数据流装入TCP结构里
					recvTCP = (TCP_frame *)pkt_data;

					//格式化IP以进行比较
					sprintf_s(dest_ip, 16, "%d.%d.%d.%d", recvTCP->ih.dest_add & 255, recvTCP->ih.dest_add >> 8 & 255,
						recvTCP->ih.dest_add >> 16 & 255, recvTCP->ih.dest_add >> 24 & 255);

					if (strcmp(dest_ip, myDevice.ip) == 0)                        //选出自己的TCP包
					{
						//若端口开放
						if (recvTCP->th.flags == SYN_ACK)
						{
							//输出结果：端口连接开放
							AddListViewItems(hList, sp.current_port, 1);

							flag = TRUE;
							//发送一个中断连接的数据报，并挂起自己等待发送结束
							ReleaseMutex(hMutex_RST);
							WaitForSingleObject(hMutex_RST, INFINITE);
						}

						//若端口关闭
						if (recvTCP->th.flags == RST_ACK)
						{
							//输出结果：端口关闭
							AddListViewItems(hList, sp.current_port, 2);
							flag = TRUE;
						}
					}
				}
			}//收包阶段

			//假如超时
			if (timeOut > 1000)
			{
				timeOut = 0;
				AddListViewItems(hList, sp.current_port, 3);
				flag = TRUE;
			}
			//假如超时或者已经收到了答复的包（无论何种情况），继续发包
			if (flag)
			{
				//发下一个包
				ReleaseMutex(hMutex_SYN);
				flag = FALSE;

				//如果已经处理完
				if (sp.current_port == sp.e_port)
				{
					PostMessage(sp.handle, END_OF_THREAD, NULL, NULL);
					AddListViewItems(hList, 0, 0);
					break;//BREAK TCP
				}

				//如果没有，则等待发包
				WaitForSingleObject(hMutex_SYN, INFINITE);
			}

		}//TCP
	}

	//delete[]sendbuf;
	//delete[]dest_ip;
	return 0;
}

//在结果输出框里面输出结果
BOOL AddListViewItems(HWND hwndListView, int portNum, int type)
{
	char *tmp = new char[128];
	ZeroMemory(tmp, 128);

	switch (type)
	{
	case -1:
	{
		sprintf_s(tmp, 128, "Starting Port Scanner...");
		break;
	}
	case 0:
	{
		sprintf_s(tmp, 128, "Port Scanning Finished.");
		break;
	}
	case 1:
	{
		sprintf_s(tmp, 128, "%s: %d   Connection accepted.", sp.dest_ip, portNum);
		break;
	}
	case 2:
	{
		sprintf_s(tmp, 128, "%s: %d   Connection denied.", sp.dest_ip, portNum);
		break;
	}
	default:
	{
		sprintf_s(tmp, 128, "%s: %d   No Answer.", sp.dest_ip, portNum);
		break;
	}	
	}

	int ListItemCount = ListView_GetItemCount(hwndListView);
	LVITEM lvi;
	ZeroMemory(&lvi, sizeof(lvi));//这个必须做，清除乱七八糟的初值
	lvi.mask = LVIF_TEXT | LVIF_PARAM | LVIF_STATE;
	//项的文本和长度
	lvi.pszText = tmp;
	lvi.cchTextMax = lstrlen(lvi.pszText) + 1;
	lvi.iItem = ListItemCount;
	//插入列，最后一个确实是1
	ListView_InsertItem(hwndListView, &lvi);
	ListView_SetItemText(hwndListView, ListItemCount, 0, tmp);

	delete[]tmp;
	return TRUE;
}
