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
// Port Scanner.cpp : ����Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "Port Scanner.h"
#include "Packet.h"
#include "Device.h"

//���任
#pragma comment(linker, "\"/manifestdependency:type='Win32'\
 name='Microsoft.Windows.Common-Controls' version='6.0.0.0'\
 processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ȫ�ֱ���: 
enum CustomDefine
{
	MAX_LOADSTRING = 100,
};
enum CustomMsg
{
	//�Զ�����Ϣ����
	END_OF_THREAD = WM_APP + 1,
	ERR_ARP = WM_APP + 2,
	ENABLE_CTL = WM_APP + 3,
	INVALID_INPUT = WM_APP + 4
};
enum IPDefine
{
	ETH_IP = 0x0800,         // IP���ݰ�
	TCP = 0x06,              // IP���ݱ���TCPЭ��
	UDP = 0x11               // IP���ݱ���UDPЭ��
};
enum ARPDefine
{
	ETH_ARP = 0x0806,        // ARP���ݰ�
	ARP_HARDWARE = 1,        // Ӳ�������ֶ�ֵ����ʾ��̫����ַ
	ARP_REQUEST = 1,         // ARP�����ֶ�
	ARP_REPLY = 2            // ARPӦ���ֶ�
};
enum TCPDefine
{
	SYN = 0x6002,            // ���֣�SYN
	SYN_ACK = 0x12,          // ����Ӧ��SYN_ACK
	RST_ACK = 0x14,          // �ܾ�Ӧ��RST_ACK
	RST = 0x5004,            // �ܾ����ӣ�RST
	MY_PORT = 0xc522         // �ҵĶ˿ڣ�50466�����⣩
};
HINSTANCE hInst;								// ��ǰʵ��
TCHAR szTitle[MAX_LOADSTRING];					// �������ı�
TCHAR szWindowClass[MAX_LOADSTRING];			// ����������
HWND myhdlg = NULL;                             // �Ի������������ڣ��ľ��
Device myDevice;                                // �豸��

HANDLE hBeginALL = CreateEvent(NULL, TRUE, FALSE, NULL);
HANDLE hEndALL = CreateEvent(NULL, TRUE, FALSE, NULL);
HANDLE hBeginTCP = CreateEvent(NULL, TRUE, FALSE, NULL);
HANDLE hMutex_SYN;                   // ʹ�û���������SYN����������̵߳Ľ�������
HANDLE hMutex_RST;                  // ʹ���¼��������RST����������̵߳Ľ�������

sparam sp;                                      // �̹߳���������
char *realIP = new char[16];                    // �洢IP������IP������������������IP��
int SelectedNIC;

// �˴���ģ���а����ĺ�����ǰ������: 
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    DlgProc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam);         //�Ӵ�����Ϣ����

BOOL CheckInput(char *input, int len, char *start_port, char *end_port);                //�������Ϸ���

UINT Send_ARP_Packet(LPVOID lpParameter);                                               //��������
UINT Send_TCP_SYN_Packet(LPVOID lpParameter);                                           //��������
UINT Send_TCP_RST_Packet(LPVOID lpParameter);                                           //��������
UINT Recv_ARP_Packet(LPVOID lpParameter);                                               //�հ�����
UINT AnalyzePacket(LPVOID lpParameter);                                                 //�հ�����

BOOL AddListViewItems(HWND hwndListView, int portNum, int type);                        //������

//�����̣߳�����˳��ܹؼ�����ϵ��ͬ�����⣨Mutex��
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

 	// TODO:  �ڴ˷��ô��롣
	MSG msg;
	HACCEL hAccelTable;

	// ��ʼ��ȫ���ַ���
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_PORTSCANNER, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);

	// ִ��Ӧ�ó����ʼ��: 
	if (!InitInstance (hInstance, nCmdShow))
	{
		return FALSE;
	}

	hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_PORTSCANNER));

	// ����Ϣѭ��: 
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

//ע�ᴰ����
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

//����ʵ�����������������
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance; // ��ʵ������洢��ȫ�ֱ�����

   //�����ڲ��ɱ��С��ͬʱ�������
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

//���������ڵ���Ϣ
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	HWND hStatus = NULL;              //�ڴ��ڵײ�����һ��״̬��

	switch (message)
	{
	case WM_CREATE:
	{
		//����״̬�������ó�ʼ�ı�
		hStatus = CreateWindow(
			STATUSCLASSNAME,                                       //ָ�������Ĵ�������
			NULL,                                                  //ָ���������ƣ�����״̬���Ļ����������Ϊ��
			WS_CHILD | WS_VISIBLE | CCS_BOTTOM,                    //ִ�д��ڷ��
			0, 0, 0, 0,                                            //int x,int y,int nWidth,int nHeight
			hWnd,                                                  //ָ��һ�������ھ��
			(HMENU)NULL,                                           //�˵����
			(HINSTANCE)GetWindowLong(hWnd, GWL_HINSTANCE),         //ģ��ʵ�����
			NULL
			);
		SendMessage(hStatus, SB_SETBKCOLOR, 0, RGB(199, 237, 204));
		sp.status = hStatus;
		SendMessage(hStatus, SB_SETTEXT, 0, (LPARAM)" Waiting for input...");

		//�����ӶԻ��򲢽�����Ϊ������
		myhdlg = CreateDialog(hInst, MAKEINTRESOURCE(IDD_FORMVIEW), hWnd, (DLGPROC)DlgProc);
		ShowWindow(myhdlg, SW_SHOW);//��ʾ�Ի���

		//���ñ���������ʽ���ⲿ�ֱ�����������ڴ���
		LOGFONT TitleFont;
		ZeroMemory(&TitleFont, sizeof(TitleFont));                    // �����������������߰���ĳ�ֵ
		lstrcpy(TitleFont.lfFaceName, "Segoe Script");                // ��������
		TitleFont.lfWeight = FW_BOLD;                                 // ��ϸ��BOLD=700��д��CSS��֪��
		TitleFont.lfHeight = -24;                                     // �����С��������н�������
		TitleFont.lfCharSet = DEFAULT_CHARSET;                        // Ĭ���ַ���
		TitleFont.lfOutPrecision = OUT_DEVICE_PRECIS;                 // �������

		HFONT hFont = CreateFontIndirect(&TitleFont);
		HWND hWndStatic = GetDlgItem(myhdlg, IDC_TITLE);
		SendMessage(hWndStatic, WM_SETFONT, (WPARAM)hFont, 0);

		//������Ŀ������ʽ
		LOGFONT TextFont;
		ZeroMemory(&TextFont, sizeof(TextFont));
		lstrcpy(TextFont.lfFaceName, "Gabriola");
		TextFont.lfHeight = -16;
		hFont = CreateFontIndirect(&TextFont);

		//���ÿؼ�����
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
		// �����˵�ѡ��: 
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

// �����ڡ������Ϣ�������
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

//����Ի�����Ϣ  
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
		//�����ı����������볤��
		Edit_LimitText(hEditBox, 32);
		//����һ����ʾ�ı����漰ANSIת���ַ�������
		char *tmp = new char[];
		strcpy(tmp, "����ѡ��������������IP��ַ������");                                //������ʾ�ı�
		int dwNum = MultiByteToWideChar(CP_ACP, 0, tmp, -1, NULL, 0);     //�����Ҫת�ɵĿ��ַ��ĳ���
		wchar_t *tip = new wchar_t[dwNum];                                //����һ���õ��ĳ��Ƚ��г�ʼ��
		MultiByteToWideChar(CP_ACP, 0, tmp, -1, tip, dwNum);              //���ֽ�ת���ɿ��ֽڣ�sizeof����ʹ��˵
		Edit_SetCueBannerText(hEditBox, tip);                             //�����ʾ�ı�������Ҫ���ı�ΪUnicode��ʽ��

		//���ö˿�������볤��Ϊ5��<65535��
		hEditBox = GetDlgItem(hdlg, IDC_EDIT_START);
		Edit_LimitText(hEditBox, 5);
		hEditBox = GetDlgItem(hdlg, IDC_EDIT_END);
		Edit_LimitText(hEditBox, 5);

		// ����ListView����  
		LVCOLUMN lvc;
		lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
		ListView_SetTextColor(hListview, RGB(0, 0, 255));                //����������ɫ
		//ListView_SetTextBkColor(hListview, RGB(199, 237, 204));          //�������ֱ�����ɫ
		ListView_SetExtendedListViewStyle(hListview, LVS_EX_GRIDLINES);  //��ӵ�����

		lvc.pszText = "INFO";                        //�б���  
		lvc.cx = 400;                                 //�п�  
		lvc.iSubItem = 0;                           //������������һ�������� (0) 
		lvc.fmt = LVCFMT_LEFT;
		ListView_InsertColumn(hListview, 0, &lvc);  //�����һ��

		//��������б�
		pcap_if_t *d;
		for (d = myDevice.alldevs; d; d = d->next)
		{
			SendMessage(hWndComboBox, CB_ADDSTRING, 0, (LPARAM)d->description);
		}

		//ûѡ������ǰ��������ʼ
		hButton = GetDlgItem(hdlg, IDC_BTN_SCAN);
		Button_Enable(hButton, FALSE);

		delete[]tmp;
		break;
	}

	case WM_CREATE:
	{
		//������ť
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
			//��ť���ܵ�ʵ��
		case IDC_BTN_SCAN:
		{
			SendMessage(sp.status, SB_SETTEXT, 0, (LPARAM)" Getting Started...");

			//�����һ�εĽ��
			SendMessage(hListview, LVM_DELETEALLITEMS, 0, 0);
			AddListViewItems(hListview, 0, -1);

			//��ȡ���벢�������Ϸ���
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
				//�Ϸ��Լ�飺���������������ܹ�����IP������IP���������IP��ʽ
				chk = CheckInput(input, len, start_port, end_port);
			}
			if (!chk)
			{
				//���Ϸ�����������
				AddListViewItems(hListview, 0, 0);
				//���ò���
				PostMessage(hdlg, INVALID_INPUT, 0, 0);
				break;
			}

			//��ȡ����Ķ˿ںţ�Ȼ�������ذ�ť�������
			hButton = GetDlgItem(hdlg, IDC_BTN_SCAN);
			Button_Enable(hButton, FALSE);
			hEditBox = GetDlgItem(hdlg, IDC_EDIT_START);
			Edit_Enable(hEditBox, FALSE);
			hEditBox = GetDlgItem(hdlg, IDC_EDIT_END);
			Edit_Enable(hEditBox, FALSE);
			hEditBox = GetDlgItem(hdlg, IDC_INPUT);
			Edit_Enable(hEditBox, FALSE);

			//�ѽ���������IP��ʾ�������
			hEditBox = GetDlgItem(hdlg, IDC_INPUT);
			sprintf_s(input, 64, "%s (%s)", input, realIP);
			Edit_SetText(hEditBox, input);

			//������������
			myDevice.DeviceGetReady(SelectedNIC);
			sp.dest_ip = realIP;
			sp.handle = hdlg;
			sp.s_port = atoi(start_port);
			sp.e_port = atoi(end_port);

			//�����µĻ�����
			hMutex_SYN = CreateMutex(NULL, FALSE, NULL);
			hMutex_RST = CreateMutex(NULL, FALSE, NULL);

			//�����߳�
			SetEvent(hBeginALL);
			ResetEvent(hBeginALL);

			delete[]input;
			delete[]start_port;
			delete[]end_port;
			break;
		}//IDC_BTN_SCAN
	
		case IDC_BTN_CLOSE:
			//�����¼�����ֹ�߳�
			SetEvent(hEndALL);
			SetEvent(hBeginALL);
			PostQuitMessage(0);
			break;

		default:
			break;
		}//wmID

		//����ؼ���Ϣ
		switch (wmEvent)
		{
			// �����б�ѡ�����仯
		case CBN_SELCHANGE:
		{
			//ûѡ������ǰ��������ʼ
			hButton = GetDlgItem(hdlg, IDC_BTN_SCAN);
			Button_Enable(hButton, TRUE);

			SelectedNIC = -1;
			SelectedNIC = (int)SendMessage(hWndComboBox, CB_GETCURSEL, 0, 0); // ���ѡ�е�ѡ����
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
		//�ָ���ذ�ť�������
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
		//δ�ܻ�ȡ��MAC��ַ
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

//�������Ϸ���
BOOL CheckInput(char *input, int len, char *start_port, char *end_port)
{
	ZeroMemory(realIP, 16);
	BOOL flag;

	//�ȴ��������������ת��IP������IP�жϺ������������������Ǻ���ӵģ��ⲿ����һ���������
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

	//�����ʼ��Winsock
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(1, 1);
	WSAStartup(wVersionRequested, &wsaData);

	errCode = getaddrinfo(input, NULL, &hostInfo, &res);

	//��ȷ�᷵��0������Դ�ǿ�
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
	/*��������������������Ѿ�ת����IP��������IP��������������IP�����Ƿ��������Ƿ������ͷǷ�IP���Լ��Ϸ����ǲ����ڵ�IP����
	��realIPһ����NULL��Ҳ����˵���������������ķ����������ԭ�еĲ������룬���Ƿ���*/

	//������˿ڣ���һ����[0, 65535]֮�䣬�ڶ��������Ǵ�����
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

//����ARP����ȡĿ��������MAC��ַ
UINT Send_ARP_Packet(LPVOID lpParameter)
{ 
	BYTE *sendbuf = new BYTE[42];                      //�����С
	ARP_frame ARPFrame;

	while (1)
	{
		//�̹߳������˳�
		WaitForSingleObject(hBeginALL, INFINITE);
		if (WaitForSingleObject(hEndALL, 0) == WAIT_OBJECT_0)break;

		ZeroMemory(sendbuf, 42);

		//�������
		memcpy(ARPFrame.eh.source_mac_add, myDevice.mac, 6);
		ARPFrame.eh.type = htons(ETH_ARP);                           //��̫��֡ͷЭ������

		ARPFrame.ah.hardware_type = htons(ARP_HARDWARE);             //Ӳ����ַ
		ARPFrame.ah.protocol_type = htons(ETH_IP);                   //ARP��Э������
		inet_pton(AF_INET, myDevice.ip, &ARPFrame.ah.source_ip_add); //���󷽵�IP��ַΪ�����IP��ַ	        
		memcpy(ARPFrame.ah.source_mac_add, myDevice.mac, 6);
		ARPFrame.ah.operation_field = htons(ARP_REQUEST);            //ARP�����
		
		//!�ж��Ǿ������ڵ�ַ���ǹ�����ַ�����������ȡ����MAC
		//!ԭ���Լ�IP��Է���IP�ֱ���������밴λ�룬�õ��Ľ��һ����˵����ͬһ������
		//!��Ϊ����������ֱ�ӻ�ȡ�Է�IP������MAC��������һ����������Ҫת�����ȷʵ�Ǿ������ھͲ��ø��ˣ����Ǿ͸ģ����ǣ�
		inet_pton(AF_INET, sp.dest_ip, &ARPFrame.ah.dest_ip_add);//Ŀ��IP
		
		//!���������жϲ��֡���ת�����롣
		unsigned long NetMask;
		inet_pton(AF_INET, myDevice.netmask, &NetMask);
		
		//�ж�
		if ((ARPFrame.ah.dest_ip_add & NetMask) != (ARPFrame.ah.source_ip_add&NetMask))
		{
			//����������ֵ����ȣ����Ŀ��IP��дΪ����IP����ʵ���Ѿ����ˣ������ٷ���Ҳû�£����øģ�
			inet_pton(AF_INET, myDevice.gateway_ip, &ARPFrame.ah.dest_ip_add);
		}
		//!��ӳ����Ĺ������ֽ���

		//�����õ����ݰ�װ�뻺��
		memset(sendbuf, 0, sizeof(sendbuf));
		memcpy(sendbuf, &ARPFrame, sizeof(ARPFrame));

		pcap_sendpacket(myDevice.adhandle, sendbuf, 42);            //����
	}

	//delete[]sendbuf;
	return 0;
}

//����ARP��
UINT Recv_ARP_Packet(LPVOID lpParameter)
{
	char *source_ip = new char[16];           //����������ݰ��е�ԴIP
	int res;                                  //������
	pcap_pkthdr * pkt_header;
	const BYTE * pkt_data;

	while (1)
	{
		//�̹߳������˳�
		WaitForSingleObject(hBeginALL, INFINITE);
		if (WaitForSingleObject(hEndALL, 0) == WAIT_OBJECT_0)break;

		//״̬��Ϣ
		SendMessage(sp.status, SB_SETTEXT, 0, (LPARAM)" Getting MAC address...");

		int timeOut = 0;

		while (true)
		{
			timeOut++;
			if ((res = pcap_next_ex(myDevice.adhandle, &pkt_header, &pkt_data)) > 0)//ʹ�÷ǻص������������ݰ�
			{

				if (*(WORD *)(pkt_data + 12) == htons(ETH_ARP))//�ж�ARP���ĵ�13,14λ��Type���Ƿ����0x0806��Ŀ�����˳�ARP��			
				{
					//��������װ��ARP֡�ṹ
					ARP_frame *recvARP = (ARP_frame *)pkt_data;

					//��ʽ��IP�Խ��бȽ�
					sprintf_s(source_ip, 16, "%d.%d.%d.%d", recvARP->ah.source_ip_add & 255, recvARP->ah.source_ip_add >> 8 & 255,
						recvARP->ah.source_ip_add >> 16 & 255, recvARP->ah.source_ip_add >> 24 & 255);

					//�жϲ�����λ�Ƿ���ARP_REPLY�����˳�ARPӦ�����ȷ����Ŀ�ĵ�ַ�𸴵�ARP��
					if (recvARP->ah.operation_field == htons(ARP_REPLY) && (strcmp(source_ip, sp.dest_ip) == 0))
					{
						//�����ȡ����MAC��ַ
						sprintf_s(sp.dest_MACStr, 18, "%02X-%02X-%02X-%02X-%02X-%02X", recvARP->ah.source_mac_add[0],
							recvARP->ah.source_mac_add[1], recvARP->ah.source_mac_add[2], recvARP->ah.source_mac_add[3],
							recvARP->ah.source_mac_add[4], recvARP->ah.source_mac_add[5]);

						BYTE *p;
						p = (BYTE *)&recvARP->ah.source_mac_add;//�ⲿ��ͨ��ָ�����͵ĸı�ʵ����ת������
						for (int i = 0; i < 6; i++)sp.dest_MAC[i] = p[i];

						break;//BREAK APR RECV.
					}
				}
			}

			//�����ǿ��
			if (WaitForSingleObject(hEndALL, 1) == WAIT_OBJECT_0)break;

			if (timeOut > 500)
			{
				//���糬ʱ���ղ���ARPӦ���������
				PostMessage(sp.handle, ERR_ARP, NULL, NULL);
				break;
			}
		}//ARP

		//֪ͨTCP�����̸߳ɻ�
		SetEvent(hBeginTCP);
	}

	//delete[]source_ip;
	return 0;
}

//����TCP_SYN���ݱ�
UINT Send_TCP_SYN_Packet(LPVOID lpParameter)
{
	BYTE *sendbuf = new BYTE[54];                     //�����С
	TCP_frame TCPFrame;
	char *msg = new char[64];

	while (1)
	{
		//�̹߳������˳�
		WaitForSingleObject(hBeginALL, INFINITE);
		if (WaitForSingleObject(hEndALL, 0) == WAIT_OBJECT_0)break;

		char *xip = sp.dest_ip;                       //ɨ��Ŀ��IP
		int port = sp.s_port;                         //Ҫɨ��Ķ˿ںţ���ֵΪ��ʼ�˿ں�
		
		//���õ�SYN�����ź���
		WaitForSingleObject(hMutex_SYN, 1);
		//�ȴ���ARP���̵߳�֪ͨ����ʼ�ź�
		WaitForSingleObject(hBeginTCP, INFINITE);

		//��öԷ�MAC��ַ����д������TCP���ݱ�
		while (true)
		{
			//�����ǿ��
			if (WaitForSingleObject(hEndALL, 1) == WAIT_OBJECT_0)break;

			//���״̬��Ϣ
			sprintf_s(msg, 64, " Scanning %s: %d...", xip, port);
			SendMessage(sp.status, SB_SETTEXT, 0, (LPARAM)msg);

			//�������
			ZeroMemory(sendbuf, 54);

			//��̫��ͷ��
			memcpy(TCPFrame.eh.source_mac_add, myDevice.mac, 6);        //ԴMAC��ַΪ�Լ���MAC��ַ
			memcpy(TCPFrame.eh.dest_mac_add, sp.dest_MAC, 6);           //Ŀ��MAC��ַ
			TCPFrame.eh.type = htons(ETH_IP);                           //��̫��֡ͷЭ������

			//IPͷ��
			TCPFrame.ih.versionAndIHL = 0x45;                           //IPV4Ϊ4������0101��20�ֽڣ�
			TCPFrame.ih.service = 0x00;                                 //���ַ������㼴��
			TCPFrame.ih.length = htons(0x0028);                         //�ܳ�����Ϊ40
			TCPFrame.ih.id = htons(GetCurrentProcessId());              //ID����ϵͳ���
			TCPFrame.ih.flagAndOffset = 0x00;                           //��־��ƫ�ƣ����㼴��
			TCPFrame.ih.TTL = 58;                                       //TTL
			TCPFrame.ih.protocol = TCP;                                 //Э��������ΪTCP
			TCPFrame.ih.checksum = 0x0000;                              //У������㣬�����ͷ�������֮
			inet_pton(AF_INET, myDevice.ip, &TCPFrame.ih.source_add);   //ԴIP��ַΪ�Լ���IP        
			inet_pton(AF_INET, xip, &TCPFrame.ih.dest_add);             //Ŀ��IP��ַ�����û�����

			//IPͷ��У���
			char *cksbuf = new char[20];
			memcpy(cksbuf, &TCPFrame.ih, 20);
			TCPFrame.ih.checksum = TCPFrame.cks((WORD *)cksbuf, 20);

			//TCP����
			TCPFrame.th.source_port = htons(MY_PORT);                    //50466
			TCPFrame.th.dest_port = htons(port);                         //��ǰɨ��Ķ˿ں�
			TCPFrame.th.seq_num = htons(1);
			TCPFrame.th.ack_num = 0;
			TCPFrame.th.len = 0x50;                                      //TCP�ײ����ȣ���ֵ*4��
			TCPFrame.th.flags = 0x02;                                    //SYN=====================
			TCPFrame.th.window_size = htons(0xffff);                     //���ڴ�С
			TCPFrame.th.checksum = 0x0000;                               //У���������
			TCPFrame.th.URG = 0x0000;                                    //URGent Number
			//TCPαͷ�����
			Psedo_TCP_head pth;
			inet_pton(AF_INET, myDevice.ip, &pth.source_addr);           //ԴIP    
			inet_pton(AF_INET, xip, &pth.dest_addr);                     //Ŀ��IP                             
			pth.protocol = TCP;                                          //TCPЭ��
			pth.seg_len = htons(20);                                     //����20��6bit��

			//����TCP�ײ���У��ͣ�α�ײ���ǰ�����ײ�һ�������㣬�����α�ײ�
			char *buf = new char[32];
			memcpy(buf, &pth, 12);
			memcpy(buf + 12, &TCPFrame.th, 20);
			TCPFrame.th.checksum = TCPFrame.cks((WORD *)buf, 32);

			//�����õ����ݰ�װ�뻺��
			memset(sendbuf, 0, sizeof(sendbuf));
			memcpy(sendbuf, &TCPFrame, 54);

			//��¼��ǰ���ڴ���Ķ˿ں�
			sp.current_port = port;

			pcap_sendpacket(myDevice.adhandle, sendbuf, 54);//����

			//���հ��̴߳����Ӧ�˿ڻذ�
			ReleaseMutex(hMutex_SYN);
			//�ȴ��䴦�����
			WaitForSingleObject(hMutex_SYN, INFINITE);

			if (port >= sp.e_port)
			{
				ReleaseMutex(hMutex_SYN);
				break;
			}

			//�˿ڼ�һ
			port++;

			delete[]cksbuf;
			delete[]buf;
		}
	}

	//delete[]sendbuf;
	//delete[]msg;
	return 0;
}

//����TCP_RST���ݱ��ж�����
UINT Send_TCP_RST_Packet(LPVOID lpParameter)
{
	BYTE *sendbuf = new BYTE[54];                     //�����С
	TCP_frame TCPFrame;

	while (1)
	{
		//�̹߳������˳�
		WaitForSingleObject(hBeginALL, INFINITE);
		if (WaitForSingleObject(hEndALL, 0) == WAIT_OBJECT_0)break;

		char *xip = sp.dest_ip;                       //ɨ��Ŀ��IP
		ZeroMemory(sendbuf, 54);
		int port = 0;                                     //��ǰ�˿ں�

		//�ȴ���ʼ�ź�
		WaitForSingleObject(hBeginTCP, INFINITE);

		while (true)
		{
			//�ȴ��հ��߳�֪ͨ
			WaitForSingleObject(hMutex_RST, INFINITE);
			port = sp.current_port;

			//���类���ݹر���Ϣ����ô����ֱ���˳���
			if (WaitForSingleObject(hEndALL, 1) == WAIT_OBJECT_0)break;//BREAK TCP_RST

			//��������
			ZeroMemory(sendbuf, 54);

			//��̫��ͷ��
			memcpy(TCPFrame.eh.source_mac_add, myDevice.mac, 6);        //ԴMAC��ַΪ�Լ���MAC��ַ
			memcpy(TCPFrame.eh.dest_mac_add, sp.dest_MAC, 6);           //Ŀ��MAC��ַ
			TCPFrame.eh.type = htons(ETH_IP);                           //��̫��֡ͷЭ������

			//IPͷ��
			TCPFrame.ih.versionAndIHL = 0x45;                           //IPV4Ϊ4������0101��20�ֽڣ�
			TCPFrame.ih.service = 0x00;                                 //���ַ������㼴��
			TCPFrame.ih.length = htons(0x0028);                         //�ܳ�����Ϊ40
			TCPFrame.ih.id = htons(GetCurrentProcessId());              //ID����ϵͳ���
			TCPFrame.ih.flagAndOffset = 0x00;                           //��־��ƫ�ƣ����㼴��
			TCPFrame.ih.TTL = 58;                                       //TTL
			TCPFrame.ih.protocol = TCP;                                 //Э��������ΪTCP
			TCPFrame.ih.checksum = 0x0000;                              //У������㣬�����ͷ�������֮
			inet_pton(AF_INET, myDevice.ip, &TCPFrame.ih.source_add);   //ԴIP��ַΪ�Լ���IP

			inet_pton(AF_INET, xip, &TCPFrame.ih.dest_add);             //Ŀ��IP��ַ�����û�����              

			//IPͷ��У���
			char *cksbuf = new char[20];
			memcpy(cksbuf, &TCPFrame.ih, 20);
			TCPFrame.ih.checksum = TCPFrame.cks((WORD *)cksbuf, 20);

			//TCP����
			TCPFrame.th.source_port = htons(MY_PORT);                    //50466
			TCPFrame.th.dest_port = htons(port);                         //��ǰɨ��Ķ˿ں�
			TCPFrame.th.seq_num = htons(1);
			TCPFrame.th.ack_num = 0;
			TCPFrame.th.len = 0x50;                                      //TCP�ײ����ȣ���ֵ*4��
			TCPFrame.th.flags = 0x04;                                    //RST================
			TCPFrame.th.window_size = htons(0xffff);                     //���ڴ�С
			TCPFrame.th.checksum = 0x0000;                               //У���������
			TCPFrame.th.URG = 0x0000;                                    //URGent Number
			//TCPαͷ�����
			Psedo_TCP_head pth;
			inet_pton(AF_INET, myDevice.ip, &pth.source_addr);           //ԴIP    
			inet_pton(AF_INET, xip, &pth.dest_addr);                     //Ŀ��IP   
			pth.protocol = TCP;                                          //TCPЭ��
			pth.seg_len = htons(20);                                     //����20��6bit��

			//����TCP�ײ���У��ͣ�α�ײ���ǰ�����ײ�һ�������㣬�����α�ײ�
			char *buf = new char[32];
			memcpy(buf, &pth, 12);
			memcpy(buf + 12, &TCPFrame.th, 20);
			TCPFrame.th.checksum = TCPFrame.cks((WORD *)buf, 32);

			//�����õ����ݰ�װ�뻺��
			memset(sendbuf, 0, sizeof(sendbuf));
			memcpy(sendbuf, &TCPFrame, 54);

			pcap_sendpacket(myDevice.adhandle, sendbuf, 54);//����

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
	BYTE *sendbuf = new BYTE[58];             //�����С	
	char *dest_ip = new char[16];             //����������ݰ��е�Ŀ��IP
	int res;                                  //������
	pcap_pkthdr * pkt_header;
	const u_char * pkt_data;

	while (1)
	{
		//�̹߳������˳�
		WaitForSingleObject(hBeginALL, INFINITE);
		if (WaitForSingleObject(hEndALL, 0) == WAIT_OBJECT_0)break;

		//����סRST�������
		WaitForSingleObject(hMutex_RST, 1);
		//�ȴ���ARP���̵߳�֪ͨ����ʼ�ź�
		WaitForSingleObject(hBeginTCP, INFINITE);

		char *xip = sp.dest_ip;
		ZeroMemory(sendbuf, 58);

		TCP_frame *recvTCP = NULL;
		BOOL flag = FALSE;
		int timeOut = 0;

		WaitForSingleObject(hMutex_SYN, INFINITE);
		hList = GetDlgItem(sp.handle, IDC_RESULT);
		//ץȡ������TCPӦ���
		while (true)
		{
			//���类���ݹر���Ϣ����ô����ֱ���˳���
			if (WaitForSingleObject(hEndALL, 1) == WAIT_OBJECT_0 && sp.current_port != sp.e_port)
			{
				AddListViewItems(hList, 0, 0);
				break;//BREAK TCP
			}

			timeOut++;
			if ((res = pcap_next_ex(myDevice.adhandle, &pkt_header, &pkt_data)) > 0)                 //ʹ�÷ǻص������������ݰ�
			{
				if (*(WORD *)(pkt_data + 12) == htons(ETH_IP) && (*(BYTE *)(pkt_data + 23) == TCP))  //ѡ�������Լ���TCPӦ���
				{
					//��������װ��TCP�ṹ��
					recvTCP = (TCP_frame *)pkt_data;

					//��ʽ��IP�Խ��бȽ�
					sprintf_s(dest_ip, 16, "%d.%d.%d.%d", recvTCP->ih.dest_add & 255, recvTCP->ih.dest_add >> 8 & 255,
						recvTCP->ih.dest_add >> 16 & 255, recvTCP->ih.dest_add >> 24 & 255);

					if (strcmp(dest_ip, myDevice.ip) == 0)                        //ѡ���Լ���TCP��
					{
						//���˿ڿ���
						if (recvTCP->th.flags == SYN_ACK)
						{
							//���������˿����ӿ���
							AddListViewItems(hList, sp.current_port, 1);

							flag = TRUE;
							//����һ���ж����ӵ����ݱ����������Լ��ȴ����ͽ���
							ReleaseMutex(hMutex_RST);
							WaitForSingleObject(hMutex_RST, INFINITE);
						}

						//���˿ڹر�
						if (recvTCP->th.flags == RST_ACK)
						{
							//���������˿ڹر�
							AddListViewItems(hList, sp.current_port, 2);
							flag = TRUE;
						}
					}
				}
			}//�հ��׶�

			//���糬ʱ
			if (timeOut > 1000)
			{
				timeOut = 0;
				AddListViewItems(hList, sp.current_port, 3);
				flag = TRUE;
			}
			//���糬ʱ�����Ѿ��յ��˴𸴵İ������ۺ������������������
			if (flag)
			{
				//����һ����
				ReleaseMutex(hMutex_SYN);
				flag = FALSE;

				//����Ѿ�������
				if (sp.current_port == sp.e_port)
				{
					PostMessage(sp.handle, END_OF_THREAD, NULL, NULL);
					AddListViewItems(hList, 0, 0);
					break;//BREAK TCP
				}

				//���û�У���ȴ�����
				WaitForSingleObject(hMutex_SYN, INFINITE);
			}

		}//TCP
	}

	//delete[]sendbuf;
	//delete[]dest_ip;
	return 0;
}

//�ڽ�����������������
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
	ZeroMemory(&lvi, sizeof(lvi));//�����������������߰���ĳ�ֵ
	lvi.mask = LVIF_TEXT | LVIF_PARAM | LVIF_STATE;
	//����ı��ͳ���
	lvi.pszText = tmp;
	lvi.cchTextMax = lstrlen(lvi.pszText) + 1;
	lvi.iItem = ListItemCount;
	//�����У����һ��ȷʵ��1
	ListView_InsertItem(hwndListView, &lvi);
	ListView_SetItemText(hwndListView, ListItemCount, 0, tmp);

	delete[]tmp;
	return TRUE;
}
