// MainDlg.h : interface of the CMainDlg class
//
/////////////////////////////////////////////////////////////////////////////

#pragma once

#include <atlmisc.h>
#include <atlframe.h>
#include <atlctrls.h>
#include <atldlgs.h>
#include "resource.h"
#include "aboutdlg.h"
#include "pcap.h"

#pragma warning(disable:4996)

class CMainDlg : public CDialogImpl<CMainDlg>, public CUpdateUI<CMainDlg>,
		public CMessageFilter, public CIdleHandler
{
public:
	enum { MAX_APP_ICONS = 4 };

	enum {
		STATUS_ACTIVE,
		STATUS_STOP,
	};

	CComboBox m_comboBox;
	CButton m_checkForever;
	WTL::CFileDialog *m_pFileDlg;

	pcap_t *m_hAdapter;
	pcap_if_t *m_alldevs;
	CIcon	m_iconDefault;
	CIcon	m_icons[MAX_APP_ICONS];

	HANDLE m_hThread;
	int m_status;

	__int64 m_nBytes;
	__int64 m_nPackets;

	BOOL m_bSrcMac;
	BOOL m_bDstMac;

	_bstr_t m_filename;
	int m_interval;
	BOOL m_bForever;
	BYTE m_srcMac[6];
	BYTE m_dstMac[6];

public:
	enum { IDD = IDD_MAINDLG };

	virtual BOOL PreTranslateMessage(MSG* pMsg)
	{
		return CWindow::IsDialogMessage(pMsg);
	}

	virtual BOOL OnIdle()
	{
		return FALSE;
	}

	BEGIN_UPDATE_UI_MAP(CMainDlg)
	END_UPDATE_UI_MAP()

	BEGIN_MSG_MAP(CMainDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
		MESSAGE_HANDLER(WM_DESTROY, OnDestroy)
		COMMAND_ID_HANDLER(IDCANCEL, OnCancel)
		MESSAGE_HANDLER(WM_CLOSE, OnClose)
		COMMAND_ID_HANDLER(IDC_BUTTON_START, OnStart)
		COMMAND_ID_HANDLER(IDC_BUTTON_STOP, OnStop)
		COMMAND_ID_HANDLER(IDC_BUTTON_CHOOSE_FILE, OnSelectFile)
		COMMAND_ID_HANDLER(IDC_BUTTON_ABOUT, OnAppAbout)
		COMMAND_HANDLER(IDC_COMBO_ADAPTERS, CBN_SELCHANGE, OnSelchangeCombo)
	END_MSG_MAP()

// Handler prototypes (uncomment arguments if needed):
//	LRESULT MessageHandler(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
//	LRESULT CommandHandler(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
//	LRESULT NotifyHandler(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/)

	LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		// center the dialog on the screen
		CenterWindow();

		// set icons
		HICON hIcon = (HICON)::LoadImage(_Module.GetResourceInstance(), MAKEINTRESOURCE(IDR_MAINFRAME), 
			IMAGE_ICON, ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON), LR_DEFAULTCOLOR);
		SetIcon(hIcon, TRUE);
		HICON hIconSmall = (HICON)::LoadImage(_Module.GetResourceInstance(), MAKEINTRESOURCE(IDR_MAINFRAME), 
			IMAGE_ICON, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);
		SetIcon(hIconSmall, FALSE);

		// register object for message filtering and idle updates
		CMessageLoop* pLoop = _Module.GetMessageLoop();
		ATLASSERT(pLoop != NULL);
		pLoop->AddMessageFilter(this);
		pLoop->AddIdleHandler(this);

		UIAddChildWindowContainer(m_hWnd);

		// set title bold
#if 0
		SetBold(IDC_STATIC_1);
		SetBold(IDC_STATIC_2);
		SetBold(IDC_STATIC_3);
		SetBold(IDC_STATIC_4);
		SetBold(IDC_STATIC_5);
		SetBold(IDC_STATIC_6);
		SetBold(IDC_STATIC_7);
		SetBold(IDC_STATIC_8);
		SetBold(IDC_STATIC_9);
#endif

		// find all adapters
		pcap_if_t *dev;
		char errbuf[PCAP_ERRBUF_SIZE];

		m_comboBox.Attach(GetDlgItem(IDC_COMBO_ADAPTERS));

		/* Retrieve the device list */
		m_alldevs = NULL;
		if(pcap_findalldevs(&m_alldevs, errbuf) != -1)
		{
			for (dev = m_alldevs; dev; dev = dev->next)
			{
				CComBSTR str = dev->name;
				m_comboBox.InsertString(0, str);
				m_comboBox.SetItemData(0, (DWORD_PTR)dev);
			}

			m_comboBox.SetCurSel(0);
			BOOL b;
			OnSelchangeCombo(0, 0, 0, b);
		}

		m_nBytes = 0;
		m_nPackets = 0;

		m_hThread = NULL;
		m_hAdapter = NULL;

		// init icons
		m_icons[0].LoadIcon(IDI_ICON1);
		m_icons[1].LoadIcon(IDI_ICON2);
		m_icons[2].LoadIcon(IDI_ICON3);
		m_icons[3].LoadIcon(IDI_ICON4);
		m_iconDefault.LoadIcon(IDI_ICON6);

		m_checkForever.Attach(GetDlgItem(IDC_CHECK_FOREVER));

		LoadConfig();

		return TRUE;
	}

	LRESULT OnDestroy(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		// unregister message filtering and idle updates
		CMessageLoop* pLoop = _Module.GetMessageLoop();
		ATLASSERT(pLoop != NULL);
		pLoop->RemoveMessageFilter(this);
		pLoop->RemoveIdleHandler(this);

		return 0;
	}

	bool ReplayPcapFile(const char *filename, BYTE *srcMac, BYTE *dstMac)
	{
		struct pcap_pkthdr *pkt_hdr;
		const u_char *pkt_buf;
		u_char local_buf[2048];
		int i;

		pcap_t *file = pcap_open_offline(filename, (char *)local_buf);

		if (!file)
			return false;

		while (pcap_next_ex(file, &pkt_hdr, &pkt_buf) == 1 && m_status == STATUS_ACTIVE) {
			memcpy(local_buf, pkt_buf, pkt_hdr->len);

			if (dstMac)
				for (i = 0; i < 6; i++) local_buf[i] = dstMac[i];

			if (srcMac)
				for (i = 0; i < 6; i++) local_buf[i+6] = srcMac[i];

			pcap_sendpacket(m_hAdapter, local_buf, pkt_hdr->len);
			m_nPackets++;
			m_nBytes += pkt_hdr->len;
			UpdateStatus();
			Sleep(m_interval);
		}

		pcap_close(file);
		return true;
	}

	static DWORD __stdcall send_thread(void *arg)
	{
		CMainDlg *pDlg = (CMainDlg *)arg;

		do {
			if (!pDlg->ReplayPcapFile(
				pDlg->m_filename,
				pDlg->m_bSrcMac ? pDlg->m_srcMac : NULL,
				pDlg->m_bDstMac ? pDlg->m_dstMac : NULL))
			{
				pDlg->MessageBox(_T("Open PCAP file failed."), _T("Error"), MB_OK | MB_ICONERROR);
				break;
			}

			Sleep(10);
		} while (pDlg->m_status == STATUS_ACTIVE && pDlg->m_bForever);

		::EnableWindow(pDlg->GetDlgItem(IDC_BUTTON_START), TRUE);
		pDlg->m_hThread = NULL;

		return 0;
	}

	LRESULT OnStart(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		TCHAR buffer[MAX_PATH];
		m_comboBox.GetLBText(m_comboBox.GetCurSel(), buffer);
		m_hAdapter = pcap_open_live(_bstr_t(buffer), 65536, 1, 1000, NULL);

		GetDlgItemText(IDC_EDIT_PCAP_FILE, buffer, MAX_PATH);
		m_filename = buffer;

		m_bForever = m_checkForever.GetCheck();
		GetDlgItemText(IDC_EDIT_INTERVAL, buffer, MAX_PATH);
		m_interval = atoi(_bstr_t(buffer));

		GetDlgItemText(IDC_EDIT_MAC_SRC, buffer, MAX_PATH);
		m_bSrcMac = str2mac(_bstr_t(buffer), m_srcMac);

		GetDlgItemText(IDC_EDIT_MAC_DST, buffer, MAX_PATH);
		m_bDstMac = str2mac(_bstr_t(buffer), m_dstMac);

		FILE *file = fopen(m_filename, "r");
		if (file != NULL) {
			fclose(file);
			m_status = STATUS_ACTIVE;
			::EnableWindow(GetDlgItem(IDC_BUTTON_START), FALSE);
			m_hThread = ::CreateThread(NULL, 0, send_thread, this, 0, NULL);
		}
		else {
			_bstr_t errmsg;

			if (m_filename.length() == 0) {
				errmsg = "You need to specify a pcap file for input.";
			}
			else {
				errmsg = "File \"" + m_filename + "\" does not exist.";
			}

			MessageBox(errmsg, _T("Error"), MB_OK | MB_ICONERROR);
		}

		return 0;
	}

	LRESULT OnStop(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		m_status = STATUS_STOP;
		return 0;
	}

	LRESULT OnCancel(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		CloseDialog(wID);
		return 0;
	}

	LRESULT OnAppAbout(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		CAboutDlg dlg;
		dlg.DoModal();
		return 0;
	}

	LRESULT OnSelectFile(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		m_pFileDlg = new WTL::CFileDialog(true);
		ATLASSERT(m_pFileDlg != NULL);

		m_pFileDlg->m_ofn.lpstrTitle = _T("Select PCAP File");
		m_pFileDlg->m_ofn.lpstrFilter = _T("PCAP files (*.pcap)\0*.pcap\0");

		TCHAR initPath[MAX_PATH];
		::GetCurrentDirectory(MAX_PATH, initPath);
		m_pFileDlg->m_ofn.lpstrInitialDir = initPath;

		if (m_pFileDlg->DoModal() == IDOK) {
			::SetWindowText(GetDlgItem(IDC_EDIT_PCAP_FILE), m_pFileDlg->m_szFileName);
		}

		delete m_pFileDlg;
		return 0;
	}

	LRESULT OnClose(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& bHandled)
	{
		if (m_hThread != NULL) {
			MessageBox(_T("Task is running, stop it before exit."), _T("Prompt"), MB_OK | MB_ICONSTOP);
			bHandled = TRUE;
		}
		else {
			bHandled = FALSE;
		}

		return 0;
	}

	LRESULT CMainDlg::OnSelchangeCombo(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		pcap_if_t *dev = (pcap_if_t *)m_comboBox.GetItemData(m_comboBox.GetCurSel());

		if (dev) {
			SetDlgItemText(IDC_EDIT_DESC, _bstr_t(dev->description));
			if (dev->addresses && dev->addresses->addr) {
				sockaddr_in * addr = (sockaddr_in *)dev->addresses->addr;
				SetDlgItemText(IDC_EDIT_ADDRESS, _bstr_t(inet_ntoa(addr->sin_addr)));
			}
			else {
				SetDlgItemText(IDC_EDIT_ADDRESS, _bstr_t("N/A"));
			}
		}
		else {
			SetDlgItemText(IDC_EDIT_DESC, _bstr_t("N/A"));
		}

		return 0;
	}

	void CloseDialog(int nVal)
	{
		if (m_hAdapter)
			pcap_close(m_hAdapter);

		if (m_alldevs)
			pcap_freealldevs(m_alldevs);

		// save user configuration
		SaveConfig();

		DestroyWindow();
		::PostQuitMessage(nVal);
	}

	void SetBold(int uID)
	{
		HWND hWnd = GetDlgItem(uID);
		HFONT hFont = (HFONT)::SendMessage(hWnd, WM_GETFONT, 0, 0);

		LOGFONT lFont;
		::GetObject(hFont, sizeof(lFont), &lFont);
		lFont.lfWeight = FW_BOLD;
		hFont = ::CreateFontIndirect(&lFont);

		::SendMessage(hWnd, WM_SETFONT, (WPARAM)hFont, (LPARAM)true);
	}

	void ShowDynamicIcon()
	{
		static int i = 0;

		if (++i == MAX_APP_ICONS) i = 0;
		SetIcon(m_icons[i]);
	}

	void UpdateStatus()
	{
		SetDlgItemText(IDC_EDIT_BYTES, _bstr_t(m_nBytes));
		SetDlgItemText(IDC_EDIT_PACKETS, _bstr_t(m_nPackets));
	}

	bool str2mac(const char *str, BYTE *mac)
	{
		const char *del = ".:- ";
		char *s = strdup(str);

		char *p = strtok(s, del);
		int i = 0;
		int hex;

		while (p) {
			if (i < 6 && strlen(p) == 2 && isxdigit(p[0]) && isxdigit(p[1])) {
				sscanf(p, "%x", &hex);
				mac[i++] = (BYTE)hex;
				p = strtok(NULL, del);
			}
			else {
				free(s);
				return false;
			}
		}

		free(s);
		return (i == 6);
	}

	void LoadConfig()
	{
		const int N = 1024;
		CRegKey reg;
		CString str;
		TCHAR buffer[N];
		ULONG nChars;
		DWORD dword;

		str.LoadString(IDS_APP_REG_NAME);
		if (reg.Open(HKEY_LOCAL_MACHINE, str) == ERROR_SUCCESS)
		{
			str.LoadString(IDS_REG_NETWORK_ADAPTER_INDEX);
			if (reg.QueryDWORDValue(str, (DWORD &)dword) == ERROR_SUCCESS)
			{
				m_comboBox.SetCurSel(dword);
				BOOL b;
				OnSelchangeCombo(0, 0, 0, b);
			}

			str.LoadString(IDS_REG_LOOP_FOREVER);
			if (reg.QueryDWORDValue(str, (DWORD &)dword) == ERROR_SUCCESS)
			{
				m_checkForever.SetCheck(dword);
			}

			str.LoadString(IDS_REG_PACKET_INTERVAL);
			nChars = N;
			if (reg.QueryStringValue(str, buffer, &nChars) == ERROR_SUCCESS)
			{
				SetDlgItemText(IDC_EDIT_INTERVAL, buffer);
			}

			str.LoadString(IDS_REG_PCAP_FILENAME);
			nChars = N;
			if (reg.QueryStringValue(str, buffer, &nChars) == ERROR_SUCCESS)
			{
				SetDlgItemText(IDC_EDIT_PCAP_FILE, buffer);
			}

			str.LoadString(IDS_REG_SOURCE_MAC_ADDR);
			nChars = N;
			if (reg.QueryStringValue(str, buffer, &nChars) == ERROR_SUCCESS)
			{
				SetDlgItemText(IDC_EDIT_MAC_SRC, buffer);
			}

			str.LoadString(IDS_REG_DEST_MAC_ADDR);
			nChars = N;
			if (reg.QueryStringValue(str, buffer, &nChars) == ERROR_SUCCESS)
			{
				SetDlgItemText(IDC_EDIT_MAC_DST, buffer);
			}
		}
	}

	void SaveConfig()
	{
		CRegKey reg;
		CString str;
		TCHAR buffer[1024];

		str.LoadString(IDS_APP_REG_NAME);
		if (reg.Open(HKEY_LOCAL_MACHINE, str) != ERROR_SUCCESS)
		{
			if (reg.Create(HKEY_LOCAL_MACHINE, str) != ERROR_SUCCESS)
			{
				return;
			}
		}

		str.LoadString(IDS_REG_NETWORK_ADAPTER_INDEX);
		reg.SetDWORDValue(str, m_comboBox.GetCurSel());

		str.LoadString(IDS_REG_LOOP_FOREVER);
		reg.SetDWORDValue(str, m_checkForever.GetCheck());

		str.LoadString(IDS_REG_PACKET_INTERVAL);
		GetDlgItemText(IDC_EDIT_INTERVAL, buffer, sizeof(buffer) / sizeof(TCHAR));
		reg.SetStringValue(str, buffer);

		str.LoadString(IDS_REG_PCAP_FILENAME);
		GetDlgItemText(IDC_EDIT_PCAP_FILE, buffer, sizeof(buffer) / sizeof(TCHAR));
		reg.SetStringValue(str, buffer);

		str.LoadString(IDS_REG_SOURCE_MAC_ADDR);
		GetDlgItemText(IDC_EDIT_MAC_SRC, buffer, sizeof(buffer) / sizeof(TCHAR));
		reg.SetStringValue(str, buffer);

		str.LoadString(IDS_REG_DEST_MAC_ADDR);
		GetDlgItemText(IDC_EDIT_MAC_DST, buffer, sizeof(buffer) / sizeof(TCHAR));
		reg.SetStringValue(str, buffer);		
	}
};
