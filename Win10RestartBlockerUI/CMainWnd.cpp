//  
//    Windows 10 Update Restart Blocker
//    "Control forced restarts from Windows Updates & custom patch for its vulnerability bug."
//    Copyright (c) 2021 www.dennisbabkin.com
//    
//        https://dennisbabkin.com/w10urb
//    
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//    
//        https://www.apache.org/licenses/LICENSE-2.0
//    
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//  
//


//Class for main window
#include "CMainWnd.h"

#include "SysInfo.h"			//For bug reports only

EXTERN_C IMAGE_DOS_HEADER __ImageBase;




CMainWnd::CMainWnd(HINSTANCE hInst)
	: _ghInstance(hInst ? hInst : (HINSTANCE)::GetModuleHandle(NULL))
	, hDlg(NULL)
	, dwExitCode(0)
	, _hAtomClassName(NULL)
	, _hEventQuitNow(NULL)
	, _hIconLogo(NULL)
	, _gszMainIconLogo({0, 0})
	, g_settings(FALSE)
	, _nCurVal1Hrs(0)
	, gReqAdmin(RYNE_ERROR)
	, _gbPostInitDlgDone(FALSE)
	, _ghCmdMonitor(NULL)
	, _hThreadEventMon(NULL)
	, _hEventStop(NULL)
	, _hAccelMain(NULL)
{
#ifdef _DEBUG


#endif

}

CMainWnd::~CMainWnd()
{
	//Destructor will be called when this class is destroyed
	//(which may be much later after this window is destroyed)
	//INFO: Thus to release resources from this class along with the window, call OnFinalMessage() instead

	VERIFY(_unregisterCurrentWndClass());

	//Thread must be closed by now!
	ASSERT(!_hThreadEventMon);
	ASSERT(!_hEventStop);
}

BOOL CMainWnd::CreateMainWnd(BOOL bPreventAnotherInstance)
{
	//Create main window
	//'bPreventAnotherInstance' = TRUE to not allow another instance of this app to run
	//RETURN:
	//		= TRUE if window was created
	BOOL bRes = FALSE;

	if(!_hEventQuitNow)
	{
		//Check if our window already exists
		_hEventQuitNow = AUX_FUNCS::CreateSharedEvent(EVENT_NAME_GUI_APP_CLOSE_NOW, FALSE);
		if(!bPreventAnotherInstance ||
			::GetLastError() != ERROR_ALREADY_EXISTS)
		{

			//Register our special class
			if(ChangeClassNameForDlgWnd(CLASS_NAME_SETTINGS_MAIN_WND))
			{
				//Create main window
				BOOL bR = DialogBoxParamSpecial(_ghInstance, MAKEINTRESOURCE(IDD_MAIN_WND), NULL, _iniDlgProc, (LPARAM)this, &this->_hAccelMain);
				if(bR)
				{
					//Window was shown OK
					bRes = TRUE;
				}
				else
				{
					//Failed to show
					dwExitCode = AUX_FUNCS::GetLastErrorNotNULL(1449);

					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(500, L"nR=%d", bR);
					ASSERT(NULL);
				}
			}
			else
			{
				//Failed
				dwExitCode = AUX_FUNCS::GetLastErrorNotNULL(8371);
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(507);
				ASSERT(NULL);
			}
		}
		else
		{
			//Another instance already exists
			ASSERT(_hEventQuitNow);
			::CloseHandle(_hEventQuitNow);
			_hEventQuitNow = NULL;


			//Find our windows by its class
			HWND hWnd = ::FindWindow(CLASS_NAME_SETTINGS_MAIN_WND, NULL);
			if(hWnd)
			{
				//Is it minimized?
				if(::IsIconic(hWnd))
				{
					//Restore that window so that the user can see it
					//INFO: We can't just call ShowWindow(hWnd, SW_RESTORE) because that window may be coming from an elevated process

					//As a "hack", we can post it a sys-command message, that will be passed through UIPI
					if(!::PostMessage(hWnd, WM_SYSCOMMAND, SC_RESTORE, 0))
					{
						//Flash it in the taskbar, if all else fails
						::FlashWindow(hWnd, TRUE);
					}
				}

				//And bring it to the forefront
				::SetForegroundWindow(hWnd);
			}
			else
			{
				//Couldn't find our window -- hah?
				ASSERT(NULL);
				::MessageBeep(MB_ICONERROR);
			}

			//Return success
			bRes = TRUE;
		}
	}
	else
	{
		//Can't call it repeatedly
		dwExitCode = 3140;
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(508);
		ASSERT(NULL);
	}

	return bRes;
}

INT_PTR CMainWnd::_iniDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if(uMsg == WM_INITDIALOG)
	{
		//Set our redirection proc
		ASSERT(lParam);
		::SetWindowLongPtr(hDlg, DWLP_USER, lParam);
		::SetWindowLongPtr(hDlg, DWLP_DLGPROC, (LONG_PTR)_redirDlgProc);

		//Set our window handle
		CMainWnd* pThis = (CMainWnd*)lParam;
		pThis->hDlg = hDlg;

		//Call our DlgProc in the class
		return pThis->DlgProc(uMsg, wParam, lParam);
	}

	return FALSE;
}

INT_PTR CMainWnd::_redirDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	//Redirection to our DlgProc in the class
	CMainWnd* pThis = (CMainWnd*)::GetWindowLongPtr(hDlg, DWLP_USER);
	ASSERT(pThis);
	ASSERT(pThis->hDlg == hDlg);

	return pThis->DlgProc(uMsg, wParam, lParam);
}


BOOL CMainWnd::DialogBoxParamSpecial(HINSTANCE hInstance, LPCWSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam, HACCEL* p_hAccel)
{
	//Same as DialogBoxParam() but with support for accelerators
	//RETURN:
	//		= TRUE if success showing dialog
	//		= FALSE if error - check GetLastError() for info
	BOOL bResult = FALSE;

	HWND hDlg = ::CreateDialogParam(hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam);
	if (hDlg)
	{
		::ShowWindow(hDlg, SW_SHOW);

		if (hWndParent)
		{
			//Disable parent window to make ours into a modal dialog
			::EnableWindow(hWndParent, FALSE);
		}

		MSG msg;
		BOOL bStopStop = FALSE;

		for (; !bStopStop;)
		{
			DWORD dwR = ::MsgWaitForMultipleObjectsEx(0, NULL, INFINITE, QS_ALLINPUT,
				MWMO_ALERTABLE | MWMO_INPUTAVAILABLE);
			if (dwR == WAIT_FAILED)
			{
				//Error
				ASSERT(false);
				break;
			}

			while (::PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
			{
				//Hack to ensure processing of EndDialog() calls
				if (msg.message == WM_NULL && msg.hwnd == hDlg)
				{
					//Normal exit
					bResult = TRUE;

					bStopStop = true;
					break;
				}

				//Do we have accelerators?
				HACCEL hAccel = p_hAccel ? *p_hAccel : NULL;
				if (hAccel)
				{
					//With accelerators
					BOOL bMsgDispatched = FALSE;

					if (hDlg == msg.hwnd ||
						::IsChild(hDlg, msg.hwnd))
					{
						//Translate accelerators
						bMsgDispatched = ::TranslateAccelerator(hDlg, hAccel, &msg);
					}
					
					if (!bMsgDispatched)
					{
						//Process dialog-specific messages
						if (::IsDialogMessage(hDlg, &msg))
						{
							bMsgDispatched = TRUE;
						}
					}

					if (!bMsgDispatched)
					{
						TranslateMessage(&msg);
						DispatchMessage(&msg);
					}
				}
				else
				{
					//No accelerators
					if (!::IsDialogMessage(hDlg, &msg))
					{
						if (msg.message >= WM_KEYFIRST && msg.message <= WM_KEYLAST)
						{
							TranslateMessage(&msg);
						}

						DispatchMessage(&msg);
					}
				}
			}
		}

		::DestroyWindow(hDlg);
		hDlg = NULL;

		if (hWndParent)
		{
			//Re-enable parent window
			::EnableWindow(hWndParent, TRUE);
		}
	}
	else
		ASSERT(false);

	return bResult;
}



INT_PTR CMainWnd::DlgProc(UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	//Main dialog procedure for the main window
	switch (uMsg)
	{
		case WM_INITDIALOG:
		{
			return OnInitDialog((HWND)wParam);
		}

		case WM_NCDESTROY:
		{
			return OnFinalMessage();
		}
		break;

		case WM_PAINT:
		{
			PAINTSTRUCT ps;
			HDC hdc = BeginPaint(hDlg, &ps);
			OnPaint(hdc, ps);
			EndPaint(hDlg, &ps);

			if(!_gbPostInitDlgDone)
			{
				//Do this only once
				_gbPostInitDlgDone = TRUE;

				//Post a message to self
				if(!::PostMessage(hDlg, MSG_ID_POST_INIT_DIALOG, 0, 0))
				{
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(530, L"h=%p", hDlg);
					ASSERT(NULL);
				}
			}
		}
		break;

		case WM_CTLCOLORSTATIC:
		{
			HBRUSH hBrush = (HBRUSH)::DefWindowProc(hDlg, uMsg, wParam, lParam);
			OnCtrlColor((HDC)wParam, (HWND)lParam, ::GetDlgCtrlID((HWND)lParam), hBrush);

			return (INT_PTR)hBrush;
		}

		case WM_COMMAND:
		{
			//Distinguish where command is coming from
			WORD wCmdId = LOWORD(wParam);
			WORD wType = HIWORD(wParam);

			if(!lParam)
			{
				//Menu command or Accelerator
				return OnMenuCommand(wCmdId, wType == 1);
			}
			else
			{
				//Buttons and other controls
				return OnCtrlCommand(wCmdId, wType);
			}
		}
		break;

		case WM_HELP:
		{
			OnHelpInfo();
			return TRUE;
		}

		case MSG_ID_POST_INIT_DIALOG:
		{
			OnPostInitDialog();
		}
		break;

		case MSG_ID_DRAG_N_DROP_FILE:
		{
			//'lParam' = file path
			OnDropFile((std::wstring*)lParam);
		}
		break;
	}

	return FALSE;
}




BOOL CMainWnd::OnInitDialog(HWND hWndDefaultFocus)
{
	//Main window initalization
	//RETURN:
	//		= TRUE if set keyboard focus to 'hWndDefaultFocus'
	//		= FALE to prevent setting default focus
	BOOL bResSetDefFocus = FALSE;

	//Set window title
	::SetWindowText(hDlg, MAIN_APP_NAME);


	//Load icons (as shared so that we don't have to delete them)
	HANDLE hIconLg = ::LoadImage(this->_ghInstance, MAKEINTRESOURCE(IDI_MAIN_ICON), IMAGE_ICON, ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON), LR_SHARED);
	ASSERT(hIconLg);
	HANDLE hIconSm = ::LoadImage(this->_ghInstance, MAKEINTRESOURCE(IDI_MAIN_ICON), IMAGE_ICON, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON), LR_SHARED);
	ASSERT(hIconSm);

	//Set window icons
	::SendMessage(hDlg, WM_SETICON, ICON_BIG, (LPARAM)hIconLg);
	::SendMessage(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIconSm);


	//Get current DPI
	double fDpiX;
	VERIFY(AUX_FUNCS::GetDPI(hDlg, &fDpiX));

	//Load logo icon
	ASSERT(!_hIconLogo);
	_gszMainIconLogo.cx= (int)(MAIN_LOGO_ICON_WIDTH * fDpiX);
	_gszMainIconLogo.cy = (int)(MAIN_LOGO_ICON_HEIGHT * fDpiX);
	HRESULT hr = ::LoadIconWithScaleDown(this->_ghInstance, MAKEINTRESOURCE(IDI_MAIN_ICON), _gszMainIconLogo.cx, _gszMainIconLogo.cy, &_hIconLogo);
	ASSERT(_hIconLogo);
	if(hr != S_OK)
	{
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(509, L"dpi=%f, w=%d, h=%d", fDpiX, _gszMainIconLogo.cx, _gszMainIconLogo.cy);
		ASSERT(NULL);
	}

	
	//Allow this window to be sent to the foreground
	::AllowSetForegroundWindow(ASFW_ANY);


	////Messages to allow for drag-and-drop to work if we're running elevated (or with higher mandatory label)    <-- does not seem to work!
	//UINT nMsgsAllow[] = {
	//	WM_COPYDATA,
	//	WM_DROPFILES,
	//	0x0049,			//WM_COPYGLOBALDATA,
	//};

	//for (int i = 0; i < _countof(nMsgsAllow); i++)
	//{
	//	if (!::ChangeWindowMessageFilter(nMsgsAllow[i], MSGFLT_ADD))
	//	{
	//		//Failed
	//		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(675, L"m=%u", nMsgsAllow[i]);
	//		ASSERT(NULL);
	//	}
	//}


	//Register for drag-and-drop into this window
	DRAG_N_DROP_REGISTER dndr(this->hDlg, DND_WND_T_GENERIC);
	if (!RegisterForDragAndDrop(&dndr))
	{
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(672);
		ASSERT(NULL);
	}


	//Load accelerators
	ASSERT(!_hAccelMain);
	_hAccelMain = ::LoadAccelerators(_ghInstance, MAKEINTRESOURCE(IDR_ACCELERATOR_MAIN));
	if (!_hAccelMain)
	{
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(664);
		ASSERT(NULL);
	}


	//Place our window in the middle of the screen
	if(!PositionThisWindowInCenterOfMonitor(_ghCmdMonitor))
	{
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(505, L"h=%p", _ghCmdMonitor);
		ASSERT(NULL);
	}


	//Did we read our settings from the command line?
	if(g_CmdSvData.saveOp == SV_O_None)
	{
		//No, then get settings from the persistent storage
		g_settings.readAll();
	}
	else
	{
		//Use settings passed from the command line
		g_settings = g_CmdSvData.Sttgs;
	}

	//Set UI controls
	SetCtrls(g_settings);


	//See if we can save changes
	gReqAdmin = IsElevationRequiredToSaveChanges();
	if(gReqAdmin != RYNE_NO)
	{
		if(gReqAdmin != RYNE_YES)
		{
			//Failed to determine
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(512);
			ASSERT(NULL);
		}

		//Display UAC shields on OK and Apply buttons
		::SendDlgItemMessage(hDlg, IDOK, BCM_SETSHIELD, 0, TRUE);
		::SendDlgItemMessage(hDlg, IDAPPLY, BCM_SETSHIELD, 0, TRUE);
	}


	//Create stop event
	ASSERT(!_hEventStop);
	_hEventStop = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!_hEventStop)
	{
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(608);
		ASSERT(NULL);
	}

	//Start a worker thread that will keep track if we need to close this app from outside
	ASSERT(!_hThreadEventMon);
	_hThreadEventMon = ::CreateThread(NULL, 0, ThreadProc_EventsWorker, this, 0, NULL);
	if (!_hThreadEventMon)
	{
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(606);
		ASSERT(NULL);
	}



	return bResSetDefFocus;
}

void CMainWnd::OnPostInitDialog()
{
	//It is called once after main window has initialized & been fully shown
	//INFO: It's a good place to show some initial UI ...

	//Do we have command line run?
	if(g_CmdSvData.saveOp != SV_O_None)
	{
		//Save the data passed in the command line
		if(SaveData(g_CmdSvData.Sttgs))
		{
			//Saved everything OK

			//Do we need to close?
			if(g_CmdSvData.saveOp == SV_O_OK)
			{
				//Post message to close
				if(!::PostMessage(hDlg, WM_CLOSE, 0, 0))
				{
					//Failed
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(532, L"h=%p", hDlg);
					ASSERT(NULL);

					::MessageBeep(MB_ICONERROR);
				}
			}
		}
		else
		{
			//Failed
			ShowFailedToSaveDataUI(533);
		}
	}
	else
	{
		//Test if we have our version of the DLL installed in the system folder
		IsShellChromeAPI_Installed(TRUE);

		//Do we have a config file path to open?
		//INFO: It will be passed via a command line
		if (!gstrOpenCfgFilePath.empty())
		{
			//Load it then
			LoadRegConfigFile(gstrOpenCfgFilePath.c_str());

		}
	}
}

BOOL CMainWnd::OnFinalMessage()
{
	//Last message received by this window before it's removed
	//RETURN:
	//		= FALSE to let dialog manager to process it as well

	//Unregister drag-and-drop
	if (!UnregisterFromDragAndDrop())
	{
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(673);
		ASSERT(NULL);
	}


	//Signal event thread to close (in case it wasn't done earlier)
	ASSERT(_hEventStop);
	if (_hEventStop)
	{
		if (!::SetEvent(_hEventStop))
		{
			//Error
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(627);
			ASSERT(NULL);
		}
	}



	if (_hThreadEventMon)
	{
		//And wait for the events thead
		DWORD dwR = ::WaitForSingleObject(_hThreadEventMon,
#ifdef _DEBUG
			INFINITE
#else
			5 * 1000		//5 sec timeout
#endif
		);
		if (dwR != WAIT_OBJECT_0)
		{
			//Error
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(607, L"r=%d", dwR);
			ASSERT(NULL);
		}

		_hThreadEventMon = NULL;
	}

	if (_hEventStop)
	{
		::CloseHandle(_hEventStop);
		_hEventStop = NULL;
	}


	if(_hIconLogo)
	{
		VERIFY(::DestroyIcon(_hIconLogo));
		_hIconLogo = NULL;
	}

	if (_hAccelMain)
	{
		VERIFY(::DestroyAcceleratorTable(_hAccelMain));
		_hAccelMain = NULL;
	}


	return FALSE;
}


void CMainWnd::OnPaint(HDC hDC, PAINTSTRUCT& ps)
{
	//Painting of the main window
	//'hDC' = device context for drawing
	//'ps' = info about paiting surface

	HWND hAnchorWnd = ::GetDlgItem(hDlg, IDC_STATIC_ICN);
	ASSERT(hAnchorWnd);
	RECT rcAnchor = {};
	::GetWindowRect(hAnchorWnd, &rcAnchor);
	::ScreenToClient(hDlg, (POINT*)&rcAnchor);
	::ScreenToClient(hDlg, ((POINT*)&rcAnchor) + 1);

	int nMidX = (rcAnchor.left + rcAnchor.right) / 2;
	int nMidY = (rcAnchor.top + rcAnchor.bottom) / 2;

	//Draw our logo
	ASSERT(_hIconLogo);
	ASSERT(_gszMainIconLogo.cx > 0 && _gszMainIconLogo.cy > 0);
	::DrawIconEx(hDC, nMidX - _gszMainIconLogo.cx / 2, nMidY - _gszMainIconLogo.cy / 2,
		_hIconLogo, _gszMainIconLogo.cx, _gszMainIconLogo.cy, 
		NULL, ::GetSysColorBrush(COLOR_BTNFACE), DI_NORMAL);

}



BOOL CMainWnd::ChangeClassNameForDlgWnd(LPCTSTR pStrNewClassName)
{
	//Change class name for this window
	//'pStrNewClassName' = new class name to use.
	//						IMPORTANT: If doing this to a dialog box created from the resource, make sure to add the following line to DIALOGEX template:
	//									CLASS "new-class-name-here"
	//RETURN:
	//		= TRUE if success
	//		= FALSE if error (check GetLastError() for details)
	BOOL bRes = FALSE;
	int nOSError = 0;

	if(pStrNewClassName && pStrNewClassName[0])
	{
		WNDCLASSEXW wcx = {};
		wcx.cbSize = sizeof(wcx);
		if(::GetClassInfoEx(this->_ghInstance, WC_DIALOG, &wcx))
		{
			wcx.lpszClassName = pStrNewClassName;

			wcx.style &= ~CS_GLOBALCLASS;

			//Unregister old class
			VERIFY(_unregisterCurrentWndClass());

			//And register new class
			ASSERT(_hAtomClassName == NULL);
			if(_hAtomClassName = ::RegisterClassEx(&wcx))
			{
				//Done
				bRes = TRUE;
			}
			else
			{
				nOSError = ::GetLastError();

				if(nOSError == ERROR_CLASS_ALREADY_EXISTS)
				{
					//Not an error - another window must have registered it
					bRes = TRUE;
				}
			}
		}
		else
			nOSError = ::GetLastError();
	}
	else
		nOSError = ERROR_INVALID_PARAMETER;

	::SetLastError(nOSError);
	return bRes;
}

BOOL CMainWnd::_unregisterCurrentWndClass()
{
	//RETURN:
	//		= TRUE if class was unregistered OK
	BOOL bRes = TRUE;

	if(_hAtomClassName)
	{
		if(!::UnregisterClass((LPCTSTR)_hAtomClassName, this->_ghInstance))
		{
			//Failed
			bRes = FALSE;
		}

		_hAtomClassName = NULL;
	}

	return bRes;
}


BOOL CMainWnd::PositionThisWindowInCenterOfMonitor(HMONITOR hMonitor)
{
	//Place this window in the center of the monitor
	//'hMonitor' = monitor handle to use, or NULL to use monitor where the aoo was original run from (in Windows Explorer)
	//RETURN:
	//		= TRUE if success
	BOOL bRes = FALSE;

	//Try to get the monitor that this app was started in
	BOOL bGotMi = FALSE;

	if(!hMonitor)
	{
		STARTUPINFO si = {0};
		::GetStartupInfo(&si);

		hMonitor = (HMONITOR)si.hStdOutput;
	}

	//WCHAR buff[256];
	//::StringCchPrintf(buff, _countof(buff), L"h=%p, flgs=0x%X", si.hStdOutput, si.dwFlags);
	//ShowMessageBox(buff);

	MONITORINFO mi = {0};
	mi.cbSize = sizeof(mi);
	if(::GetMonitorInfo(hMonitor, &mi))
	{
		//Got monitor size & position where the process was started from
		bGotMi = TRUE;
	}
	else
	{
		//Use the monitor we're running in
		HMONITOR hMon = ::MonitorFromWindow(hDlg, MONITOR_DEFAULTTONEAREST);
		if(::GetMonitorInfo(hMon, &mi))
		{
			bGotMi = TRUE;
		}
		else
		{
			//Failed for some reason
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(504, L"h=%p", hMon);
			ASSERT(NULL);
		}
	}

	if(bGotMi)
	{
		//Center our window againt the monitor
		RECT rcThis = {};
		::GetWindowRect(hDlg, &rcThis);
		int nWndW = rcThis.right - rcThis.left;
		int nWndH = rcThis.bottom - rcThis.top;
		int nScrW = mi.rcWork.right - mi.rcWork.left;
		int nScrH = mi.rcWork.bottom - mi.rcWork.top;

		if(::SetWindowPos(hDlg, HWND_TOP, 
			mi.rcWork.left + (nScrW - nWndW) / 2, 
			mi.rcWork.top + (nScrH - nWndH) / 2,
			0, 0, SWP_NOSIZE))
		{
			//Done
			bRes = TRUE;
		}
	}

	return bRes;
}



BOOL CMainWnd::OnCtrlCommand(WORD wCtrlID, WORD wCode)
{
	//'wCtrlID' = command specified from some control in the window
	//'wCode' = code for the command
	//RETURN:
	//		= TRUE if command was processed
	BOOL bProcessed = FALSE;

	switch(wCtrlID)
	{
		case IDOK:
		{
			if(OnOK())
			{
				//End our dialog window
				EndDialog(hDlg, wCtrlID);
			}
		}
		return TRUE;

		case IDCANCEL:
		{
			if(OnCancel())
			{
				//End our dialog window
				EndDialog(hDlg, wCtrlID);
			}
		}
		return TRUE;

		case IDAPPLY:
		{
			//Apply button was clicked
			OnApply();
		}
		return TRUE;

		case IDC_COMBO_SHOW_TYPE:
		{
			if(wCode == CBN_SELCHANGE)
			{
				//Selection changed
				UpdateWhenToShowCtrls();

				return TRUE;
			}
		}
		break;

		case IDC_CHECK_BLOCK_ENABLED:
		{
			if(wCode == BN_CLICKED)
			{
				//Update after checkbox click
				UpdateBlockEnableCtrls();
			}
		}
		break;

		case IDC_COMBO_SHOW_VAL1:
		{
			if (wCode == CBN_EDITCHANGE ||
				wCode == CBN_SELCHANGE)
			{
				//Update text of the control with days
				UpdateShowEveryHrsCtrlText(GetCurrentWhenToShow(), HRS_UNKNOWN);
			}
		}
		break;

	}

	return bProcessed;
}

BOOL CMainWnd::OnMenuCommand(WORD wCmd, BOOL bAccelerator)
{
	//'wCmd' = command specified from the menu
	//'bAccelerator' = TRUE if command came from accelerator
	//RETURN:
	//		= TRUE if command was processed
	BOOL bProcessed = FALSE;

	switch(wCmd)
	{
		case ID_FILE_OPEN_CONFIG_FILE:
		{
			OnMenuFileOpenConfig();
		}
		return TRUE;

		case ID_FILE_SAVE_INTO_CONFIG_FILE:
		{
			OnMenuFileSaveConfig();
		}
		return TRUE;

		case ID_FILE_EXIT:
		{
			//Close the app
			::PostMessage(hDlg, WM_CLOSE, 0, 0);
		}
		return TRUE;

		case ID_HELP_ABOUT:
		{
			//Show About dialog
			OnMenuHelpAbout();
		}
		return TRUE;

		case ID_HELP_ONLINEHELP:
		{
			//Help info
			OnHelpInfo();
		}
		return TRUE;

		case ID_HELP_CHECK_FOR_UPDATES:
		{
			//Check for updates
			OnCheckForUpdates();
		}
		return TRUE;

		case ID_HELP_LEARN_HOW_IT_WORKS:
		{
			//Show blog post
			OnShowBlogPost();
		}
		return TRUE;

		case ID_EDIT_SETDEFAULTS:
		{
			//Set defaults
			OnEditSetDefaults();
		}
		return TRUE;

		case ID_BUGREPORT_OPEN_EVENT_LOG:
		{
			//Open event log window
			OpenEventLog();
		}
		return TRUE;

		case ID_BUGREPORT_REPORT_BUG:
		{
			//Open www site to report bugs
			SubmitBugReport();
		}
		return TRUE;

		case ID_OPTIONS_REBOOT_WITHOUT_UPDATES:
		{
			//Reboot without installation of updates
			PowerOpNoUpdates(PWR_OP_REBOOT);
		}
		return TRUE;

		case ID_OPTIONS_SHUTDOWN_WITHOUT_UPDATES:
		{
			//Shut down without installation of updates
			PowerOpNoUpdates(PWR_OP_SHUTDOWN);
		}
		return TRUE;

		case ID_OPTIONS_FORCE_BSOD:
		{
			//Force a BSOD
			PowerOpNoUpdates(PWR_OP_BSOD);
		}
		return TRUE;

	}

	return bProcessed;
}



void CMainWnd::OnMenuHelpAbout()
{
	//Show About dialog
	if(::DialogBoxParam(this->_ghInstance, MAKEINTRESOURCE(IDD_ABOUTBOX), hDlg, _AboutDlgProc, (LPARAM)this) == -1)
	{
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(506);
		::MessageBeep(MB_ICONERROR);
	}
}


CMainWnd* CMainWnd::GetCMainWndFromHWND(HWND hWnd)
{
	//RETURN:
	//		= Pointer to CMainWnd for the main window, or
	//		= NULL if 'hWnd' is not the main window handle
	CMainWnd* pThis = (CMainWnd*)::GetWindowLongPtr(hWnd, DWLP_USER);
	return pThis;
}

// Message handler for about box.
INT_PTR CMainWnd::_AboutDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
	{
		//Initialization
		WCHAR buff[1024];

#ifdef _M_X64
#define APP_BITNESS L"64-bit"
#else
#define APP_BITNESS L"32-bit"
#endif

		//App name
		VERIFY(SUCCEEDED(::StringCchPrintf(buff, _countof(buff), L"%s", MAIN_APP_NAME)));
		::SetDlgItemText(hDlg, IDC_STATIC_APP_NAME, buff);

		//App version
		VERIFY(SUCCEEDED(::StringCchPrintf(buff, _countof(buff), L"v.%s (%s)", MAIN_APP_VER, APP_BITNESS)));
		::SetDlgItemText(hDlg, IDC_STATIC_APP_VER, buff);

		//Copyright year
		SYSTEMTIME st = {};
		::GetLocalTime(&st);
		VERIFY(SUCCEEDED(::StringCchPrintf(buff, _countof(buff), L"Copyright (c) %s%u", st.wYear > 2020 ? L"2020-" : L"", st.wYear)));
		::SetDlgItemText(hDlg, IDC_STATIC_COPYRIGHT, buff);

		//Author's URL
		::SetDlgItemText(hDlg, IDC_SYSLINK_DB, L"<a>dennisbabkin.com</a>");

        return (INT_PTR)TRUE;
	}

    case WM_COMMAND:
    if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
    {
        EndDialog(hDlg, LOWORD(wParam));
        return (INT_PTR)TRUE;
    }
    break;

	case WM_NOTIFY:
	{
		NMLINK* pNML = (NMLINK*)lParam;
		if (pNML->hdr.code == NM_CLICK)
		{
			//Link was clicked
			if (pNML->hdr.idFrom == IDC_SYSLINK_DB)
			{
				CMainWnd* pMainWnd = GetCMainWndFromHWND(::GetParent(hDlg));
				ASSERT(pMainWnd);

				//Open website
				pMainWnd->OpenWebPageWithErrorUI(URL_DENNISBABKIN);
			}
		}
	}
	break;

	}


    return (INT_PTR)FALSE;
}



void CMainWnd::OnCtrlColor(HDC hDC, HWND hWndCtrl, UINT nCtrlId, HBRUSH& hBrush)
{
	//Called to ask for control color
	//'hDC' = device control for painting in the control
	//'hWndCtrl' = control whose notification it is
	//'nCtrlId' = ID of the control whose notification it is
	//'hBrush' = background brush (can be updated here)

	switch(nCtrlId)
	{
		case IDC_STATIC_MSG1:
		{
			::SetTextColor(hDC, ::GetSysColor(COLOR_3DDKSHADOW));
		}
		break;
	}

}


UI_SHOW_TYPE CMainWnd::GetCurrentWhenToShow()
{
	//RETURN:
	//		= Currently selected "When to show" popup option, or
	//		= -1 if none
	UI_SHOW_TYPE res = (UI_SHOW_TYPE)-1;

	HWND hWndWhen2Show = ::GetDlgItem(hDlg, IDC_COMBO_SHOW_TYPE);
	ASSERT(hWndWhen2Show);

	int nIdx = (int)::SendMessage(hWndWhen2Show, CB_GETCURSEL, NULL, NULL);
	if(nIdx != CB_ERR)
	{
		INT_PTR nData = ::SendMessage(hWndWhen2Show, CB_GETITEMDATA, nIdx, NULL);
		if(nData >= 0 && nData < UI_SH_T_COUNT)
		{
			res = (UI_SHOW_TYPE)nData;
		}
	}

	return res;
}


UINT CMainWnd::_minToHrs(UINT nMin)
{
	UINT nHrs = nMin / 60;
	return (nMin % 60) ? nHrs + 1 : nHrs;
}

UI_SHOW_TYPE CMainWnd::GetWhenToShowSaveState(BOOL bInitial)
{
	//Get current selection
	UI_SHOW_TYPE selType = GetCurrentWhenToShow();

	if(!bInitial && 
		selType != UI_SH_T_SHOW_EVERY_N_MINS)
	{
		HWND hWndCmbShowVal1 = ::GetDlgItem(hDlg, IDC_COMBO_SHOW_VAL1);
		ASSERT(hWndCmbShowVal1);

		//Remember old value from minutes control
		WCHAR buff[128] = {};
		buff[0] = 0;
		::SendMessage(hWndCmbShowVal1, WM_GETTEXT, _countof(buff), (LPARAM)buff);
		buff[_countof(buff) - 1] = 0;

		_nCurVal1Hrs = _wtoi(buff);
	}

	return selType;
}


void CMainWnd::UpdateShowEveryHrsCtrlText(UI_SHOW_TYPE type, int nHrs)
{
	//'type' = value selected in the 'IDC_COMBO_SHOW_TYPE' control
	//'nHrs' = number or hrs, or 'HRS_UNKNOWN', or 'HRS_NONE'
	HWND hWndStMeasure = ::GetDlgItem(hDlg, IDC_STATIC_MEASURE_VAL1);
	ASSERT(hWndStMeasure);

	WCHAR buffStr[128];
	buffStr[0] = 0;

	if (type == UI_SH_T_SHOW_EVERY_N_MINS)
	{
		if (nHrs == HRS_UNKNOWN)
		{
			//Get currentl selected number of hours
			nHrs = GetCurrentShowEveryHrsFromCtrl();
			if (nHrs == HRS_UNKNOWN)
				nHrs = HRS_NONE;
		}

		if (nHrs != HRS_NONE &&
			nHrs > 24 &&
			nHrs <= MAX_ALLOWED_DONT_SHOW_POPUP_IN_MINS)
		{
			//Format it
			double fDays = nHrs / 24.0;
			VERIFY(SUCCEEDED(::StringCchPrintf(buffStr, _countof(buffStr), L"hrs. (%.1f days)", fDays)));
		}
		else
		{
			//Nor formatting needed
			VERIFY(SUCCEEDED(::StringCchCopy(buffStr, _countof(buffStr), L"hrs.")));
		}
	}
	else if (type == UI_SH_T_SHOW_ALWAYS)
	{
		//Show none
	}
	else
		ASSERT(NULL);

	::SendMessage(hWndStMeasure, WM_SETTEXT, NULL, (LPARAM)buffStr);
}

void CMainWnd::UpdateWhenToShowCtrls(BOOL bInitial)
{
	HWND hWndStName = ::GetDlgItem(hDlg, IDC_STATIC_NAME_VAL1);
	ASSERT(hWndStName);

	HWND hWndCmbShowVal1 = ::GetDlgItem(hDlg, IDC_COMBO_SHOW_VAL1);
	ASSERT(hWndCmbShowVal1);

	WCHAR buff[128] = {};

	//See if we're enabled
	BOOL bBlockEnabled = IsBlockEnabled();


	//Get current selection
	UI_SHOW_TYPE selType = GetWhenToShowSaveState(bInitial);

	int nCurSelHrs = HRS_NONE;


	static struct{
		UI_SHOW_TYPE type;
		LPCTSTR pStrName;
	}
	kstrType2Names[] = {
		{UI_SH_T_SHOW_EVERY_N_MINS,		L"Since last time it was shown:"}
	};

	BOOL bMatched = FALSE;

	for(int i = 0; i < _countof(kstrType2Names); i++)
	{
		if(kstrType2Names[i].type == selType)
		{
			//Set name & measure
			::SendMessage(hWndStName, WM_SETTEXT, NULL, (LPARAM)kstrType2Names[i].pStrName);

			nCurSelHrs = HRS_UNKNOWN;
			//::SendMessage(hWndStMeasure, WM_SETTEXT, NULL, (LPARAM)kstrType2Names[i].pStrMeasure);

			if(bBlockEnabled)
			{
				::EnableWindow(hWndCmbShowVal1, TRUE);
			}

			if(selType == UI_SH_T_SHOW_EVERY_N_MINS)
			{
				//Fill in minutes control
				::SendMessage(hWndCmbShowVal1, CB_RESETCONTENT, NULL, NULL);

				//Current selection
				if(_nCurVal1Hrs > 0 &&
					(_nCurVal1Hrs * 60) <= MAX_ALLOWED_DONT_SHOW_POPUP_IN_MINS)
				{
					::StringCchPrintf(buff, _countof(buff), L"%d", _nCurVal1Hrs);
					::SendMessage(hWndCmbShowVal1, WM_SETTEXT, NULL, (LPARAM)buff);
				}

				static struct{
					UINT nHrs;
				}
				kstrNumHrs[] = {
					1, 2, 3, 6, 12, 24, 48, 72, 96, 168
				};

				for(int i = 0; i < _countof(kstrNumHrs); i++)
				{
					::StringCchPrintf(buff, _countof(buff), L"%d", kstrNumHrs[i].nHrs);

					::SendMessage(hWndCmbShowVal1, CB_ADDSTRING, NULL, (LPARAM)buff);
				}

			}

			bMatched = TRUE;
			break;
		}
	}


	if(!bMatched)
	{
		//Disable all
		::SendMessage(hWndStName, WM_SETTEXT, NULL, (LPARAM)L"");
		//::SendMessage(hWndStMeasure, WM_SETTEXT, NULL, (LPARAM)L"");

		::SendMessage(hWndCmbShowVal1, WM_SETTEXT, NULL, (LPARAM)L"");
		::SendMessage(hWndCmbShowVal1, CB_RESETCONTENT, NULL, NULL);
		::EnableWindow(hWndCmbShowVal1, FALSE);
	}

	UpdateShowEveryHrsCtrlText(selType, nCurSelHrs);
}

BOOL CMainWnd::IsBlockEnabled()
{
	//RETURN:
	//		= TRUE if we're currently enabled to block (in UI)

	return ::IsDlgButtonChecked(hDlg, IDC_CHECK_BLOCK_ENABLED) == BST_CHECKED;
}

void CMainWnd::UpdateBlockEnableCtrls(BOOL bInitial)
{
	//See if we're enabled
	BOOL bEnabled = IsBlockEnabled();


	static UINT ctrlIDs[] = {
		IDC_COMBO_POPUP_TIMEOUT,
		IDC_CHECK_PLAY_WARN_SOUND,
		IDC_CHECK_IDLE_SLEEP,
		IDC_COMBO_SHOW_TYPE,
	};

	for(int i = 0; i < _countof(ctrlIDs); i++)
	{
		HWND hWndCtrl = ::GetDlgItem(hDlg, ctrlIDs[i]);
		ASSERT(hWndCtrl);

		::EnableWindow(hWndCtrl, bEnabled);
	}

	HWND hWndVal1 = ::GetDlgItem(hDlg, IDC_COMBO_SHOW_VAL1);
	ASSERT(hWndVal1);

	if(bEnabled)
	{
		//Get current selection
		UI_SHOW_TYPE selType = GetCurrentWhenToShow();

		::EnableWindow(hWndVal1, selType == UI_SH_T_SHOW_EVERY_N_MINS);
	}
	else
	{
		::EnableWindow(hWndVal1, FALSE);
	}

}


int CMainWnd::ShowMessageBox(LPCTSTR pStrMsg, UINT nType)
{
	//Show message box and return result
	//'nType' = type of message box to show:
	//				MB_ICONEXCLAMATION, MB_ICONINFORMATION, MB_ICONQUESTION, MB_ICONERROR
	//				MB_YESNOCANCEL, MB_YESNO, MB_OK
	//RETURN:
	//		= One of: IDOK, IDYES, IDNO, IDOK, IDCANCEL, etc.
	return ::MessageBox(hDlg, pStrMsg, MAIN_APP_NAME, nType);
}


void CMainWnd::OnEditSetDefaults()
{
	//Set defaults

	//Show user warning
	if(ShowMessageBox(L"Do you want to reset controls to their defaults?", MB_ICONQUESTION | MB_YESNOCANCEL) == IDYES)
	{
		//Get default settings
		APP_SETTINGS defs(FALSE);
		defs.setDefaults();

		SetCtrls(defs);
	}
}



void CMainWnd::SetCtrls(APP_SETTINGS& settings)
{
	//Set UI controls from 'settings'
	WCHAR buff[256];

	//Fill out initial controls
	::CheckDlgButton(hDlg, IDC_CHECK_BLOCK_ENABLED, settings.bBlockEnabled ? BST_CHECKED: BST_UNCHECKED);

	HWND hWndHidePopup = ::GetDlgItem(hDlg, IDC_COMBO_POPUP_TIMEOUT);
	ASSERT(hWndHidePopup);

	//Reset it
	::SendMessage(hWndHidePopup, CB_RESETCONTENT, NULL, NULL);

	//When to hide popup
	static struct{
		UINT nTimeoutMin;
		LPCTSTR pStrName;
	}
	kstrHideOptions[] = {
		//Sec				Message to user
		{0,					L"Never (keep it until user interacts with it)"},
		{(1 * 60),			L"After 1 minute"},
		{(5 * 60),			L"After 5 minutes"},
		{(10 * 60),			L"After 10 minutes"},
		{(30 * 60),			L"After 30 minutes"},
		{(1 * 60 * 60),		L"After 1 hour"},
		{(2 * 60 * 60),		L"After 2 hours"},
		{(3 * 60 * 60),		L"After 3 hours"},
		{(6 * 60 * 60),		L"After 6 hours"},
		{(12 * 60 * 60),	L"After 12 hours"},
		{(24 * 60 * 60),	L"After 24 hours"},
	};

	BOOL bHideOptSelected = FALSE;
	UINT nHideOptTOSec = settings.nUI_TimeOutSec;

	for(int i = 0; i < _countof(kstrHideOptions); i++)
	{
		int nIdx = (int)::SendMessage(hWndHidePopup, CB_ADDSTRING, NULL, (LPARAM)kstrHideOptions[i].pStrName);
		ASSERT(nIdx >= 0);
		VERIFY(::SendMessage(hWndHidePopup, CB_SETITEMDATA, nIdx, kstrHideOptions[i].nTimeoutMin) != CB_ERR);

		if(kstrHideOptions[i].nTimeoutMin == nHideOptTOSec)
		{
			//Select it
			::SendMessage(hWndHidePopup, CB_SETCURSEL, nIdx, NULL);
			bHideOptSelected = TRUE;
		}
	}

	if (!bHideOptSelected)
	{
		//Add custom value to the list
		if (nHideOptTOSec < 60)
		{
			VERIFY(SUCCEEDED(::StringCchPrintf(buff, _countof(buff), L"After %u second(s)", nHideOptTOSec)));
		}
		else if (nHideOptTOSec < (60 * 60))
		{
			int nMin = nHideOptTOSec / 60;
			int nSec = nHideOptTOSec % 60;

			VERIFY(SUCCEEDED(::StringCchPrintf(buff, _countof(buff), L"After %u min : %u sec", nMin, nSec)));
		}
		else if (nHideOptTOSec < (24 * 60 * 60))
		{
			int nHrs = nHideOptTOSec / (60 * 60);
			int nMinLeft = nHideOptTOSec - nHrs * (60 * 60);
			int nMin = nMinLeft / 60;
			int nSec = nMinLeft % 60;

			VERIFY(SUCCEEDED(::StringCchPrintf(buff, _countof(buff), L"After %u hr : %u min : %u sec", nHrs, nMin, nSec)));
		}
		else
		{
			double fHrs = nHideOptTOSec / (60.0 * 60.0);
			VERIFY(SUCCEEDED(::StringCchPrintf(buff, _countof(buff), L"After %.1f hr(s)", fHrs)));
		}

		//Set it to combo box
		int nIdx = (int)::SendMessage(hWndHidePopup, CB_ADDSTRING, NULL, (LPARAM)buff);
		ASSERT(nIdx >= 0);
		VERIFY(::SendMessage(hWndHidePopup, CB_SETITEMDATA, nIdx, nHideOptTOSec) != CB_ERR);
		::SendMessage(hWndHidePopup, CB_SETCURSEL, nIdx, NULL);
	}


	//Play warning sound
	::CheckDlgButton(hDlg, IDC_CHECK_PLAY_WARN_SOUND, settings.bUI_AllowSound ? BST_CHECKED: BST_UNCHECKED);

	//Allow idle timer
	::CheckDlgButton(hDlg, IDC_CHECK_IDLE_SLEEP, settings.bAllowSleep ? BST_CHECKED: BST_UNCHECKED);



	//Reset cache for the minutes control
	_nCurVal1Hrs = _minToHrs(settings.nUI_ShowVal1);

	HWND hWndWhen2Show = ::GetDlgItem(hDlg, IDC_COMBO_SHOW_TYPE);
	ASSERT(hWndWhen2Show);

	//Reset it
	::SendMessage(hWndWhen2Show, CB_RESETCONTENT, NULL, NULL);

	//When to show popup
	static struct{
		UI_SHOW_TYPE showType;
		LPCTSTR pStrName;
	}
	kstrWhen2Show[] = {
		//type								Message to user	
		{UI_SH_T_SHOW_ALWAYS,				L"Always show this popup",},
		{UI_SH_T_SHOW_EVERY_N_MINS,			L"Show this popup no sooner than:",},
	};

	for(int i = 0; i < _countof(kstrWhen2Show); i++)
	{
		int nIdx = (int)::SendMessage(hWndWhen2Show, CB_ADDSTRING, NULL, (LPARAM)kstrWhen2Show[i].pStrName);
		ASSERT(nIdx >= 0);
		VERIFY(::SendMessage(hWndWhen2Show, CB_SETITEMDATA, nIdx, kstrWhen2Show[i].showType) != CB_ERR);

		if(kstrWhen2Show[i].showType == settings.UI_ShowType)
		{
			//Select it
			::SendMessage(hWndWhen2Show, CB_SETCURSEL, nIdx, NULL);
		}

	}


	//Update controls
	UpdateWhenToShowCtrls(TRUE);
	UpdateBlockEnableCtrls(TRUE);
}



RES_YES_NO_ERR CMainWnd::IsElevationRequiredToSaveChanges()
{
	//RETURN:
	//		= RYNE_YES if we need to elevate our app to save changes
	//		= RYNE_NO if we don't need elevation
	//		= RYNE_ERROR if error determining (check GetLastError() for info)

	HKEY hKey;
	DWORD dwR = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_KEY_SFTWR, 0, KEY_READ | KEY_WRITE, &hKey);
	if(dwR == ERROR_SUCCESS)
	{
		ASSERT(hKey);
		VERIFY(::RegCloseKey(hKey) == ERROR_SUCCESS);

		return RYNE_NO;
	}
	else if(dwR == ERROR_ACCESS_DENIED)
	{
		//Need elevation
		return RYNE_YES;
	}

	//Failed
	::SetLastError(dwR);
	return RYNE_ERROR;
}


BOOL CMainWnd::GetComboBoxSelectedData(UINT nCtrlID, LRESULT* pOutData)
{
	//'pOutData' = if not NULL, receives selected item data
	//RETURN:
	//		= TRUE if retrieve selected data in 'pOutData'
	BOOL bRes = FALSE;
	LRESULT lData = 0;

	HWND hWndCtrl = ::GetDlgItem(hDlg, nCtrlID);
	ASSERT(hWndCtrl);

	INT_PTR nIdx = ::SendMessage(hWndCtrl, CB_GETCURSEL, NULL, NULL);
	if(nIdx != CB_ERR)
	{
		lData = ::SendMessage(hWndCtrl, CB_GETITEMDATA, nIdx, NULL);
		if(lData != CB_ERR)
		{
			bRes = TRUE;
		}
	}

	if(pOutData)
		*pOutData = lData;

	return bRes;
}

int CMainWnd::GetCurrentShowEveryHrsFromCtrl()
{
	//RETURN:
	//		= Number of hours selected, or
	//		= 0 if none, or
	//		= HRS_UNKNOWN if error

	HWND hWndCtrl = ::GetDlgItem(hDlg, IDC_COMBO_SHOW_VAL1);
	ASSERT(hWndCtrl);

	BOOL bTranslated = FALSE;
	UINT nVHrs = 0;

	WCHAR buff[128];
	buff[0] = 0;
	INT_PTR nCurSel = ::SendMessage(hWndCtrl, CB_GETCURSEL, 0, 0);
	if (nCurSel != CB_ERR)
	{
		UINT nchLn = (UINT)::SendMessage(hWndCtrl, CB_GETLBTEXTLEN, nCurSel, 0);
		if (nchLn == CB_ERR)
		{
			ASSERT(NULL);
			return HRS_UNKNOWN;
		}
		if (nchLn + 1 > _countof(buff))
		{
			ASSERT(NULL);
			return HRS_UNKNOWN;
		}

		if (::SendMessage(hWndCtrl, CB_GETLBTEXT, nCurSel, (LPARAM)buff) != CB_ERR)
		{
			nVHrs = _wtoi(buff);
			bTranslated = TRUE;
		}
	}

	if (!bTranslated)
	{
		//Use another method
		nVHrs = ::GetDlgItemInt(hDlg, IDC_COMBO_SHOW_VAL1, &bTranslated, TRUE);
	}

	if (bTranslated &&
		nVHrs >= 0 &&
		(nVHrs * 60) <= MAX_ALLOWED_DONT_SHOW_POPUP_IN_MINS)
	{
	}
	else
	{
		//Bad value
		nVHrs = HRS_UNKNOWN;
	}

	return nVHrs;
}

BOOL CMainWnd::CollectDataFromUI(APP_SETTINGS& outData)
{
	//Collect data from UI into 'outData'
	//INFO: Checks data for correctness and show UI errors if any
	//RETURN:
	//		= TRUE if data was collected and is valid
	BOOL bRes = TRUE;

	outData.bBlockEnabled = IsBlockEnabled();
	BOOL bOn = outData.bBlockEnabled;

	//Make default struct
	APP_SETTINGS asDefs(FALSE);
	asDefs.setDefaults();

	//When to hide popup
	LRESULT lData;
	if(GetComboBoxSelectedData(IDC_COMBO_POPUP_TIMEOUT, &lData))
	{
		outData.nUI_TimeOutSec = (int)lData;
	}
	else
	{
		//Nothing selected
		if (bOn)
		{
			ShowMessageBox(L"Select 'Hide popup' option", MB_ICONERROR);
			bRes = FALSE;
		}
		else
			outData.nUI_TimeOutSec = asDefs.nUI_TimeOutSec;
	}

	outData.bUI_AllowSound = IsDlgButtonChecked(hDlg, IDC_CHECK_PLAY_WARN_SOUND) == BST_CHECKED;
	outData.bAllowSleep = IsDlgButtonChecked(hDlg, IDC_CHECK_IDLE_SLEEP) == BST_CHECKED;

	//When to show
	if(GetComboBoxSelectedData(IDC_COMBO_SHOW_TYPE, &lData))
	{
		outData.UI_ShowType = (UI_SHOW_TYPE)lData;

		if(outData.UI_ShowType == UI_SH_T_SHOW_ALWAYS)
		{
			//Used cached minutes
			outData.nUI_ShowVal1 = _nCurVal1Hrs * 60;
		}
		else if(outData.UI_ShowType == UI_SH_T_SHOW_EVERY_N_MINS)
		{
			//Get hours as well
			UINT nVHrs = GetCurrentShowEveryHrsFromCtrl();
			if(nVHrs != HRS_UNKNOWN)
			{
				//Convert to minutes for storage
				outData.nUI_ShowVal1 = nVHrs * 60;
			}
			else
			{
				//Bad value
				if (bOn)
				{
					WCHAR buff[1024];
					::StringCchPrintf(buff, _countof(buff),
						L"Incorrect value of hours specified. It must be an integer between 0 and %u.",
						MAX_ALLOWED_DONT_SHOW_POPUP_IN_MINS / 60);

					ShowMessageBox(buff, MB_ICONERROR);
					bRes = FALSE;
				}
				else
					outData.nUI_ShowVal1 = asDefs.nUI_ShowVal1;
			}
		}
		else
		{
			//Error
			if (bOn)
			{
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(513, L"v=%d", outData.UI_ShowType);
				ASSERT(NULL);

				ShowMessageBox(L"Incorrect selection in 'when to show popup'", MB_ICONERROR);
				bRes = FALSE;
			}
			else
			{
				//Fallback
				outData.UI_ShowType = asDefs.UI_ShowType;
				outData.nUI_ShowVal1 = asDefs.nUI_ShowVal1;
			}
		}
	}
	else
	{
		//Nothing selected
		if (bOn)
		{
			ShowMessageBox(L"Select option when to show popup", MB_ICONERROR);
			bRes = FALSE;
		}
		else
		{
			//Fallback
			outData.UI_ShowType = asDefs.UI_ShowType;
			outData.nUI_ShowVal1 = asDefs.nUI_ShowVal1;
		}
	}


	return bRes;
}



BOOL CMainWnd::OnOK()
{
	//OK'ing this window
	//RETURN:
	//		= TRUE to allow it
	BOOL bResAllow = SaveDataFromUI(TRUE);

	return bResAllow;
}


void CMainWnd::OnApply()
{
	//Applying this window
	SaveDataFromUI(FALSE);

}


BOOL CMainWnd::OnCancel()
{
	//Canceling this window
	//RETURN:
	//		= TRUE to allow it
	BOOL bResAllow = TRUE;

	//Signal event thread to close
	ASSERT(_hEventStop);
	if (_hEventStop)
	{
		if (!::SetEvent(_hEventStop))
		{
			//Error
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(609);
			ASSERT(NULL);
		}
	}


	return bResAllow;
}


void CMainWnd::ShowFailedToSaveDataUI(int nSpecErr)
{
	//Show dialog if a call to SaveData() fails
	int nOSError = ::GetLastError();
	EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(nSpecErr, L"Failed to save data");

	WCHAR buffMsg[1024];
	WCHAR buff[1224];
	::StringCchPrintf(buff, _countof(buff), L"ERROR: (0x%X) Failed to save data.\n\n%s", 
		nOSError, AUX_FUNCS::getFormattedErrorMsg(nOSError, buffMsg, _countof(buffMsg)));

	//Show user message
	ShowMessageBox(buff, MB_ICONERROR);
}



BOOL CMainWnd::SaveDataFromUI(BOOL bCloseWhenSaved)
{
	//RETURN:
	//		= TRUE to allow to close
	//		= FALSE to prevent closing
	BOOL bAllowToClose = TRUE;

	//Set wait cursor
	SHOW_WAIT_CURSOR waitCursor;

	//Collect data
	APP_SETTINGS stgs;
	if(!CollectDataFromUI(stgs))
	{
		//Can't continue
		return FALSE;
	}

	//Can we save it here?
	if(gReqAdmin == RYNE_NO)
	{
		//Save data
		if(!SaveData(stgs))
		{
			//Failed to save
			ShowFailedToSaveDataUI(514);

			return FALSE;
		}
	}
	else
	{
		//Need to request elevation
		int nOSError = -1;
		BOOL bShowUserErrorMsg = TRUE;

		//Do not close (at this point)
		bAllowToClose = FALSE;

		SAVED_DATA svDta;
		svDta.saveOp = bCloseWhenSaved ? SV_O_OK : SV_O_APPLY;
		svDta.Sttgs = stgs;

		//Convert to byte array
		size_t szcbData;
		void* pData = svDta.toBytes(&szcbData);
		if(pData)
		{
			//Convert to hex string
			size_t szchHexStrLen = szcbData * 2 + 1;
			WCHAR* pHexStr = new (std::nothrow) WCHAR[szchHexStrLen];
			if(pHexStr)
			{
				BYTE by, byL;
				WCHAR* pD = pHexStr;

				//Add hex values for serialized data for saving
				for(size_t i = 0; i < szcbData; i++)
				{
					by = *((BYTE*)pData + i);

					byL = by >> 4;
					*pD = byL < 0xA ? '0' + byL : 'a' + byL - 0xA;
					pD++;

					byL = by & 0xF;
					*pD = byL < 0xA ? '0' + byL : 'a' + byL - 0xA;
					pD++;
				}

				//Final null
				*pD = 0;
				pD++;

				ASSERT(pD - pHexStr == szchHexStrLen);



				//Get self path
				WCHAR buffThis[MAX_PATH] = {};
				::GetModuleFileName(NULL, buffThis, _countof(buffThis));
				buffThis[_countof(buffThis) - 1] = 0;

				//Make unique event name
				WCHAR buffEvent[128] = {};
				FILETIME ftUtc = {};
				::GetSystemTimeAsFileTime(&ftUtc);
				::StringCchPrintf(buffEvent, _countof(buffEvent), 
					L"%08x%08x%08x%08x"
					,
					::GetCurrentProcessId(),
					::GetCurrentThreadId(),
					ftUtc.dwHighDateTime,
					ftUtc.dwLowDateTime
					);

				//Get monitor where our window is now (so that we can show our new elevated window in the same monotor)
				HMONITOR hMonitor = ::MonitorFromWindow(hDlg, MONITOR_DEFAULTTONEAREST);

				WCHAR buffMonH[32] = {};
				ASSERT(sizeof(hMonitor) == sizeof(void*));
				::StringCchPrintf(buffMonH, _countof(buffMonH),
#ifdef _M_X64
					L"%016Ix"
#else
					L"%08Ix"
#endif
					,
					hMonitor);


				//Make command line
				size_t szchCmdLn = TSIZEOF(CMD_PARAM_RUN L" ") + szchHexStrLen + TSIZEOF(L" ") + wcslen(buffEvent) + TSIZEOF(L" ") + wcslen(buffMonH);
				WCHAR* pCmdLine = new (std::nothrow) WCHAR[szchCmdLn + 1];
				if(pCmdLine)
				{
					//Compose command line
					HRESULT hr = ::StringCchPrintf(pCmdLine, szchCmdLn, 
						L"%s %s %s %s"
						,
						CMD_PARAM_RUN,
						pHexStr,
						buffEvent,
						buffMonH
						);

					if(hr == S_OK)
					{
						//Create an event
						HANDLE hEvent = ::CreateEvent(NULL, TRUE, FALSE, buffEvent);
						if(hEvent)
						{

							//Init COM
							BOOL bComInitted = SUCCEEDED(::CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE));

							//Prep the struct
							SHELLEXECUTEINFO sei = {0};
							sei.cbSize = sizeof(sei);
							sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_UNICODE /*| SEE_MASK_HMONITOR*/;
							sei.hwnd = NULL;
							sei.lpVerb = L"runas";			//Request elevation
							sei.lpFile = buffThis;
							sei.lpParameters = pCmdLine;
							sei.nShow = SW_SHOW;

							////Get monitor where our window is
							//sei.hMonitor = hMonitor;					//Can't use it here because of the bug in Windows that somehow always wants to use primary monitor :(


							//Run the app
							if(::ShellExecuteEx(&sei))
							{
								//Started evelated
								SHOW_WAIT_CURSOR waitCursor2;

								//Wait for our event
								//INFO: It will be signaled by the child process that we just started, if it got our data
								DWORD dwRw = ::WaitForSingleObject(hEvent, 3 * 1000);

								if(dwRw == WAIT_OBJECT_0)
								{
									//Started OK

									//We can now close self
									if(::PostMessage(hDlg, WM_CLOSE, 0, 0))
									{
										//And don't show an error message
										bShowUserErrorMsg = FALSE;
										bAllowToClose = FALSE;
									}
									else
									{
										//Error
										nOSError = ::GetLastError();
										EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(522, L"exe=\"%s\", cmd=\"%s\"", buffThis, pCmdLine);
										ASSERT(NULL);
									}
								}
								else if(dwRw == WAIT_TIMEOUT)
								{
									//Timed out
									nOSError = ERROR_TIMEOUT;
									EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(521, L"exe=\"%s\", cmd=\"%s\"", buffThis, pCmdLine);
								}
								else
								{
									//Error
									nOSError = ::GetLastError();
									EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(520, L"exe=\"%s\", cmd=\"%s\"", buffThis, pCmdLine);
									ASSERT(NULL);
								}

							}
							else
							{
								//See why we failed
								nOSError = ::GetLastError();

								if(nOSError == ERROR_CANCELLED)
								{
									//User cancel UAC prompt
									bShowUserErrorMsg = FALSE;
								}
								else
								{
									//Some error
									EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(517, L"exe=\"%s\", cmd=\"%s\"", buffThis, pCmdLine);
									ASSERT(NULL);
								}
							}


							//Close handles
							if(sei.hProcess)
							{
								VERIFY(::CloseHandle(sei.hProcess));
								sei.hProcess = NULL;
							}

							VERIFY(::CloseHandle(hEvent));
							hEvent = NULL;

							//Uninit COM
							if(bComInitted)
								::CoUninitialize();
						}
						else
						{
							//Error
							nOSError = ::GetLastError();
							EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(519, L"nm=%s", buffEvent);
							ASSERT(NULL);
						}
					}
					else
					{
						//Failed to make cmd line
						nOSError = (int)hr;
						::SetLastError(nOSError);
						EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(518, L"sz=%Iu", szchCmdLn);
						ASSERT(NULL);
					}


					//Free mem
					delete[] pCmdLine;
					pCmdLine = NULL;
				}
				else
				{
					//Error
					nOSError = ERROR_OUTOFMEMORY;
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(518, L"sz=%Iu", szchCmdLn);
					ASSERT(NULL);
				}


				//Free mem
				delete[] pHexStr;
				pHexStr = NULL;
			}
			else
			{
				//Error
				nOSError = ERROR_OUTOFMEMORY;
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(516);
				ASSERT(NULL);
			}


			//Free mem
			delete[] pData;
			pData = NULL;
		}
		else
		{
			//Error
			nOSError = ::GetLastError();
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(515);
			ASSERT(NULL);
		}


		if(bShowUserErrorMsg)
		{
			//Show user error message
			WCHAR buffMsg[1024];
			WCHAR buff[1224];
			::StringCchPrintf(buff, _countof(buff), L"ERROR: (0x%X) Failed to request elevation to save data.\n\n%s", 
				nOSError, AUX_FUNCS::getFormattedErrorMsg(nOSError, buffMsg, _countof(buffMsg)));

			//Show user message
			ShowMessageBox(buff, MB_ICONERROR);
		}
	}


	return bAllowToClose;
}

CMD_LINE_PARSE_RESULTS CMainWnd::ParseCommandLine()
{
	//Parse command line parameters that were passed into the app
	//RETURN:
	//		= Bitwise result of parsing command line
	CMD_LINE_PARSE_RESULTS res = CLPR_None;

	//Check for special command line parameters that can be passed by SaveDataFromUI()
	if(__argc == 5)
	{
		int p = 1;

		//Ex: r 02000000010000002c01000001000000000000000100000003000000 0000ea700000f56001d67f58b47f3b04 0000000000010007
		if(_wcsicmp(__wargv[p++], CMD_PARAM_RUN) == 0)
		{
			//Convert hex string into binary
			LPCTSTR pStrHex = __wargv[p++];
			size_t szchLnHex = wcslen(pStrHex);
			if((szchLnHex % 2) == 0)
			{
				BYTE* pData = new (std::nothrow) BYTE[szchLnHex / 2];
				if(pData)
				{
					BOOL bParsedOK = TRUE;
					BYTE* pD = pData;
					BYTE by;

					for(size_t i = 0; i < szchLnHex; i++)
					{
						WCHAR c = pStrHex[i];

						if(c >= '0' && c <= '9')
							by = c - '0';
						else if(c >= 'a' && c <= 'f')
							by = c - 'a' + 10;
						else if(c >= 'A' && c <= 'F')
							by = c - 'A' + 10;
						else
						{
							//Bad char
							EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(525, L"c=%c, i=%Iu, cmd: %s", c, i, ::GetCommandLineW());
							ASSERT(NULL);

							bParsedOK = FALSE;
							break;
						}

						if(!(i & 1))
						{
							*pD = by << 4;
						}
						else
						{
							*pD |= by;
							pD++;
						}
					}

					if(bParsedOK)
					{
						ASSERT(pD - pData == szchLnHex / 2);

						//Deserialize data back
						if(g_CmdSvData.fromBytes(pData, szchLnHex / 2))
						{
							//Finally get the event name
							LPCTSTR pStrEventName = __wargv[p++];

							if(pStrEventName &&
								pStrEventName[0])
							{
								//Open such event (it must have been created by us earlier)
								HANDLE hEvent = ::OpenEvent(EVENT_MODIFY_STATE, FALSE, pStrEventName);
								if(hEvent)
								{
									//And set it to signal the waiting "Self" that we got the data
									if(::SetEvent(hEvent))
									{
										//Finally get the monitor handle
										LPCTSTR pStrMonH = __wargv[p++];
										size_t nMonH = 0;
										if(swscanf_s(pStrMonH, L"%Ix", &nMonH) == 1)
										{
											_ghCmdMonitor = (HMONITOR)nMonH;
										}
										else
										{
											//Failed to scan it -- but not a crtitical error
											EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(534, L"cmd: %s", ::GetCommandLineW());
											ASSERT(NULL);
										}

										//Good, now we're done
										(UINT&)res |= CLPR_AUTO_SAVE_ELEVATED;
									}
									else
									{
										//Couldn't set the event
										EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(529, L"cmd: %s", ::GetCommandLineW());
										ASSERT(NULL);
									}

									//Close event
									VERIFY(::CloseHandle(hEvent));
									hEvent = NULL;
								}
								else
								{
									//Couldn't open the event by name
									EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(528, L"nm=\"%s\", cmd: %s", pStrEventName, ::GetCommandLineW());
									ASSERT(NULL);
								}
							}
							else
							{
								//Bad name
								EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(527, L"cmd: %s", ::GetCommandLineW());
								ASSERT(NULL);
							}
						}
						else
						{
							//Failed to deserialize
							EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(526, L"cmd: %s", ::GetCommandLineW());
							ASSERT(NULL);
						}
					}


					//Free mem
					delete[] pData;
					pData = NULL;
				}
				else
				{
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(524, L"cmd: %s", ::GetCommandLineW());
					ASSERT(NULL);
				}
			}
			else
			{
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(523, L"cmd: %s", ::GetCommandLineW());
				ASSERT(NULL);
			}


			//Did we succeed?
			if(!(res & CLPR_AUTO_SAVE_ELEVATED))
			{
				//Play error sound
				::MessageBeep(MB_ICONERROR);
			}
		}
	}
	else if (__argc == 2)
	{
		//See if we were passed a file in a command line argument
		//INFO: Like if a user dragged it into the icon of our program in the Windows Explorer
		LPCTSTR pStrFilePath = __wargv[1];

		if (AUX_FUNCS::IsFileByFilePath(pStrFilePath))
		{
			//Set it to import later when the app loads up
			gstrOpenCfgFilePath = pStrFilePath;
		}
		else
		{
			//Not a file, notify the user by playing an error sound
			::MessageBeep(MB_ICONERROR);
		}
	}

	return res;
}


BOOL CMainWnd::SaveData(APP_SETTINGS& data)
{
	//Save 'data' in registry
	//RETURN:
	//		= TRUE if success
	//		= FALSE if error (check GetLastError() for info)
	BOOL bRes = TRUE;
	int nOSError = 0;

	if(!AUX_FUNCS::WriteSettingsInt32(REG_VAL_NAME__BLOCK_ENABLED, data.bBlockEnabled))
	{
		nOSError = ::GetLastError();
		bRes = FALSE;
	}

	if(!AUX_FUNCS::WriteSettingsInt32(REG_VAL_NAME__UI_TIMEOUT_SEC, data.nUI_TimeOutSec))
	{
		nOSError = ::GetLastError();
		bRes = FALSE;
	}

	if(!AUX_FUNCS::WriteSettingsInt32(REG_VAL_NAME__UI_ALLOW_SOUND, data.bUI_AllowSound))
	{
		nOSError = ::GetLastError();
		bRes = FALSE;
	}

	if(!AUX_FUNCS::WriteSettingsInt32(REG_VAL_NAME__UI_ALLOW_SLEEP, data.bAllowSleep))
	{
		nOSError = ::GetLastError();
		bRes = FALSE;
	}

	if(!AUX_FUNCS::WriteSettingsInt32(REG_VAL_NAME__UI_SHOW_TYPE, data.UI_ShowType))
	{
		nOSError = ::GetLastError();
		bRes = FALSE;
	}

	if(!AUX_FUNCS::WriteSettingsInt32(REG_VAL_NAME__UI_SHOW_VAL_1, data.nUI_ShowVal1))
	{
		nOSError = ::GetLastError();
		bRes = FALSE;
	}


	//Create shared key
	if(!AUX_FUNCS::CreateHKLMSharedKey())
	{
		nOSError = ::GetLastError();
		bRes = FALSE;
	}


	::SetLastError(nOSError);
	return bRes;
}


int CMainWnd::ShellExecuteWithMonitor(HWND hWnd, LPCTSTR lpOperation, LPCTSTR lpFile, LPCTSTR lpParameters, LPCTSTR lpDirectory, INT nShowCmd, HWND hWndToUseForMonitor, ULONG uiFlags, HANDLE* phOutProcess)
{
	//Same as ShellExecute, except that it runs in the same monitor as the one where this app started from
	//'hWndToUseForMonitor' = if not NULL, must specify the window to use to detect the monitor that it's in to pass to the program that is being started
	//						  if NULL, the monitor that the app was started from will be used
	//'uiFlags' = flags for ShellExecuteEx call, such as: SEE_MASK_FLAG_NO_UI or SEE_MASK_NO_CONSOLE or SEE_MASK_WAITFORINPUTIDLE, etc.
	//'phOutProcess' = if not NULL, may receive process handle. (Info: It must be closed with CloseHandle() function if handle is not NULL!)
	//RETURN:
	//		0 - if success
	//		Otherwise error -- also sets GetLastError()
	int nOSError = NO_ERROR;

	//Prep the struct
	SHELLEXECUTEINFO sei = {0};
	sei.cbSize = sizeof(sei);
	sei.fMask = uiFlags & ~(SEE_MASK_HMONITOR | SEE_MASK_NOCLOSEPROCESS);
	sei.hwnd = hWnd;
	sei.lpVerb = lpOperation;
	sei.lpFile = lpFile;
	sei.lpParameters = lpParameters;
	sei.lpDirectory = lpDirectory;
	sei.nShow = nShowCmd;

	if(hWndToUseForMonitor)
	{
		//Get current monitor
		HMONITOR hMonMainWnd = ::MonitorFromWindow(hWndToUseForMonitor, MONITOR_DEFAULTTONULL);
		if(hMonMainWnd)
		{
			//We have a monitor handle
			sei.fMask |= SEE_MASK_HMONITOR;
			sei.hMonitor = hMonMainWnd;
		}
	}

	if(phOutProcess)
	{
		//Add flag
		sei.fMask |= SEE_MASK_NOCLOSEPROCESS;
	}


	//Init COM
	BOOL bComInitted = SUCCEEDED(::CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE));

	//Run it
	if(::ShellExecuteEx(&sei))
	{
		//Done
	}
	else
	{
		//Error
		nOSError = AUX_FUNCS::GetLastErrorNotNULL(ERROR_GEN_FAILURE);
	}

	//Uninit COM
	if(bComInitted)
	{
		::CoUninitialize();
	}

	if(phOutProcess)
		*phOutProcess = sei.hProcess;

	::SetLastError(nOSError);
	return nOSError;
}


BOOL CMainWnd::OpenWebPage(LPCTSTR pStrURI)
{
	//'pStrURI' = http(s) or local page to open
	//RETURN:
	//		= TRUE if success
	//		= FALSE if error (check GetLastError() for info)
	BOOL bRes = FALSE;

	if(!pStrURI || !pStrURI[0])
	{
		//Nothing to open
		::SetLastError(ERROR_EMPTY);
		return FALSE;
	}

	#pragma warning(push)	//Disable compiler warning when casting from HINSTANCE to int
	#pragma warning(disable: 4311)
	int nRet = (int)(size_t)ShellExecute(hDlg, L"open", pStrURI ? pStrURI : L"", NULL, NULL, SW_SHOWNORMAL);
	#pragma warning(pop)	// C4312
	if(nRet > 32)
		bRes = TRUE;

	::SetLastError(nRet);
	return bRes;
}

BOOL CMainWnd::OpenWebPageWithErrorUI(LPCTSTR pStrURI)
{
	//Save as OpenWebPage() but will show a user error message if opening fails
	//RETURN:
	//		= TRUE if success
	//		= FALSE if error (check GetLastError() for info)

	if(OpenWebPage(pStrURI))
	{
		return TRUE;
	}

	//Show user error
	int nOSError = ::GetLastError();
	EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(536, L"%s", pStrURI);

	//Format error message
	WCHAR buffMsg[1024];
	AUX_FUNCS::getFormattedErrorMsg(nOSError, buffMsg, _countof(buffMsg));

	//Rough estimate
	size_t szchLnBuff = wcslen(buffMsg) + (pStrURI ? wcslen(pStrURI) : 0) + 256;

	WCHAR* p_buff = new (std::nothrow) WCHAR[szchLnBuff];
	if(p_buff)
	{
		p_buff[0] = 0;
		VERIFY(::StringCchPrintf(p_buff, szchLnBuff, L"ERROR: (0x%X) Failed to open the following page:\n\n%s\n\n%s"
			, 
			nOSError, 
			pStrURI ? pStrURI : L"<null>",
			buffMsg) == S_OK);

		p_buff[szchLnBuff - 1] = 0;		//Safety null

		//Show it to the user
		ShowMessageBox(p_buff, MB_ICONERROR);

		//Free mem
		delete[] p_buff;
		p_buff = NULL;
	}
	else
	{
		//Failed?
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(537, L"sz=%Iu", szchLnBuff);
		ASSERT(NULL);
		::MessageBeep(MB_ICONERROR);
	}

	::SetLastError(nOSError);
	return FALSE;
}




WCHAR* CMainWnd::UrlEncode(LPCTSTR pStrUrl)
{
	//Encode UrlEncoded URL
	//INFO: Example of encoded URL: "res://C:\\Documents%20and%20Settings\\Administrator\\Desktop\\WinApiSearch64.exe"
	//'pStrUrl' = URL to encode (can be NULL, or "")
	//RETURN:
	//		= Encoded URL -- must be removed with delete[]!
	//		= NULL if error (check GetLastError() for info)
	BOOL bRes = FALSE;
	int nOSError = 0;

	WCHAR* p_strEncodedUrl = NULL;

	if(pStrUrl &&
		pStrUrl[0])
	{
		//Pick escaping flags
		DWORD dwEscFlags = URL_ESCAPE_PERCENT | URL_ESCAPE_AS_UTF8;

		//See how much data do we need
		WCHAR dummy;
		DWORD dwchLn = 1;
		HRESULT hr = ::UrlEscape((LPWSTR)pStrUrl, &dummy, &dwchLn, dwEscFlags);
		if(hr == E_POINTER)
		{
			if(dwchLn != 0)
			{
				//Reserve mem
				WCHAR* pBuff = new (std::nothrow) WCHAR[dwchLn + 1];
				if(pBuff)
				{
					//And now escape
					DWORD dwchLn2 = dwchLn;
					if(SUCCEEDED(hr = ::UrlEscape((LPWSTR)pStrUrl, pBuff, &dwchLn2, dwEscFlags)))
					{
						if(dwchLn2 + 1 == dwchLn &&
							dwchLn2 != 0)
						{
							//Done
							p_strEncodedUrl = pBuff;
						}
						else
						{
							//Bad length
							ASSERT(NULL);
							nOSError = ERROR_BAD_LENGTH;

							delete[] pBuff;
							pBuff = NULL;
						}
					}
					else
					{
						//Failed
						nOSError = (int)hr;

						delete[] pBuff;
						pBuff = NULL;
					}
				}
				else
					nOSError = ERROR_OUTOFMEMORY;
			}
			else
			{
				ASSERT(NULL);
				nOSError = ERROR_BAD_ARGUMENTS;
			}
		}
		else
		{
			//Unexpected error
			nOSError = (int)hr;
			ASSERT(NULL);
		}
	}
	else
	{
		//Empty string
		p_strEncodedUrl = new (std::nothrow) WCHAR[1];
		if(p_strEncodedUrl)
		{
			p_strEncodedUrl[0] = 0;
		}
		else
			nOSError = ERROR_OUTOFMEMORY;
	}

	::SetLastError(nOSError);
	return p_strEncodedUrl;
}





BOOL CMainWnd::OpenEventLog()
{
	//Open Windows Event Log
	//RETURN:
	//		= TRUE if success
	//		= FALSE if error (check GetLastError() for info)

	//Get system path
	TCHAR buffPath[MAX_PATH * 2];
	buffPath[0] = 0;
	::GetSystemDirectory(buffPath, _countof(buffPath));
	buffPath[_countof(buffPath) - 1] = 0;

	//Path to oepn
	VERIFY(AUX_FUNCS::MakeFolderPathEndWithSlash_Buff(buffPath, _countof(buffPath), TRUE));
	VERIFY(::StringCchCat(buffPath, _countof(buffPath), L"eventvwr.exe") == S_OK);

	//Open it
	int nOSError = ShellExecuteWithMonitor(hDlg, 
		L"open",
		buffPath,
		L"/c:Application",
		NULL,
		SW_SHOW,
		hDlg);
	if(nOSError == NO_ERROR)
	{
		return TRUE;
	}

	//Show user error
	EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(535, L"h=%p, path: %s", hDlg, buffPath);

	WCHAR buffMsg[1024];
	WCHAR buff[1224];
	::StringCchPrintf(buff, _countof(buff), L"ERROR: (0x%X) Failed to show Windows Event Log.\n\n%s", 
		nOSError, AUX_FUNCS::getFormattedErrorMsg(nOSError, buffMsg, _countof(buffMsg)));

	ShowMessageBox(buff, MB_ICONERROR);

	::SetLastError(nOSError);
	return FALSE;
}


BOOL CMainWnd::SubmitBugReport()
{
	//Open web page to allow user to submit bug report
	//RETURN:
	//		= TRUE if success
	//		= FALSE if error (check GetLastError() for info)

	std::wstring strDesc;

	//Get system info (except disk info)
	SysInfo::SYS_INFO_COLLECTOR::GetBriefSystemInfo(strDesc, SysInfo::CSI_MASK_ALL_EXCEPT_DISK);

	//Get app version and its bitness
	WCHAR buffVer[256] = {};
	::StringCchPrintf(buffVer, _countof(buffVer), L"%s, %d-bit", 
		MAIN_APP_VER,
#ifdef _M_X64
		64
#else
		32
#endif
		);

	//App name, version & system description
	LPCTSTR pAppNameEncoded = UrlEncode(MAIN_APP_NAME);
	LPCTSTR pAppVerEncoded = UrlEncode(buffVer);
	LPCTSTR pDescEncoded = UrlEncode(strDesc.c_str());
	ASSERT(pAppNameEncoded);
	ASSERT(pAppVerEncoded);
	ASSERT(pDescEncoded);

	//Make URL
	WCHAR buffUrl[1024] = {};
	VERIFY(::StringCchPrintf(buffUrl, _countof(buffUrl),
		//name version description
		URL_SUBMIT_BUG_REPORT
		,
		pAppNameEncoded,
		pAppVerEncoded,
		pDescEncoded
		) == S_OK);

	buffUrl[_countof(buffUrl) - 1] = 0;

	//Free mem
	delete[] pAppNameEncoded;
	delete[] pAppVerEncoded;
	delete[] pDescEncoded;

	return OpenWebPageWithErrorUI(buffUrl);
}


void CMainWnd::OnHelpInfo()
{
	//Show online help info

	LPCTSTR pAppVerEncoded = UrlEncode(MAIN_APP_VER);

	//Make URL
	WCHAR buffUrl[1024] = {};
	VERIFY(::StringCchPrintf(buffUrl, _countof(buffUrl),
		//version
		URL_ONLINE_HELP
		,
		pAppVerEncoded
		) == S_OK);

	buffUrl[_countof(buffUrl) - 1] = 0;

	//Free mem
	delete[] pAppVerEncoded;

	OpenWebPageWithErrorUI(buffUrl);
}



void CMainWnd::OnCheckForUpdates()
{
	//Show online page to check for an update

	LPCTSTR pAppVerEncoded = UrlEncode(MAIN_APP_VER);

	//Make URL
	WCHAR buffUrl[1024] = {};
	VERIFY(::StringCchPrintf(buffUrl, _countof(buffUrl),
		//version
		URL_CHECK_UPDATES
		,
		pAppVerEncoded
		) == S_OK);

	buffUrl[_countof(buffUrl) - 1] = 0;

	//Free mem
	delete[] pAppVerEncoded;

	OpenWebPageWithErrorUI(buffUrl);
}


void CMainWnd::OnShowBlogPost()
{
	//Open blog post with descriptions of the research that went into making this app

	OpenWebPageWithErrorUI(URL_BLOG_POST);
}


RES_YES_NO_ERR CMainWnd::IsShellChromeAPI_Installed(BOOL bShowErrorUI)
{
	//'bShowErrorUI' = TRUE to show error message UI in case it is not installed or if there's an error
	//RETURN:
	///	RYNE_YES = if our ShellChromeAPI.dll is in the system folder
	//	RYNE_NO  = if no, it is not
	//	RYNE_ERROR = if error (check GetLastError() for info)
	RES_YES_NO_ERR res = RYNE_ERROR;
	int nOSError = 0;

	HMODULE hMod = ::LoadLibraryEx(VULN_SHELL_DLL_FILE_NAME, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (hMod)
	{
		UINT(WINAPI* pfnTestCorrectDll)(int) = NULL;
		(FARPROC&)pfnTestCorrectDll = ::GetProcAddress(hMod, "TestCorrectDll");
		if (pfnTestCorrectDll)
		{
			if (pfnTestCorrectDll(NULL) == SHELL_CHROME_API_ID_STAMP)
			{
				//Got it
				res = RYNE_YES;
			}
			else
			{
				//Wrong version
				nOSError = 1828;
			}
		}
		else
		{
			//Bad library
			nOSError = 1756;
		}

		::FreeLibrary(hMod);
	}
	else
	{
		nOSError = ::GetLastError();
		if (nOSError == ERROR_MOD_NOT_FOUND)
			res = RYNE_NO;
	}

	if (bShowErrorUI)
	{
		if (res != RYNE_YES)
		{
			//Need to show error message
			WCHAR buff[1024];
			WCHAR buffMsg[1024];
			VERIFY(::StringCchPrintf(buff, _countof(buff), L"ERROR: %s\n\n(%u) %s"
				, 
				res == RYNE_NO ? L"[538] Required component was not found. Please reinstall the application." : 
				L"[539] Failed to load required component. Reinstalling the application may solve this issue:",
				nOSError,
				AUX_FUNCS::getFormattedErrorMsg(nOSError, buffMsg, _countof(buffMsg))
			) == S_OK);

			::SetLastError(nOSError);
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(540, L"res=%d", res);
			ShowMessageBox(buff, MB_ICONERROR);
		}
	}

	::SetLastError(nOSError);
	return res;
}

BOOL CMainWnd::_enumProcCloseAll(HWND hWnd, LPARAM lParam)
{
	//Close window if it's not our main
	HWND hWndThis = (HWND)lParam;
	if (hWnd != hWndThis)
	{
		//Make sure it's a dialog window
		TCHAR buff[MAX_PATH];
		if (::GetClassName(hWnd, buff, MAX_PATH))
		{
			//Check that it's a dialog class
			if (lstrcmp(buff, L"#32770") == 0)
			{
				//See if certain buttons are present, and if yes, then close it by sending those button click messages
				if (::GetDlgItem(hWnd, IDCANCEL))
				{
					::SendMessage(hWnd, WM_CLOSE, 0, 0);
				}
				else if (::GetDlgItem(hWnd, IDNO))
				{
					::SendMessage(hWnd, WM_COMMAND, MAKELONG(IDNO, BN_CLICKED), 0);
				}
				else if (::GetDlgItem(hWnd, IDOK))
				{
					::SendMessage(hWnd, WM_COMMAND, MAKELONG(IDOK, BN_CLICKED), 0);
				}
				else
				{
					//Fallback method
					::SendMessage(hWnd, WM_CLOSE, 0, 0);
				}
			}
		}
	}

	return TRUE;
}

BOOL CMainWnd::CloseAllWindowsExceptMainWnd()
{
	//Closes all open windows that were opened by this process, except the main window
	//RETURN:
	//		= TRUE if no errors
	BOOL bRes = FALSE;

	//Enumerate all threads in this process
	HANDLE hEnum = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hEnum != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te32 = { 0 };
		te32.dwSize = sizeof(te32);
		if (Thread32First(hEnum, &te32))
		{
			DWORD nProcID = ::GetCurrentProcessId();
			
			for(;;)
			{
				//Our process only
				if (te32.th32OwnerProcessID == nProcID)
				{
					//Look through all windows in this thread
					EnumThreadWindows(te32.th32ThreadID, _enumProcCloseAll, (LPARAM)hDlg);
				}

				//Go to next one
				if(!Thread32Next(hEnum, &te32))
				{
					if (::GetLastError() == ERROR_NO_MORE_FILES)
					{
						//All done
						bRes = TRUE;
					}
					else
					{
						//Error
						EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(613);
						ASSERT(NULL);
					}
					
					break;
				}
			}
		}
		else
		{
			//Error
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(612);
			ASSERT(NULL);
		}

		//Close handle
		VERIFY(CloseHandle(hEnum));
	}
	else
	{
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(611);
		ASSERT(NULL);
	}

	return bRes;
}


DWORD CMainWnd::ThreadProc_EventsWorker(LPVOID lpParameter)
{
	//Thread that monitors special events while the main window is running
	CMainWnd* pThis = (CMainWnd*)lpParameter;
	ASSERT(pThis);

	HANDLE hDudEvent = NULL;

	enum HANDLE_TYPES{
		HT_STOP_EVENT,		//[Manual] event that will be set when this GUI app is closing
		HT_QUIT_APP,		//[Manual] event that is set to close this app immedaitely (during uninstallation)

		HT_COUNT			//Must be last!
	};

	HANDLE hWaitHandles[HT_COUNT] = {};
	ASSERT(pThis->_hEventStop);
	hWaitHandles[HT_STOP_EVENT] = pThis->_hEventStop;
	ASSERT(pThis->_hEventQuitNow);
	hWaitHandles[HT_QUIT_APP] = pThis->_hEventQuitNow;


	//Waiting loop
	for (;; ::Sleep(1))		//Precaution if this loop starts running amuck
	{
		DWORD dwR = ::WaitForMultipleObjects(_countof(hWaitHandles), hWaitHandles, FALSE, INFINITE) - WAIT_OBJECT_0;

		if (dwR == HT_STOP_EVENT)
		{
			//Need to quit this thread
			break;
		}
		else if (dwR == HT_QUIT_APP)
		{
			//Need to close this app (usually instructed from the outside by the uninstaller)
			BOOL bResClosedAll = pThis->CloseAllWindowsExceptMainWnd();
			if (bResClosedAll)
			{
				//And then post a message to the main window to close
				HWND hMainWnd = pThis->hDlg;
				if (hMainWnd &&
					::IsWindow(hMainWnd))
				{
					if (!::PostMessage(hMainWnd, WM_CLOSE, 0, 0))
					{
						//Failed
						EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(614, L"h=0x%p", hMainWnd);
						ASSERT(NULL);

						bResClosedAll = FALSE;
					}
				}
			}
			else
			{
				//Failed
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(619);
				ASSERT(NULL);
			}


			if (!bResClosedAll)
			{
				//Have no choice but to kill the self process
				EVENT_LOG_REPORTS::ReportEventLogMsgWARNING_WithFormat(L"[620] Terminating self");

				//INFO: We'll use a function that should signal to terminate this process unconditionally
				if (!::TerminateProcess(::GetCurrentProcess(), 0xdead0001))
				{
					//Even that failed
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(621);
					::ExitProcess(0xdead0002);
				}
			}


			//Remove our handle for the wait list (so that we won't get back to this clause again)
			ASSERT(!hDudEvent);
			hDudEvent = ::CreateEvent(NULL, FALSE, FALSE, NULL);
			if (!hDudEvent)
			{
				//Error
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(615);
				ASSERT(NULL);
			}

			hWaitHandles[HT_QUIT_APP] = hDudEvent;
		}
		else
		{
			//Error
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(610, L"r=%d", dwR);

			break;
		}
	}



	//Clean up
	if (hDudEvent)
	{
		::CloseHandle(hDudEvent);
		hDudEvent = NULL;
	}

	return 0;
}


LPCTSTR CMainWnd::ConvertStringsNulls(std::wstring* pStr, TCHAR chAnchor)
{
	//Replace all occurances of 'chAnchor' in 'pStr' with \0's
	//RETURN:
	//		= Pointer to converted string (INFO: The pointer is valid in the scope of 'pStr')
	ASSERT(pStr);

	WCHAR* pStrBuff = &(*pStr)[0];
	intptr_t nLnBuff = pStr->size();
	for (intptr_t i = 0; i < nLnBuff; i++)
	{
		if (pStrBuff[i] == chAnchor)
			pStrBuff[i] = 0;
	}

	return pStrBuff;
}


void CMainWnd::ConvertMultiPartPathIntoComponents(std::wstring& strMultiPartPath, std::vector<std::wstring>& arrOutComponents, LPCTSTR pStrMultiFilePathSeparator)
{
	//Convert multi-part path from 'strMultiPartPath' into components separated by 'pStrMultiFilePathSeparator'
	//'arrOutComponents' = receives all components as file paths

	//Clear
	arrOutComponents.clear();

	//We must have a separator
	if (pStrMultiFilePathSeparator &&
		pStrMultiFilePathSeparator[0])
	{
		intptr_t nPos = 0;
		std::wstring strToken = AUX_FUNCS::Tokenize(strMultiPartPath, pStrMultiFilePathSeparator, nPos);
		while (nPos != -1)
		{
			AUX_FUNCS::Trim(strToken);
			if (!strToken.empty())
			{
				arrOutComponents.push_back(strToken);
			}

			strToken = AUX_FUNCS::Tokenize(strMultiPartPath, pStrMultiFilePathSeparator, nPos);
		}
	}
	else
		ASSERT(NULL);
}



UINT_PTR CMainWnd::_OFNHookProcOldStyle(HWND hdlg, UINT uiMsg, WPARAM wParam, LPARAM lParam)
{
	//Must always return FALSE to enable showing of the old-style dialog box
	return FALSE;
}


RES_YES_NO_ERR CMainWnd::GetOpenFilePathWithDialog(std::wstring* pOutStrPaths, HWND hParentWnd, DWORD dwFlags, LPCTSTR pStrFilter, int* pnFilterIndex, LPCTSTR pStrInitialFolder, LPCTSTR pStrTitle, LPCTSTR pStrMultiFilePathSeparator)
{
	//Show dialog that allows to pick file name(s) for opening
	//'pOutStrPaths' = if not NULL, receives the file path(s) picked by the user
	//					INFO: In case of multiple file selection, use ConvertMultiPartPathIntoComponents() to convert it into individual files
	//'hParentWnd' = parent Window handle, or NULL to use default
	//'dwFlags' = Can be [bitwise]:
	//				- OFN_NODEREFERENCELINKS = Not to follow links
	//				- OFN_FILEMUSTEXIST		= [Default] specified file must exist
	//				- OFN_ALLOWMULTISELECT	= to allow selection of more than one file
	//'pStrFilter' = filter for the files, use "|" to separate parts. It must end with "|"!
	//'pnFilterIndex' = if not NULL, then it is 1-based filter index (from 'pStrFilter') to select. When this function returns, it will contain selected filter index
	//'pStrInitialFolder' = if not NULL, initial folder where to open this window (may or may not be slash-terminated)
	//'pStrTitle' = if not NULL, replacement title for the dialog
	//'pStrMultiFilePathSeparator' = if used to separate returned file paths in case of multi-file selection
	//RETURN:
	//	RYNE_YES	- Success, got file path(s) in 'pOutStrPaths'
	//	RYNE_NO		- If user canceled the dialog
	//	RYNE_ERROR	- If error
	return _open_save_dlg_func(FALSE, pOutStrPaths, hParentWnd, dwFlags, NULL, pStrFilter, pnFilterIndex, pStrTitle, NULL, pStrInitialFolder, pStrMultiFilePathSeparator);
}

RES_YES_NO_ERR CMainWnd::GetSaveFilePathWithDialog(std::wstring* pOutStrPath, HWND hParentWnd, DWORD dwFlags, LPCTSTR pStrDefaultExt, LPCTSTR pStrFilter, int* pnFilterIndex, LPCTSTR pStrTitle, LPCTSTR pStrFileName, LPCTSTR pStrInitialFolder)
{
	//Show dialog that allows to pick file name(s) for saving
	//'pOutStrPath' = if not NULL, receives the file path selected by the user
	//'hParentWnd' = parent Window handle, or NULL to use default
	//'dwFlags' = Bitwise flags. See 
	//'pStrDefaultExt' = default extension ("ini" for instance)
	//'pStrFilter' = filter for the files, use "|" to separate parts. It must end with "|"!
	//'pnFilterIndex' = if not NULL, then it is 1-based filter index (from 'pStrFilter') to select. When this function returns, it will contain selected filter index
	//'pStrTitle' = if not NULL, title for the top of the window
	//'pStrFileName' = if not NULL, default file name for saving
	//'pStrInitialFolder' = if not NULL, initial folder where to open this window (may or may not be slash-terminated)
	//RETURN:
	//	RYNE_YES	- Success, got file path(s) in 'pOutStrPaths'
	//	RYNE_NO		- If user canceled the dialog
	//	RYNE_ERROR	- If error
	return _open_save_dlg_func(TRUE, pOutStrPath, hParentWnd, dwFlags, pStrDefaultExt, pStrFilter, pnFilterIndex, pStrTitle, pStrFileName, pStrInitialFolder, NULL);
}


RES_YES_NO_ERR CMainWnd::_open_save_dlg_func(BOOL bSaveDlg, std::wstring* pOutStrPath, HWND hParentWnd, DWORD dwFlags, 
	LPCTSTR pStrDefaultExt, LPCTSTR pStrFilter, int* pnFilterIndex, LPCTSTR pStrTitle, LPCTSTR pStrFileName,
	LPCTSTR pStrInitialFolder, LPCTSTR pStrMultiFilePathSeparator)
{
	//Internal method
	RES_YES_NO_ERR res = RYNE_ERROR;

	std::wstring strPath;
	HRESULT hr;

	BOOL bFallbackToOldDlg = TRUE;
	std::wstring strFilter;

#ifdef _DEBUG
	if (pStrMultiFilePathSeparator)
	{
		ASSERT(pStrMultiFilePathSeparator[0]);		//Separator must ne provided! Or set it to NULL
	}
#endif

	//Add some default flags
	dwFlags |= OFN_HIDEREADONLY | OFN_EXPLORER | OFN_ENABLESIZING;

	if (bSaveDlg)
	{
		//For saving only
		dwFlags &= ~(OFN_ALLOWMULTISELECT);		//Don't allow multiselection
	}


	std::wstring strIniDirPath;
	if (pStrInitialFolder)
	{
		//Remove last slash
		strIniDirPath = AUX_FUNCS::MakeFolderPathEndWithSlash(pStrInitialFolder, FALSE);
	}


	//Init COM - we need single-threaded model only (multi-threaded model is not supported by IFileDialog)
	if (SUCCEEDED(hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)))
	{
		CComPtr<IFileDialog> pIFileDialog;

		if (SUCCEEDED(hr = CoCreateInstance(bSaveDlg ? CLSID_FileSaveDialog : CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pIFileDialog))))
		{
			//pIFileDialog->Advise();

			if (pStrTitle)
			{
				if (FAILED(hr = pIFileDialog->SetTitle(pStrTitle)))
				{
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(647, L"bSv=%d, hr=0x%x, str=\"%s\"", bSaveDlg, hr, pStrTitle);
					ASSERT(NULL);
				}
			}

			if (pStrDefaultExt)
			{
				if (FAILED(hr = pIFileDialog->SetDefaultExtension(pStrDefaultExt)))
				{
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(646, L"bSv=%d, hr=0x%x, ext=\"%s\"", bSaveDlg, hr, pStrDefaultExt);
					ASSERT(NULL);
				}
			}

			if (pStrFileName)
			{
				if (FAILED(pIFileDialog->SetFileName(pStrFileName)))
				{
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(645, L"bSv=%d, hr=0x%x, name=\"%s\"", bSaveDlg, hr, pStrFileName);
					ASSERT(NULL);
				}
			}

			if (!strIniDirPath.empty())
			{
				CComPtr<IShellItem> pShItm;
				if (SUCCEEDED(hr = ::SHCreateItemFromParsingName(strIniDirPath.c_str(), NULL, IID_PPV_ARGS(&pShItm))))
				{
					if (FAILED(hr = pIFileDialog->SetDefaultFolder(pShItm)))
					{
						EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(650, L"bSv=%d, hr=0x%x, path=\"%s\"", bSaveDlg, hr, strIniDirPath.c_str());
						ASSERT(NULL);
					}
				}
				else
				{
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(651, L"bSv=%d, hr=0x%x, path=\"%s\"", bSaveDlg, hr, strIniDirPath.c_str());
					ASSERT(NULL);
				}
			}

			struct CDFS_2 {
				std::wstring strName;
				std::wstring strSpec;
			};

			std::vector<CDFS_2> arrFltrs;

			if (pStrFilter)
			{
				ASSERT(pStrFilter[wcslen(pStrFilter) - 1] == '|');
				strFilter = pStrFilter;

				BOOL bFiltersOK = TRUE;
				intptr_t nIdx = 0;

				do
				{
					CDFS_2 cd;

					cd.strName = AUX_FUNCS::Tokenize(strFilter, L"|", nIdx);
					if (nIdx == -1)
					{
						//Error
						bFiltersOK = FALSE;
						EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(634, L"bSv=%d, fltr=\"%s\"", bSaveDlg, pStrFilter);
						ASSERT(NULL);
						break;
					}
					cd.strSpec = AUX_FUNCS::Tokenize(strFilter, L"|", nIdx);

					if (!cd.strName.empty() &&
						!cd.strSpec.empty())
					{
						arrFltrs.push_back(cd);
					}
				} while (nIdx != -1);

				if (bFiltersOK)
				{
					size_t szCntCDs = arrFltrs.size();
					if (szCntCDs != 0)
					{
						COMDLG_FILTERSPEC* pCDs = new (std::nothrow) COMDLG_FILTERSPEC[szCntCDs];
						if (pCDs)
						{
							COMDLG_FILTERSPEC* pD = pCDs;
							const CDFS_2* pS = arrFltrs.data();
							for (const CDFS_2* pE = pS + szCntCDs; pS < pE; ++pS, pD++)
							{
								pD->pszName = pS->strName.c_str();
								pD->pszSpec = pS->strSpec.c_str();
							}

							if (FAILED(pIFileDialog->SetFileTypes((UINT)szCntCDs, pCDs)))
							{
								EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(636, L"bSv=%d, sz=%Iu, fltr=\"%s\"", bSaveDlg, szCntCDs, pStrFilter);
								ASSERT(NULL);
							}

							if (pnFilterIndex)
							{
								UINT nIdxFlt = *pnFilterIndex;
								if (FAILED(pIFileDialog->SetFileTypeIndex(nIdxFlt)))
								{
									EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(637, L"bSv=%d, i=%d", bSaveDlg, nIdxFlt);
									ASSERT(NULL);
								}
							}


							delete[] pCDs;
							pCDs = NULL;
						}
						else
						{
							EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(635, L"bSv=%d, sz=%Iu", bSaveDlg, szCntCDs);
							ASSERT(NULL);
						}
					}
				}
			}

			//Adjust flgs
			DWORD dwAdjFlags = 0;
			hr = pIFileDialog->GetOptions(&dwAdjFlags);
			if (SUCCEEDED(hr))
			{
				//Convert old flags to new ones
#define VISTA_FILE_DIALOG_FLAG_MAPPING(OLD,NEW) \
	((dwFlags & (OLD)) ? (dwAdjFlags |= (NEW)) : (dwAdjFlags &= ~(NEW)))
#define VISTA_FILE_DIALOG_FLAG_DIRECT_MAPPING(FLAG) \
	VISTA_FILE_DIALOG_FLAG_MAPPING(OFN_##FLAG, FOS_##FLAG)

				VISTA_FILE_DIALOG_FLAG_DIRECT_MAPPING(ALLOWMULTISELECT);
				VISTA_FILE_DIALOG_FLAG_DIRECT_MAPPING(CREATEPROMPT);
				VISTA_FILE_DIALOG_FLAG_DIRECT_MAPPING(DONTADDTORECENT);
				VISTA_FILE_DIALOG_FLAG_DIRECT_MAPPING(FILEMUSTEXIST);
				VISTA_FILE_DIALOG_FLAG_DIRECT_MAPPING(FORCESHOWHIDDEN);
				VISTA_FILE_DIALOG_FLAG_DIRECT_MAPPING(NOCHANGEDIR);
				VISTA_FILE_DIALOG_FLAG_DIRECT_MAPPING(NODEREFERENCELINKS);
				VISTA_FILE_DIALOG_FLAG_DIRECT_MAPPING(NOREADONLYRETURN);
				VISTA_FILE_DIALOG_FLAG_DIRECT_MAPPING(NOTESTFILECREATE);
				VISTA_FILE_DIALOG_FLAG_DIRECT_MAPPING(NOVALIDATE);
				VISTA_FILE_DIALOG_FLAG_DIRECT_MAPPING(OVERWRITEPROMPT);
				VISTA_FILE_DIALOG_FLAG_DIRECT_MAPPING(PATHMUSTEXIST);
				VISTA_FILE_DIALOG_FLAG_DIRECT_MAPPING(SHAREAWARE);

				dwAdjFlags |= FOS_FORCEFILESYSTEM;

				hr = pIFileDialog->SetOptions(dwAdjFlags);
				if (SUCCEEDED(hr))
				{
					//And show the dialog
					HRESULT hrDlg = pIFileDialog->Show(hParentWnd);
					if (SUCCEEDED(hrDlg))
					{
						//User chose something
						PWSTR pszFilePath;

						//No need to show old style dialog
						bFallbackToOldDlg = FALSE;


						if (!bSaveDlg)
						{
							//Only when opening (because we may have multi-file selection
							CComPtr<IFileOpenDialog> pIfod;
							if (SUCCEEDED(hr = pIFileDialog->QueryInterface(&pIfod)))
							{
								CComPtr<IShellItemArray> pIShItmArr;
								if (SUCCEEDED(hr = pIfod->GetResults(&pIShItmArr)))
								{
									DWORD dwFileCnt = 0;
									if (SUCCEEDED(hr = pIShItmArr->GetCount(&dwFileCnt)))
									{
										//Assume success
										res = RYNE_YES;

										//Go throuhg all files
										for (DWORD f = 0; f < dwFileCnt; f++)
										{
											CComPtr<IShellItem> pIshFile;
											if (SUCCEEDED(hr = pIShItmArr->GetItemAt(f, &pIshFile)))
											{
												pszFilePath = NULL;
												if (SUCCEEDED(hr = pIshFile->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath)))
												{
													if (pszFilePath &&
														pszFilePath[0])
													{
														//Add it to our composite path
														if (pStrMultiFilePathSeparator &&
															!strPath.empty())
														{
															strPath += pStrMultiFilePathSeparator;
														}

														strPath += pszFilePath;
													}

													//Free mem
													::CoTaskMemFree(pszFilePath);
												}
												else
												{
													//Failed to get path
													EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(656, L"bSv=%d, hr=0x%x, f=%d", bSaveDlg, hr, f);
													ASSERT(NULL);

													res = RYNE_ERROR;
													break;
												}
											}
											else
											{
												//Failed to get file
												EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(655, L"bSv=%d, hr=0x%x, f=%d", bSaveDlg, hr, f);
												ASSERT(NULL);

												res = RYNE_ERROR;
												break;
											}
										}
									}
									else
									{
										//Error
										EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(654, L"bSv=%d, hr=0x%x", bSaveDlg, hr);
										ASSERT(NULL);
									}
								}
								else
								{
									//Error
									EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(653, L"bSv=%d, hr=0x%x", bSaveDlg, hr);
									ASSERT(NULL);
								}
							}
							else
							{
								//Error
								EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(652, L"bSv=%d, hr=0x%x", bSaveDlg, hr);
								ASSERT(NULL);
							}
						}
						else
						{
							//Get single file path picked
							CComPtr<IShellItem> pIshi;
							if (SUCCEEDED(hr = pIFileDialog->GetResult(&pIshi)))
							{
								pszFilePath = NULL;
								hr = pIshi->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
								if (SUCCEEDED(hr))
								{
									//Got the file
									strPath = pszFilePath;

									//Return success to the user
									res = RYNE_YES;

									//Free mem
									::CoTaskMemFree(pszFilePath);
								}
								else
								{
									//Failed
									EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(643, L"bSv=%d, hr=0x%x", bSaveDlg, hr);
									ASSERT(NULL);
								}
							}
							else
							{
								//Failed
								EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(642, L"bSv=%d, hr=0x%x", bSaveDlg, hr);
								ASSERT(NULL);
							}
						}
					}
					else if (hrDlg == 0x800704C7)		//ERROR_CANCELLED
					{
						//User canceled the dialog
						res = RYNE_NO;

						//Don't use the fallback method
						bFallbackToOldDlg = FALSE;
					}
					else
					{
						//Error
						EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(641, L"bSv=%d, hr=0x%x, hWnd=0x%p", bSaveDlg, hrDlg, hParentWnd);
						ASSERT(NULL);
					}


					//If showed OK, or if user canceled
					if (SUCCEEDED(hrDlg) ||
						hrDlg == 0x800704C7)
					{
						if (pnFilterIndex)
						{
							//Return selected index
							if (FAILED(hr = pIFileDialog->GetFileTypeIndex((UINT*)pnFilterIndex)))
							{
								//Error
								EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(644, L"bSv=%d, hr=0x%x", bSaveDlg, hr);
								*pnFilterIndex = -1;
								ASSERT(NULL);
							}
						}
					}
				}
				else
				{
					//Error
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(640, L"bSv=%d, hr=0x%x, flags=0x%X", bSaveDlg, hr, dwAdjFlags);
					ASSERT(NULL);
				}
			}
			else
			{
				//Error
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(639, L"bSv=%d, hr=0x%x", bSaveDlg, hr);
				ASSERT(NULL);
			}
		}
		else
		{
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(638, L"bSv=%d, hr=0x%x", bSaveDlg, hr);
			ASSERT(NULL);
		}

		//Unregister COM
		CoUninitialize();
	}
	else
	{
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(633, L"bSv=%d, hr=0x%x", bSaveDlg, hr);
		ASSERT(NULL);
	}


	//Do we need to use a fallback older method?
	if (bFallbackToOldDlg)
	{
		//Show old style dialog
		TCHAR m_szTitle[_MAX_PATH] = {};			// contains title for the window
		m_szTitle[0] = 0;
		WCHAR* pszFilePath = NULL;					// contains full path name after return

		OPENFILENAME ofn = {};
		ofn.lStructSize = sizeof(OPENFILENAME);

		//Reserve file path from the heap
		if (dwFlags & OFN_ALLOWMULTISELECT)
		{
			//Multi-selection
			ofn.nMaxFile = MAX_PATH_LONG_UNICODE;
		}
		else
		{
			//Single selection
			ofn.nMaxFile = _MAX_PATH;
		}

		//Reserve mem
		pszFilePath = new (std::nothrow) WCHAR[ofn.nMaxFile];
		if (pszFilePath)
		{
			pszFilePath[0] = 0;

			//Fill out other params
			ofn.hwndOwner = hParentWnd;
			ofn.lpstrDefExt = pStrDefaultExt;
			ofn.lpstrFile = pszFilePath;
			ofn.Flags = dwFlags;
			ofn.hInstance = (HINSTANCE)&__ImageBase;

			if (!strIniDirPath.empty())
			{
				ofn.lpstrInitialDir = strIniDirPath.c_str();
			}

			if (pStrFilter)
			{
				ASSERT(pStrFilter[wcslen(pStrFilter) - 1] == '|');
				strFilter = pStrFilter;
				ofn.lpstrFilter = ConvertStringsNulls(&strFilter, '|');
			}

			if (pnFilterIndex)
			{
				ofn.nFilterIndex = *pnFilterIndex;
			}

			//'pStrTitle' = if not NULL, title for the top of the window
			//'pStrFileName' = if not NULL, default file name for saving
			if (pStrTitle)
			{
				VERIFY(SUCCEEDED(::StringCchCopy(m_szTitle, _countof(m_szTitle), pStrTitle)));
				ofn.lpstrTitle = m_szTitle;
			}

			if (pStrFileName)
			{
				VERIFY(SUCCEEDED(::StringCchCopy(pszFilePath, ofn.nMaxFile, pStrFileName)));
			}


			//Pick the right function
			BOOL(APIENTRY *pfnGet__FileName)(LPOPENFILENAMEW);
			pfnGet__FileName = bSaveDlg ? ::GetSaveFileName : ::GetOpenFileName;

			WCHAR chPathSep = 0;

			//Show dialog
			BOOL bResShw = pfnGet__FileName(&ofn);
			if (!bResShw)
			{
				//Didn't show dialog, let's see why
				DWORD dwDlgRs;
				if (dwDlgRs = ::CommDlgExtendedError())
				{
					//Some failure
					EVENT_LOG_REPORTS::ReportEventLogMsgWARNING_WithFormat(L"[648] bSv=%d, r=%d", bSaveDlg, dwDlgRs);

					//Older OS, try removing some flags
					ofn.lStructSize = OPENFILENAME_SIZE_VERSION_400;
					ofn.Flags &= ~(OFN_EXPLORER | OFN_ENABLESIZING);
					ofn.Flags |= OFN_ENABLEHOOK;
					ofn.lpfnHook = _OFNHookProcOldStyle;

					chPathSep = L' ';

					//Try again
					bResShw = pfnGet__FileName(&ofn);
					if (!bResShw)
					{
						//Failed again?
						if (dwDlgRs = ::CommDlgExtendedError())
						{
							//Something else is wrong
							EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(649, L"bSv=%d, r=%d", bSaveDlg, dwDlgRs);
							ASSERT(NULL);
						}
						else
						{
							//User cancled old dialog
							res = RYNE_NO;
						}
					}
				}
				else
				{
					//User canceled it
					res = RYNE_NO;
				}
			}

			if (bResShw)
			{
				//Success showing dialog
				res = RYNE_YES;

				if (dwFlags & OFN_ALLOWMULTISELECT)
				{
					//Possible multi-selection
					std::wstring strPart;
					std::vector<std::wstring> arrParts;

					//Extract all parts
					const WCHAR* pB = ofn.lpstrFile;
					for (const WCHAR* pS = pB;; pS++)
					{
						WCHAR z = *pS;
						if (z == chPathSep &&
							pS - ofn.lpstrFile + 1 >= ofn.nFileOffset)
						{
							strPart.assign(pB, pS - pB);
							arrParts.push_back(strPart);

							pS++;
							pB = pS;

							if (!(*pS))
								break;
						}
						else if (!z)
						{
							if (!chPathSep)
							{
								//Error
								EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(658, L"bSv=%d, dir=\"%s\"", bSaveDlg, ofn.lpstrFile);
								ASSERT(NULL);

								res = RYNE_ERROR;
							}
							else
							{
								//Add last part
								strPart.assign(pB, pS - pB);
								arrParts.push_back(strPart);
							}

							break;
						}
					}

					if (res == RYNE_YES)
					{
						//See how many parts did we get?
						intptr_t nCntParts = arrParts.size();
						ASSERT(nCntParts > 0);
						if (nCntParts > 1)
						{
							//Multi-selection -- first part is the directory, followed by selected file names
							std::wstring strDirPath = AUX_FUNCS::MakeFolderPathEndWithSlash(arrParts[0], TRUE);

							for (intptr_t p = 1; p < nCntParts; p++)
							{
								//Add it to our composite path
								if (pStrMultiFilePathSeparator &&
									!strPath.empty())
								{
									strPath += pStrMultiFilePathSeparator;
								}

								strPath += strDirPath;
								strPath += arrParts[p];
							}
						}
						else
						{
							//Use as is
							strPath = ofn.lpstrFile;
						}
					}
				}
				else
				{
					//Only single file selection
					strPath = ofn.lpstrFile;
				}
			}


			//Free mem
			delete[] pszFilePath;
			pszFilePath = NULL;

			//Remember filter index
			if (pnFilterIndex)
				*pnFilterIndex = ofn.nFilterIndex;
		}
		else
		{
			//Memory fault
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(657, L"bSv=%d", bSaveDlg);
			ASSERT(NULL);
		}
	}


	if (pOutStrPath)
		*pOutStrPath = strPath;

	return res;
}



BOOL CMainWnd::SaveRegConfigFileContents(LPCTSTR pStrFilePath, std::vector<CUSTOM_REG_VALUE>& arrData)
{
	//Save 'arrData' array in the 'pStrFilePath' file
	//RETURN:
	//		= TRUE if success
	//		= FALSE if failed - check GetLastError() for details
	BOOL bRes = FALSE;
	int nOSError = 0;

	if (pStrFilePath &&
		pStrFilePath[0])
	{
		//Format the contents
		std::wstring strData;

		SYSTEMTIME stNow = {};
		::GetLocalTime(&stNow);

		AUX_FUNCS::Format(strData,
			L"; Configuration format saved automatically from\r\n"
			L";  %s\r\n"
			L";  Date: %04u-%02u-%02u %02u:%02u:%02u\r\n"
			L"\r\n"
			L"%s=\"%s\"\r\n"
			L"\r\n"
			,
			MAIN_APP_NAME,
			stNow.wYear, stNow.wMonth, stNow.wDay, stNow.wHour, stNow.wMinute, stNow.wSecond,
			REG_VAL_NAME__VERSION,
			AUX_FUNCS::EscapeDoubleQuoteString(MAIN_APP_VER).c_str()
			);

		//Add all entries
		const CUSTOM_REG_VALUE* pCRV = arrData.data();
		for (const CUSTOM_REG_VALUE* pEnd = pCRV + arrData.size(); pCRV < pEnd; ++pCRV)
		{
			AUX_FUNCS::AppendFormat(strData,
				L"%s\r\n"
				,
				AUX_FUNCS::CUSTOM_REG_VALUE_to_NameValue_Str(pCRV).c_str()
				);
		}


		//Create new file
		HANDLE hFile = ::CreateFile(pStrFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			//Write file as UTF-16 with a BOM
			static BYTE bom[] = { 0xff, 0xfe };

			DWORD dwcbWrtn = 0;
			if (::WriteFile(hFile, bom, sizeof(bom), &dwcbWrtn, NULL))
			{
				if (dwcbWrtn == sizeof(bom))
				{
					//Then write our string
					size_t szchLnData = strData.size() * sizeof(WCHAR);
					dwcbWrtn = 0;
					if (::WriteFile(hFile, strData.c_str(), (DWORD)szchLnData, &dwcbWrtn, NULL))
					{
						if (dwcbWrtn == szchLnData)
						{
							//All done
							bRes = TRUE;

						}
						else
							nOSError = 4635;
					}
					else
						nOSError = ::GetLastError();
				}
				else
					nOSError = 3089;
			}
			else
				nOSError = ::GetLastError();

			//Close handle
			::CloseHandle(hFile);
		}
		else
			nOSError = ::GetLastError();
	}
	else
		nOSError = 2115;

	::SetLastError(nOSError);
	return bRes;
}


void CMainWnd::OnMenuFileSaveConfig()
{
	//Save current settings into a config file

	//Collect data firsr
	APP_SETTINGS stgs;
	if (!CollectDataFromUI(stgs))
	{
		//Can't continue if data was not collected
		return;
	}

	//Convert result to the array
	std::vector<CUSTOM_REG_VALUE> arrCRVs;
	if (!stgs.to_CUSTOM_REG_VALUE_array(arrCRVs))
	{
		//Failed
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(659, L"sz=%Id", arrCRVs.size());
		ASSERT(NULL);

		ShowMessageBox(L"[660] Failed to collect data.", MB_ICONERROR);
		return;
	}

	//Ask user where to save
	int nFilter = 2;
	std::wstring strPath;
	RES_YES_NO_ERR rzSf = GetSaveFilePathWithDialog(&strPath, hDlg,
		OFN_OVERWRITEPROMPT,
		REG_CONFILE_FILE_EXT,
		L"All Files (*.*)|*.*|Text Files (*." REG_CONFILE_FILE_EXT L")|*." REG_CONFILE_FILE_EXT L"|",
		&nFilter, NULL,
		REG_CONFILE_FILE_NAME);

	if (rzSf == RYNE_YES)
	{
		//Set wait cursor
		SHOW_WAIT_CURSOR waitCursor;

		if (!CMainWnd::SaveRegConfigFileContents(strPath.c_str(), arrCRVs))
		{
			//Error saving
			int nOSError = ::GetLastError();
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(663, L"path=\"%s\"", strPath.c_str());

			//Show user message
			WCHAR buffMsg[1024];
			WCHAR buff[1224];
			::StringCchPrintf(buff, _countof(buff), 
				L"Failed to save in the following file:\n\n%s\n\nERROR: (0x%X) %s"
				,
				strPath.c_str(),
				nOSError, 
				AUX_FUNCS::getFormattedErrorMsg(nOSError, buffMsg, _countof(buffMsg)));

			ShowMessageBox(buff, MB_ICONERROR);
		}
	}
	else if (rzSf != RYNE_NO)
	{
		//Error showing dialog box
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(661, L"r=%d", rzSf);
		ASSERT(NULL);

		ShowMessageBox(L"[662] Failed to save data.", MB_ICONERROR);
	}
}


void CMainWnd::OnMenuFileOpenConfig()
{
	//Open config file and place its settings in the UI

	//Ask user where for a file path
	int nFilter = 2;
	std::wstring strPath;
	RES_YES_NO_ERR rzSf = CMainWnd::GetOpenFilePathWithDialog(&strPath, hDlg,
		OFN_FILEMUSTEXIST,
		L"All Files (*.*)|*.*|Text Files (*." REG_CONFILE_FILE_EXT L")|*." REG_CONFILE_FILE_EXT L"|",
		&nFilter);

	if (rzSf == RYNE_YES)
	{
		//User provided a file
		LoadRegConfigFile(strPath.c_str());

	}
	else if (rzSf != RYNE_NO)
	{
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(665, L"r=%d", rzSf);
		ASSERT(NULL);

		ShowMessageBox(L"[666] Failed to show open-file dialog.", MB_ICONERROR);
	}

}

BOOL CMainWnd::LoadRegConfigFile(LPCTSTR pStrFilePath)
{
	//Load registry configuration from a file in 'pStrFilePath'
	//INFO: Will show error message if any
	//RETURN:
	//		= TRUE if success
	//		= FALSE if error (check GetLastError() for info)
	ASSERT(pStrFilePath && pStrFilePath[0]);
	BOOL bRes = FALSE;
	int nOSError = 0;

	//Show waiting cursor
	SHOW_WAIT_CURSOR waitCursor;

	WCHAR buffMsg[1024];
	WCHAR buff[1224];

	std::vector<CUSTOM_REG_VALUE> arrCRVs;
	if (AUX_FUNCS::GetRegConfigFileContents(pStrFilePath, &arrCRVs))
	{
		//Convert to UI settings
		APP_SETTINGS as;
		VER_CMP_RES rezVer;
		BOOL bAllowContinue = FALSE;

		//Check version first
		CUSTOM_REG_VALUE* pVer = AUX_FUNCS::find_CUSTOM_REG_VALUE_byName(arrCRVs, REG_VAL_NAME__VERSION);
		if (!pVer)
		{
			//Failed
			nOSError = 4452;
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(669, L"path=\"%s\"", pStrFilePath);

			goto lbl_content_err;
		}

		if (pVer->type != CRVT_STRING)
		{
			//Bad type
			nOSError = 1756;
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(670, L"t=%d, path=\"%s\"", pVer->type, pStrFilePath);

			goto lbl_content_err;
		}

		//Check that it's not a newer version
		rezVer = AUX_FUNCS::CompareVersions(pVer->strVal.c_str(), MAIN_APP_VER);
		if (rezVer == VCRES_EQUAL ||
			rezVer == VCRES_V1_LESS_THAN_V2)
		{
			//All good
			bAllowContinue = TRUE;
		}
		else if (rezVer == VCRES_V1_GREATER_THAN_V2)
		{
			//Newer version

			if (ShowMessageBox(L"You are trying to open a configuration file that was created by a newer version of this program. Some parameters may not open correctly.\n\n"
				L"Do you want to continue?",
				MB_ICONWARNING | MB_YESNOCANCEL | MB_DEFBUTTON2) == IDYES)
			{
				//User chose to open
				bAllowContinue = TRUE;
			}
		}
		else
		{
			//Error
			nOSError = ::GetLastError();
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(671, L"ver=\"%s\", path=\"%s\"", pVer->strVal.c_str(), pStrFilePath);

			goto lbl_content_err;
		}


		if (bAllowContinue)
		{
			//Begin with defaults
			as.setDefaults();

			//Convert
			if (as.from_CUSTOM_REG_VALUE_array(arrCRVs))
			{

				//Set UI controls now
				SetCtrls(as);

				//Done
				bRes = TRUE;
			}
			else
			{
				//Failed to convert
				nOSError = ::GetLastError();
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(668, L"path=\"%s\"", pStrFilePath);
lbl_content_err:
				//Show user message
				::StringCchPrintf(buff, _countof(buff),
					L"Configuration data in the following file is incorrect:\n\n%s\n\nERROR: (0x%X) %s"
					,
					pStrFilePath,
					nOSError,
					AUX_FUNCS::getFormattedErrorMsg(nOSError, buffMsg, _countof(buffMsg)));

				ShowMessageBox(buff, MB_ICONERROR);
			}
		}
	}
	else
	{
		//Error
		nOSError = ::GetLastError();
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(667, L"path=\"%s\"", pStrFilePath);

		//Show user message
		::StringCchPrintf(buff, _countof(buff),
			L"Failed to read configuration data from the following file:\n\n%s\n\nERROR: (0x%X) %s"
			,
			pStrFilePath,
			nOSError,
			AUX_FUNCS::getFormattedErrorMsg(nOSError, buffMsg, _countof(buffMsg)));

		ShowMessageBox(buff, MB_ICONERROR);
	}

	::SetLastError(nOSError);
	return bRes;
}


BOOL CMainWnd::OnDragAndDrop_IsAllowed(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER * pInfo)
{
	//Is called to find out if drag-and-drop is allowed (this function is called first)
	//'pInfo' = drag-and-drop window info
	//RETURN:
	//		= TRUE if drag-and-drop operation of 'dragType' item is allowed
	assert(pInfo);
	BOOL bResAllow = FALSE;

	if (dragType == DIT_URI)
	{
		//Allow only files
		bResAllow = TRUE;
	}

	return bResAllow;
}

void CMainWnd::OnDragAndDrop_Began(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER * pInfo, BOOL * pbSetFocus, DWORD grfKeyState, POINTL pt, DWORD * pdwEffect)
{
	//Is called when drag-and-drop starts (is called only once)
	//'dragType' = type of object being dragged
	//'pInfo' = drag-and-drop window info
	//'pbSetFocus' = pointer to the BOOL var that is set to TRUE originally. You can set it to FALSE, if you won't need the window to receive keyboard focus
	//'grfKeyState' = bitwise auxiliary key state during the drag-and-drop:
	//					MK_CONTROL, MK_SHIFT, MK_ALT, MK_BUTTON, MK_LBUTTON, MK_MBUTTON, and MK_RBUTTON
	//'pt' = current cursor coordinates in screen coordinates.
	//'pdwEffect' = pointer to a variable that was set to visual effect bits for the mouse cursor. See IDropTarget::DoDragDrop
	assert(pInfo);
	assert(pbSetFocus);
	assert(pdwEffect);

}

void CMainWnd::OnDragAndDrop_Pending(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER * pInfo, DWORD grfKeyState, POINTL pt, DWORD * pdwEffect)
{
	//Is called when drag-and-drop is ongoing (is called multiple times as the user moves the mouse)
	//'dragType' = type of object being dragged
	//'pInfo' = drag-and-drop window info
	//'grfKeyState' = bitwise auxiliary key state during the drag-and-drop:
	//					MK_CONTROL, MK_SHIFT, MK_ALT, MK_BUTTON, MK_LBUTTON, MK_MBUTTON, and MK_RBUTTON
	//'pt' = current cursor coordinates in screen coordinates.
	//'pdwEffect' = pointer to a variable that was set to visual effect bits for the mouse cursor. See IDropTarget::DoDragDrop
	assert(pInfo);
	assert(pdwEffect);

}

void CMainWnd::OnDragAndDrop_Ended(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER * pInfo)
{
	//Is called when drag-and-drop ends (is called only once)
	//'dragType' = type of object being dragged
	//'pInfo' = drag-and-drop window info
	assert(pInfo);


}

BOOL CMainWnd::OnDragAndDrop_DropData(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER * pInfo, DRAGGED_ITEMS * pDroppedItems, DWORD grfKeyState, POINTL pt, DWORD * pdwEffect, DRAG_N_DROP_DROP_FLAGS dropFlags)
{
	//Is called when drag-and-drop data has been successfully dropped into this window (it is called only once)
	//'dragType' = type of object being dragged
	//'pInfo' = drag-and-drop window info
	//'pDroppedItems' = items that were just dropped
	//'grfKeyState' = bitwise auxiliary key state during the drag-and-drop:
	//					MK_CONTROL, MK_SHIFT, MK_ALT, MK_BUTTON, MK_LBUTTON, MK_MBUTTON, and MK_RBUTTON
	//'pt' = current cursor coordinates in screen coordinates.
	//'pdwEffect' = pointer to a variable that was set to visual effect bits for the mouse cursor. See IDropTarget::DoDragDrop
	//'dropFlags' = [bitwise] flags for the drag-and-drop that just occurred
	//RETURN:
	//		= TRUE if dropped items were accepted
	//		= FALSE if they were not accepted
	assert(pInfo);
	assert(pDroppedItems);
	assert(pdwEffect);
	BOOL bResAccepted = FALSE;

	//Need files only
	if (pDroppedItems->dataType == DIT_URI)
	{
		if (pDroppedItems->arrPaths.size() >= 1)
		{
			//We're accepting it
			bResAccepted = TRUE;

			//Send message to self to process it later
			//INFO: Do not hold off OLE mechanism here in case we need to show some UI....
			std::wstring* p_strFilePath = new (std::nothrow) std::wstring(pDroppedItems->arrPaths[0]);
			if (p_strFilePath)
			{
				ASSERT(pInfo->hWndTarget);
				if (!::PostMessage(pInfo->hWndTarget, MSG_ID_DRAG_N_DROP_FILE, 0, (LPARAM)p_strFilePath))
				{
					//Failed
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(681, L"path=\"%s\"", p_strFilePath->c_str());
					
					delete p_strFilePath;
					p_strFilePath = NULL;
				}
			}
		}
	}

	return bResAccepted;
}

void CMainWnd::OnDropFile(std::wstring* p_strFilePath)
{
	//Called when a user drag-and-drops a file
	//'p_strFilePath' = file path -- must be removed with delete!
	ASSERT(p_strFilePath);

	if (p_strFilePath)
	{
		//Open it
		LoadRegConfigFile(p_strFilePath->c_str());

		//Free mem
		delete p_strFilePath;
		p_strFilePath = NULL;
	}
}


BOOL CMainWnd::PowerOpNoUpdates(POWER_OP powerOp)
{
	//Initiate power operation in 'powerOp' without updates
	//RETURN:
	//		= TRUE if success
	//		= FALSE if error (check GetLastError() for info)
	BOOL bRes = FALSE;
	int nOSError = 0;

	LPCTSTR pStrPowerOp = NULL;
	DWORD dwPowerOpFlags = 0;
	LPCTSTR pStrSubOption = L"(This tool will attempt to prevent installation of updates, if possible.)";

	WCHAR buffMsg[1024];
	WCHAR buff[1224];

	switch (powerOp)
	{
	case PWR_OP_REBOOT:
		pStrPowerOp = L"reboot this computer";
		dwPowerOpFlags = SHUTDOWN_RESTART | SHUTDOWN_RESTARTAPPS;
		break;

	case PWR_OP_SHUTDOWN:
		pStrPowerOp = L"shut down this computer";
		dwPowerOpFlags = SHUTDOWN_POWEROFF;
		break;

	case PWR_OP_BSOD:
		pStrPowerOp = L"\"Blue Screen\" this computer";
		pStrSubOption = L"(IMPORTANT: Make sure to save all your data first!)";
		break;

	default:
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(685, L"pwr=%d", powerOp);
		ASSERT(NULL);
		pStrPowerOp = NULL;
		nOSError = ERROR_EMPTY;
		break;
	}

	if (pStrPowerOp)
	{
		//Show user warning
		if (this->ShowMessageBox(AUX_FUNCS::EasyFormat(
			L"Do you want to %s now?\n\n"
			L"%s"
			,
			pStrPowerOp,
			pStrSubOption).c_str(),
			MB_ICONWARNING | MB_YESNOCANCEL) == IDYES)
		{
			BOOL bResPwrOp = FALSE;

			//Set privilege first
			if (AUX_FUNCS::AdjustPrivilege(SE_SHUTDOWN_NAME, TRUE, NULL))
			{
				if (powerOp != PWR_OP_BSOD)
				{
					//Initiate the power op
					nOSError = ::InitiateShutdown(NULL, NULL, 0, dwPowerOpFlags, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED);
				}
				else
				{
					//Implement undocumented way to BSOD this computer
					typedef struct _UNICODE_STRING {
						USHORT Length;
						USHORT MaximumLength;
						_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
					} UNICODE_STRING;
					typedef UNICODE_STRING *PUNICODE_STRING;

					NTSTATUS (NTAPI *pfn_NtRaiseHardError)(
						NTSTATUS ErrorStatus,
						ULONG NumberOfParameters,
						PUNICODE_STRING UnicodeStringParameterMask,
						PVOID parameters,
						ULONG ResponseOption,
						PULONG Response) = NULL;

					(FARPROC&)pfn_NtRaiseHardError = ::GetProcAddress(::GetModuleHandle(L"ntdll.dll"), "NtRaiseHardError");
					if (pfn_NtRaiseHardError)
					{
						//Initiate "Blue Screen of Death"
						ULONG nResponse;
						NTSTATUS status = pfn_NtRaiseHardError(0xDEADDEAD /* MANUALLY_INITIATED_CRASH1 */, 0, NULL, NULL, 6 /* OPTION_SHUTDOWN_SYSTEM */, &nResponse);
						if (status == 0)
						{
							//Success
							nOSError = ERROR_SUCCESS;
						}
						else
						{
							//Failed
							nOSError = RtlNtStatusToDosError(status);
							if (nOSError == ERROR_SUCCESS)
								nOSError = ERROR_GEN_FAILURE;

							::SetLastError(nOSError);
							EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(689, L"nResponse=0x%x", nResponse);
						}
					}
					else
					{
						//No function
						nOSError = AUX_FUNCS::GetLastErrorNotNULL(ERROR_INVALID_FUNCTION);
						EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(688);
					}
				}

				//Restore privilege back
				if (!AUX_FUNCS::AdjustPrivilege(SE_SHUTDOWN_NAME, FALSE, NULL))
				{
					//Failed
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(687, L"p=%d", dwPowerOpFlags);
				}

				//Check result
				if (nOSError == ERROR_SUCCESS)
				{
					//Done
					bResPwrOp = TRUE;
				}
			}
			else
			{
				//Failed
				nOSError = ::GetLastError();
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(686, L"p=%d", dwPowerOpFlags);
			}


			if (!bResPwrOp)
			{
				//Show user error
				::StringCchPrintf(buff, _countof(buff),
					L"Failed to %s:\n\nERROR: (0x%X) %s"
					,
					pStrPowerOp,
					nOSError,
					AUX_FUNCS::getFormattedErrorMsg(nOSError, buffMsg, _countof(buffMsg)));

				ShowMessageBox(buff, MB_ICONERROR);
			}
		}
	}

	::SetLastError(nOSError);
	return bRes;
}