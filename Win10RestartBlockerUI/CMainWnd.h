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
#pragma once

#include <Windows.h>
#include "framework.h"

#include <ShObjIdl_core.h>

#include <commdlg.h>
#include "CDropTarget32.h"



#define MAIN_LOGO_ICON_WIDTH 64
#define MAIN_LOGO_ICON_HEIGHT 64

class CMainWnd : public CDropTarget32
{
public:
	CMainWnd(HINSTANCE hInst = NULL);
	~CMainWnd();
	BOOL CreateMainWnd(BOOL bPreventAnotherInstance);
	CMD_LINE_PARSE_RESULTS ParseCommandLine();
	DWORD dwExitCode;				//App exit code: 0=success
private:
	HINSTANCE _ghInstance;
	HWND hDlg;
	ATOM _hAtomClassName;		//Class registered for this window
	HANDLE _hEventQuitNow;		//[Manual] event that is used to check if another instance is already running, and also will be set to close this app immedaitely (during uninstallation) -- this event is never closed on purpose. It will be removed automatically when this app quits
	HICON _hIconLogo;			//Main logo
	SIZE _gszMainIconLogo;		//Size of main icon logo that we loaded (scaled for current DPI setting)
	HANDLE _hThreadEventMon;	//Thread that monitors special events (it runs for as long as this GUI app is running)
	HANDLE _hEventStop;			//[Manual] event that will be set when this GUI app is closing
	APP_SETTINGS g_settings;	//Cached settings
	RES_YES_NO_ERR gReqAdmin;	//Check if elevation is required to access privileged resources
	SAVED_DATA g_CmdSvData;		//Data for saving, passed via command line call
	POWER_OP g_CmdSvPowerOp;	//Power operation, passed via command line call
	std::wstring gstrOpenCfgFilePath;		//Config file path passed into our app via command line
	HMONITOR _ghCmdMonitor;		//Monitor handle to show our window in (when invoked from a command line)
	BOOL _gbPostInitDlgDone;	//TRUE if post-init-dialog message was dispatched
	HACCEL _hAccelMain;			//Main window accelerators
	HBITMAP _ghBmpUAC;			//UAC shield bitmap
	INT_PTR DlgProc(UINT uMsg, WPARAM wParam, LPARAM lParam);
	BOOL OnInitDialog(HWND hWndDefaultFocus);
	void OnPostInitDialog();
	BOOL OnFinalMessage();
	BOOL GetLogoIconRect(RECT & rcOut);
	void OnPaint(HDC hDC, PAINTSTRUCT& ps);
	BOOL ChangeClassNameForDlgWnd(LPCTSTR pStrNewClassName);
	BOOL _unregisterCurrentWndClass();
	BOOL PositionThisWindowInCenterOfMonitor(HMONITOR hMonitor = NULL);
	BOOL OnCtrlCommand(WORD wCtrlID, WORD wCode);
	BOOL OnMenuCommand(WORD wCmd, BOOL bAccelerator);
	void OnMenuHelpAbout();
	static CMainWnd * GetCMainWndFromHWND(HWND hWnd);
	static INT_PTR CALLBACK _iniDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static INT_PTR CALLBACK _redirDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static BOOL DialogBoxParamSpecial(HINSTANCE hInstance, LPCWSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam = 0, HACCEL* p_hAccel = NULL);
	static INT_PTR CALLBACK _AboutDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
	void OnCtrlColor(HDC hDC, HWND hWndCtrl, UINT nCtrlId, HBRUSH & hBrush);
	UI_SHOW_TYPE GetCurrentWhenToShow();
	static UINT _minToHrs(UINT nMin);
	UI_SHOW_TYPE GetWhenToShowSaveState(BOOL bInitial = FALSE);
	int _nCurVal1Hrs;
	void UpdateShowEveryHrsCtrlText(UI_SHOW_TYPE type, int nHrs);
	void UpdateWhenToShowCtrls(BOOL bInitial = FALSE);
	BOOL IsBlockEnabled();
	void UpdateBlockEnableCtrls(BOOL bInitial = FALSE);
	void OnHelpInfo();
	void OnCheckForUpdates();
	void OnShowBlogPost();
	RES_YES_NO_ERR IsShellChromeAPI_Installed(BOOL bShowErrorUI = FALSE);
	static BOOL CALLBACK _enumProcCloseAll(HWND hWnd, LPARAM lParam);
	BOOL CloseAllWindowsExceptMainWnd();
	int ShowMessageBox(LPCTSTR pStrMsg, UINT nType = MB_ICONEXCLAMATION);
	void OnEditSetDefaults();
	void SetCtrls(APP_SETTINGS& settings);
	RES_YES_NO_ERR IsElevationRequiredToSaveChanges();
	BOOL GetComboBoxSelectedData(UINT nCtrlID, LRESULT * pOutData = NULL);
	int GetCurrentShowEveryHrsFromCtrl();
	BOOL CollectDataFromUI(APP_SETTINGS & outData);
	BOOL OnOK();
	void OnApply();
	BOOL OnCancel();
	void ShowFailedToSaveDataUI(int nSpecErr);
	BOOL SaveDataFromUI(BOOL bCloseWhenSaved);
	BOOL SaveData(APP_SETTINGS & data);
	static int ShellExecuteWithMonitor(HWND hWnd, LPCTSTR lpOperation, LPCTSTR lpFile, LPCTSTR lpParameters, LPCTSTR lpDirectory = NULL, INT nShowCmd = SW_SHOW, HWND hWndToUseForMonitor = NULL, ULONG uiFlags = SEE_MASK_FLAG_NO_UI, HANDLE* phOutProcess = NULL);
	BOOL OpenWebPage(LPCTSTR pStrURI);
	BOOL OpenWebPageWithErrorUI(LPCTSTR pStrURI);
	static WCHAR * UrlEncode(LPCTSTR pStrUrl);
	BOOL OpenEventLog();
	BOOL SubmitBugReport();
	static DWORD WINAPI ThreadProc_EventsWorker(LPVOID lpParameter);
	static LPCTSTR ConvertStringsNulls(std::wstring * pStr, TCHAR chAnchor = L'|');
	static void ConvertMultiPartPathIntoComponents(std::wstring & strMultiPartPath, std::vector<std::wstring>& arrOutComponents, LPCTSTR pStrMultiFilePathSeparator = L"|");
	static UINT_PTR CALLBACK _OFNHookProcOldStyle(HWND   hdlg, UINT   uiMsg, WPARAM wParam, LPARAM lParam);
	static RES_YES_NO_ERR GetOpenFilePathWithDialog(std::wstring * pOutStrPaths = NULL, HWND hParentWnd = NULL, DWORD dwFlags = OFN_FILEMUSTEXIST, LPCTSTR pStrFilter = L"All Files (*.*)|*.*|", int* pnFilterIndex = NULL, LPCTSTR pStrInitialFolder = NULL, LPCTSTR pStrTitle = NULL, LPCTSTR pStrMultiFilePathSeparator = L"|");
	static RES_YES_NO_ERR GetSaveFilePathWithDialog(std::wstring* pOutStrPath, HWND hParentWnd, DWORD dwFlags = OFN_OVERWRITEPROMPT, LPCTSTR pStrDefaultExt = L"txt", LPCTSTR pStrFilter = L"All Files (*.*)|*.*|", int* pnFilterIndex = NULL, LPCTSTR pStrTitle = NULL, LPCTSTR pStrFileName = NULL, LPCTSTR pStrInitialFolder = NULL);
	static RES_YES_NO_ERR _open_save_dlg_func(BOOL bSaveDlg, std::wstring * pOutStrPath, HWND hParentWnd, DWORD dwFlags, LPCTSTR pStrDefaultExt, LPCTSTR pStrFilter, int * pnFilterIndex, LPCTSTR pStrTitle, LPCTSTR pStrFileName, LPCTSTR pStrInitialFolder, LPCTSTR pStrMultiFilePathSeparator);
	static BOOL SaveRegConfigFileContents(LPCTSTR pStrFilePath, std::vector<CUSTOM_REG_VALUE>& arrData);
	void OnMenuFileSaveConfig();
private:
	RES_YES_NO_ERR _requestElevationAndRunSelf(int & nOSError, LPCTSTR pStrCmdRun, const void* pValue, size_t szcbValue, DWORD dwmsTimeout = (3 * 1000));
	static HRESULT _i2b_ConvertBufferToPARGB32(HPAINTBUFFER hPaintBuffer, HDC hdc, HICON hicon, SIZE & sizIcon);
	static HRESULT _i2b_Create32BitHBITMAP(HDC hdc, const SIZE * psize, void ** ppvBits, HBITMAP * phBmp);
	static bool _i2b_HasAlpha(ARGB * pargb, SIZE & sizImage, int cxRow);
	static void _i2b_InitBitmapInfo(BITMAPINFO * pbmi, ULONG cbInfo, LONG cx, LONG cy, WORD bpp);
	static HRESULT _i2b_ConvertToPARGB32(HDC hdc, ARGB * pargb, HBITMAP hbmp, SIZE & sizImage, int cxRow);
	BOOL OnDragAndDrop_IsAllowed(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER* pInfo);
	void OnDragAndDrop_Began(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER* pInfo, BOOL* pbSetFocus, DWORD grfKeyState, POINTL pt, DWORD* pdwEffect);
	void OnDragAndDrop_Pending(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER* pInfo, DWORD grfKeyState, POINTL pt, DWORD* pdwEffect);
	void OnDragAndDrop_Ended(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER* pInfo);
	BOOL OnDragAndDrop_DropData(DRAG_ITEM_TYPE dragType, DRAG_N_DROP_REGISTER* pInfo, DRAGGED_ITEMS* pDroppedItems, DWORD grfKeyState, POINTL pt, DWORD* pdwEffect, DRAG_N_DROP_DROP_FLAGS dropFlags);
private:
	void OnMenuFileOpenConfig();
	BOOL LoadRegConfigFile(LPCTSTR pStrFilePath);
	void OnDropFile(std::wstring* p_strFilePath);
	BOOL PowerOp(POWER_OP powerOp);
	static LPCTSTR translatePowerOpName(POWER_OP powerOp, LPCTSTR& pStrSubOption, DWORD& dwPowerOpFlags);
	BOOL performPowerOp(POWER_OP powerOp);
	static BOOL GetIconSize(HICON hIcon, SIZE * pOutSz = NULL);
	static HBITMAP IconToBitmapPARGB32(HICON hIcon);
	void ReloadResources();
	static RES_YES_NO_ERR IsRebootWithoutUpdatesEnabled(BOOL bCheckWritable = TRUE);
	static BOOL DeleteValueAndEmptyKeyFromSystemRegistry(HKEY hIniKey, BOOL bWOW64, LPCTSTR lpSubKey, LPCTSTR lpKeyValue);
//	static BOOL SetRegKeyValueWithDACL(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData, int* pnOutSpecErr = NULL);
};

