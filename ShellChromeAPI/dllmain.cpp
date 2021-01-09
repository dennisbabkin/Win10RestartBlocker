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


// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")

#include <strsafe.h>
#include <stdlib.h>

#include <winreg.h>

#include "event_log_reporter.h"



//#define SHOW_DIAGNOSTIC			//Uncomment this to show diagnostic messages




BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	BOOL bResult = TRUE;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		//Don't need extra calls to DllMain here
		::DisableThreadLibraryCalls(hModule);

	}
	break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return bResult;
}






extern "C" UINT WINAPI Shell_RequestShutdown(UINT nValue)
{
	//'nValue' = will be 1 if called from usosvc
	//RETURN:
	//		= Doen't matter
	//		  (There will be a 2 minute delay in usosvc when this function returns)
	UINT nRes = 0;

	//This is the exported function
	#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)

	//EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(542, L"Shell_RequestShutdown, v=%d", nValue);

	//Magic input value
	if(nValue == 1)
	{

		//Read settings
		APP_SETTINGS settings(TRUE);

		//See how often are we allowed to show the reboot UI
		//INFO: If it's shown too often the reboot will be blocked automatically
		UINT nMinShowDelayMin = 0;
		if(settings.UI_ShowType == UI_SH_T_SHOW_EVERY_N_MINS)
		{
			nMinShowDelayMin = settings.nUI_ShowVal1;

			//Can't be more than 7 days
			if(nMinShowDelayMin > MAX_ALLOWED_DONT_SHOW_POPUP_IN_MINS)
			{
				nMinShowDelayMin = MAX_ALLOWED_DONT_SHOW_POPUP_IN_MINS;
			}
		}



		DWORD dwActiveSession = ::WTSGetActiveConsoleSessionId();
		if(dwActiveSession != -1)
		{
			//We have a user session
			BOOL bAllowToReboot = FALSE;

			DWORD dwResponse = 0;
			FILETIME ftUtc = {};
			FILETIME ftLastUiUtc = {};
			DWORD dwchLnTitle;
			DWORD dwchLnMsg;
			DWORD dwR;
			DWORD dwType;
			DWORD dwcbSzData;
			BOOL bShowUI = TRUE;
			WCHAR buffTitle[256];
			WCHAR buffMsg[1024];
			WCHAR buffActiveSessName[128];
			HRESULT hr;


			//Get session name
			LPTSTR pstrActiveSessName = NULL;
			DWORD dwDummy;
			if (::WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, dwActiveSession, WTSUserName, &pstrActiveSessName, &dwDummy))
			{
				//Copy name
				if (FAILED(hr = ::StringCchCopy(buffActiveSessName, _countof(buffActiveSessName), pstrActiveSessName)))
				{
					buffActiveSessName[_countof(buffActiveSessName) - 1] = 0;
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(683, L"hr=0x%X", hr);
				}

				//Free mem
				::WTSFreeMemory(pstrActiveSessName);
			}
			else
			{
				//Failed
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(682, L"s=%d", dwActiveSession);
				buffActiveSessName[0] = 0;
			}


			//Only if this app is enabled
			if(!settings.bBlockEnabled)
			{
				//Block is not enabled -- thus always allow
				EVENT_LOG_REPORTS::ReportEventLogMsgInfo_WithFormat(L"Block is disabled, will allow reboot for session (%d):\"%s\".", dwActiveSession, buffActiveSessName);

				goto lbl_reboot_msg;
			}


			if(settings.bAllowSleep)
			{
				//Allow going into idle sleep mode for this thread (in case it was blocked)
				EXECUTION_STATE prevState = ::SetThreadExecutionState(ES_CONTINUOUS);

				EVENT_LOG_REPORTS::ReportEventLogMsgInfo_WithFormat(L"Allowed idle sleep for thread ID=%u, session (%d):\"%s\". Previous ExecState=0x%x", 
					::GetCurrentThreadId(), dwActiveSession, buffActiveSessName, prevState);
			}


			//Current UTC time
			::GetSystemTimeAsFileTime(&ftUtc);

			#define VAL_NAME_LAST_UI L"UI_LastShown"

			if(nMinShowDelayMin != 0)
			{
				//When did we show it last time?
				dwcbSzData = sizeof(ftLastUiUtc);
				dwType = 0;
				dwR = ::RegGetValue(HKEY_LOCAL_MACHINE, REG_KEY_SHARED, VAL_NAME_LAST_UI, RRF_RT_REG_QWORD, &dwType, &ftLastUiUtc, &dwcbSzData);
				if(dwR == ERROR_SUCCESS &&
					dwcbSzData == sizeof(ftLastUiUtc) &&
					dwType == REG_QWORD)
				{
					//Time elapsed in minutes
					double fElapsedMin = (*(LONGLONG*)&ftUtc - *(LONGLONG*)&ftLastUiUtc) / (10000000.0 * 60.0);

					if(fElapsedMin >= 0 &&
						fElapsedMin < nMinShowDelayMin)
					{
						//Don't show UI -- it's too soon since it was shown last
						bShowUI = FALSE;

						EVENT_LOG_REPORTS::ReportEventLogMsgInfo_WithFormat(
							L"Will not show reboot UI: elapsed only %.2f min since last showing over allowed %u min minimum. Will silently block reboot. Session (%d):\"%s\".", 
							fElapsedMin, nMinShowDelayMin, dwActiveSession, buffActiveSessName);
					}
				}
			}



			if(bShowUI)
			{
				//Remember when we're showing the UI
				dwR = ::RegSetKeyValue(HKEY_LOCAL_MACHINE, REG_KEY_SHARED, VAL_NAME_LAST_UI, REG_QWORD, &ftUtc, sizeof(ftUtc));
				if(dwR != ERROR_SUCCESS)
				{
					//Failed
					::SetLastError(dwR);
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_WithFormat(L"Failed to set last UI time for session (%d):\"%s\"", dwActiveSession, buffActiveSessName);
				}


				::StringCchCopy(buffTitle, _countof(buffTitle), L"Reboot Attempt - " MAIN_APP_NAME);

#define MAIN_MSG L"Windows is attempting to RESTART YOUR COMPUTER.\n\n" \
				L"Do you want to allow it now?\n\n" \
				L"IMPORTANT: Before allowing it, make sure to save all your work! Otherwise, if you're not ready, click No."

#ifdef SHOW_DIAGNOSTIC
				//Diagnostic output
				DWORD dwPid = ::GetCurrentProcessId();
				WCHAR buffProcPath[MAX_PATH] = {};
				::GetModuleFileName(NULL, buffProcPath, _countof(buffProcPath));
				buffProcPath[_countof(buffProcPath) - 1] = 0;

				::StringCchPrintf(buffMsg, _countof(buffMsg),
					MAIN_MSG
					L"\n\n"
					L"PID: %d\n"
					L"Proc: %s"
					,
					dwPid,
					buffProcPath
					);
#else
				//Release/production build
				::StringCchCopy(buffMsg, _countof(buffMsg),
					MAIN_MSG
					);
#endif

				dwchLnTitle = (DWORD)wcslen(buffTitle) * sizeof(WCHAR);
				dwchLnMsg = (DWORD)wcslen(buffMsg) * sizeof(WCHAR);

				//Show message box to the user
				if(!::WTSSendMessage(WTS_CURRENT_SERVER_HANDLE, 
					dwActiveSession, 
					buffTitle,
					dwchLnTitle,
					buffMsg,
					dwchLnMsg,
					MB_YESNOCANCEL | MB_DEFBUTTON2 | MB_SYSTEMMODAL | (settings.bUI_AllowSound ? MB_ICONWARNING : 0),
					settings.nUI_TimeOutSec,
					&dwResponse,
					TRUE))
				{
					//Failed
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_WithFormat(L"Main WTSSendMessage failed: ln1=%d, ln2=%d, session (%d):\"%s\"", 
						dwchLnTitle, dwchLnMsg, dwActiveSession, buffActiveSessName);
				}
			}



			//What was the choice?
			if(dwResponse == IDYES)
			{
				//User chose to allow to reboot
				EVENT_LOG_REPORTS::ReportEventLogMsgInfo_WithFormat(L"User chose to reboot, session (%d):\"%s\"", dwActiveSession, buffActiveSessName);

lbl_reboot_msg:
				//We will allow reboot to proceed
				bAllowToReboot = TRUE;

				//See if we need to show UI
				//INFO: Don't do it if the session is already ending
				if(!::GetSystemMetrics(SM_SHUTTINGDOWN))
				{
					//Get current time
					SYSTEMTIME st = {};
					::GetLocalTime(&st);
					FILETIME ft = {};
					::SystemTimeToFileTime(&st, &ft);

					//Calculate local time 2 minutes from now -- this is what Sleep(120000) does in usosvc
					const ULONG uiPendingTimeoutSec = 2 * 60;
					*(ULONGLONG*)&ft += uiPendingTimeoutSec * 10000000LL;
					::FileTimeToSystemTime(&ft, &st);

					//Format time when reboot will take place for the user
					WCHAR buffWhen[128] = {};
					::GetTimeFormatEx(LOCALE_NAME_SYSTEM_DEFAULT, 0, &st, NULL, buffWhen, _countof(buffWhen));
					buffWhen[_countof(buffWhen) - 1] = 0;

					//Prep the message to the user
					::StringCchCopy(buffTitle, _countof(buffTitle), L"Pending Reboot!");
					::StringCchPrintf(buffMsg, _countof(buffMsg),
						L"Your computer will restart at %s ..."
						,
						buffWhen
					);

					dwchLnTitle = (DWORD)wcslen(buffTitle) * sizeof(WCHAR);
					dwchLnMsg = (DWORD)wcslen(buffMsg) * sizeof(WCHAR);

					//Show notification to the user when reboot will take place (but don't wait for it!)
					DWORD dwDummy;
					if (!::WTSSendMessage(WTS_CURRENT_SERVER_HANDLE,
						dwActiveSession,
						buffTitle,
						dwchLnTitle,
						buffMsg,
						dwchLnMsg,
						MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL,
						uiPendingTimeoutSec - 2,		//Hide this pop-up 2 seconds before the reboot because of the bug in this API that may show this popup again when rebooting begins ...
						&dwDummy,
						FALSE))
					{
						//Failed to show
						EVENT_LOG_REPORTS::ReportEventLogMsgERROR_WithFormat(L"When-will-reboot WTSSendMessage failed: ln1=%d, ln2=%d, session (%d):\"%s\"",
							dwchLnTitle, dwchLnMsg, dwActiveSession, buffActiveSessName);
					}
				}
				else
				{
					EVENT_LOG_REPORTS::ReportEventLogMsgWARNING_WithFormat(L"When-will-reboot WTSSendMessage was skipped as the session (%d):\"%s\" is already logging off...", 
						dwActiveSession, buffActiveSessName);
				}

			}
			else if(dwResponse == IDTIMEOUT)
			{
				//Timed out
				EVENT_LOG_REPORTS::ReportEventLogMsgWARNING_WithFormat(L"Message box timed out, will block reboot automatically for session (%d):\"%s\"", 
					dwActiveSession, buffActiveSessName);
			}
			else if(dwResponse != IDNO &&
				dwResponse != IDCANCEL &&
				dwResponse != 0)
			{
				//Some unexpected response
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_WithFormat(L"Received bad response: %d for session (%d):\"%s\"", dwResponse, dwActiveSession, buffActiveSessName);
			}


			//See if we're allowing reboot to go on
			if(!bAllowToReboot)
			{
				//See if user consented to it
				BOOL bUserConsent = 
					dwResponse == IDNO ||
					dwResponse == IDCANCEL;

				//Block reboot by removing the privilege
				//INFO: Without it, the shutdown API will fail.
				if(AUX_FUNCS::AdjustPrivilege(SE_SHUTDOWN_NAME, FALSE, NULL))
				{
					//All good!
					EVENT_LOG_REPORTS::ReportEventLogMsgInfo_WithFormat(L"Successfully blocked reboot %s for session (%d):\"%s\"", 
						bUserConsent ? L"after user consent" : L"automatically",
						dwActiveSession, buffActiveSessName);
				}
				else
				{
					//Failed
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_WithFormat(L"Failed to remove shutdown-privilege for session (%d):\"%s\", system will probably reboot now :(", 
						dwActiveSession, buffActiveSessName);
				}
			}
		}
		else
			EVENT_LOG_REPORTS::ReportEventLogMsgWARNING_WithFormat(L"No active session, ID=%d. Will allow reboot ...", dwActiveSession);
	}
	else
	{
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_WithFormat(L"Bad input param: %d", nValue);
	}

	return nRes;
}




UINT WINAPI TestCorrectDll(int)
{
	//RETURN:
	//		= Always returns

	//This is the exported function
	#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)

	return SHELL_CHROME_API_ID_STAMP;
}