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


// Win10RestartBlockerUI.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "Win10RestartBlockerUI.h"
#include "CMainWnd.h"


//Enable visual themes for our UI by adding a manifest
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")



int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);


	//Check if this is Windows 10
	RTL_OSVERSIONINFOEXW ver;
	if(AUX_FUNCS::CheckWindowsVersion(&ver))
	{
		if(ver.dwMajorVersion < 10)
		{
			//Can't start on a non-Windows 10 version of the OS
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(511, L"Bad Windows version: %d.%d.%d", ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber);
			ASSERT(NULL);

			return -2;
		}
	}
	else
	{
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(510);
		ASSERT(NULL);
	}


	//Check OS bitness
	//		= RYNE_NO if 32-bit OS
	//		= RYNE_YES if 64-bit OS
	//		= RYNE_ERROR if error
	RES_YES_NO_ERR res64bit = AUX_FUNCS::Is64BitOS();
	if (res64bit == RYNE_ERROR)
	{
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(601, L"Unknown bitness");
		ASSERT(NULL);

		return -3;
	}
#ifdef _M_X64
	else if (res64bit != RYNE_YES)
	{
		//OS must be 64-bit
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(602, L"Incorrect bitness");
		ASSERT(NULL);

		return -3;
	}
#else
	else if (res64bit != RYNE_NO)
	{
#ifndef _DEBUG
		//OS must be 32-bit
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(603, L"Incorrect bitness");
		ASSERT(NULL);

		return -3;
#endif
	}
#endif


	//Show main window
	CMainWnd mainWnd(hInstance);
	CMD_LINE_PARSE_RESULTS clpr = mainWnd.ParseCommandLine();
	if(!mainWnd.CreateMainWnd((clpr & CLPR_AUTO_SAVE_ELEVATED) ? FALSE : TRUE))
	{
		//Failed to show window
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(503, L"CRITICAL: Failed to open main window");
		ASSERT(NULL);
		::MessageBeep(MB_ICONERROR);
	}


	return (int)mainWnd.dwExitCode;
}


