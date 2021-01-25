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


// TestShellChromeAPI.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

#include "..\ShellChromeAPI\SharedDefs.h"





int main()
{
//    std::cout << "Hello World!\n";

	::GdiFlush();

	if(AUX_FUNCS::AdjustPrivilege(SE_SHUTDOWN_NAME, TRUE, NULL))
	{
		HMODULE hMod = LoadLibrary(VULN_SHELL_DLL_FILE_NAME);
		//HMODULE hMod = LoadLibraryExW(VULN_SHELL_DLL_FILE_NAME, (HANDLE)0x0, 0x800);

		if(hMod)
		{
			UINT (WINAPI *pfnShell_RequestShutdown)(UINT);

			(FARPROC&)pfnShell_RequestShutdown = GetProcAddress(hMod, "Shell_RequestShutdown");
			if(pfnShell_RequestShutdown)
			{
				int rr = pfnShell_RequestShutdown(1);

				//if(rr)
				//{
				//	DWORD dw = 0;	//InitiateShutdownW((LPWSTR)0x0,(LPWSTR)0x0,0, 0x2087, 0x80020010);
				//	if(dw != 0)
				//	{
				//		::MessageBox(NULL, L"Error", L"error", MB_ICONERROR | MB_OK);
				//	}
				//	else
				//	{
				//		::MessageBox(NULL, L"OK", L"ok", MB_ICONERROR | MB_OK);
				//	}
				//}
			}

			::FreeLibrary(hMod);
		}
	}

}


