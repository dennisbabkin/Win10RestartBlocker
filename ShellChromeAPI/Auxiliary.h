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
#pragma once

#include <stdlib.h>
#include <strsafe.h>
#include <sddl.h>
#include <aclapi.h>

#include <string>
#include <vector>

#include <assert.h>

#include <algorithm>
#include <functional>
#include <cctype>

#include <shellapi.h>
#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")


#include "SharedDefs.h"




//Custom assertion definitions
#ifdef _DEBUG
#define ASSERT(f) if(!(f))\
{\
		if(::IsDebuggerPresent()) { ::DebugBreak(); } \
        char __buffer123456789[256*4];\
        ::StringCchPrintfA(__buffer123456789, _countof(__buffer123456789), "ASSERTION!!!\nFile: %s\nLine: %d\nGetLastError() = %d", __FILE__, __LINE__, ::GetLastError());\
        FatalAppExitA(0, __buffer123456789);\
}
#else
#define ASSERT(f) ((void)0)
#endif

#ifdef _DEBUG
#define VERIFY(f) ASSERT(f)
#else
#define VERIFY(f) ((void)(f))
#endif



//Trace outout
#ifdef _DEBUG
#define TRACE(s, ...) \
	{ WCHAR __dbg_buff[1024]; if(SUCCEEDED(::StringCchPrintf(__dbg_buff, _countof(__dbg_buff), s, __VA_ARGS__))) { ::OutputDebugString(__dbg_buff);} else ASSERT(NULL);}
#define TRACEA(s, ...) \
	{ char __dbg_buffA[1024]; if(SUCCEEDED(::StringCchPrintfA(__dbg_buffA, _countof(__dbg_buffA), s, __VA_ARGS__))) { ::OutputDebugStringA(__dbg_buffA);} else ASSERT(NULL);}
#else
#define TRACE(s, ...) ((void)0)
#define TRACEA(s, ...) ((void)0)
#endif


#ifndef RES_YES_NO_ERR
enum RES_YES_NO_ERR {
	RYNE_YES = 1,
	RYNE_NO = 0,
	RYNE_ERROR = -1,
};
#endif



enum CUST_REG_VAL_TYPE {
	CRVT_None,

	CRVT_INTEGER,
	CRVT_STRING,
};


struct CUSTOM_REG_VALUE {
	CUST_REG_VAL_TYPE type;

	std::wstring strName;
	LONGLONG uiVal;					//Valid only if 'type' == CRVT_INTEGER
	std::wstring strVal;			//Valid only if 'type' == CRVT_STRING

	CUSTOM_REG_VALUE()
		: type(CRVT_None)
		, uiVal(0)
	{
	}

	void EmptyIt()
	{
		type = CRVT_None;

		strName.clear();
		uiVal = 0;
		strVal.clear();
	}

	RES_YES_NO_ERR IsValue32BitInteger(BOOL bSigned) const
	{
		//'bSigned' = TRUE to treat it as a signed integer, FALSE - as unsigned
		//RETURN:
		//		RYNE_YES = current value can fit into 32-bit integer
		//		RYNE_NO = current value cannot fit into 32-bit integer, and must use 64-bit integer
		//		RYNE_ERROR = current value is not an integer

		if (type == CRVT_INTEGER)
		{
			if (bSigned)
				return (LONGLONG)uiVal >= INT_MIN && (LONGLONG)uiVal <= INT_MAX ? RYNE_YES : RYNE_NO;
			else
				return (ULONGLONG)uiVal <= UINT_MAX ? RYNE_YES : RYNE_NO;
		}

		return RYNE_ERROR;
	}

	std::wstring toValueString() const
	{
		//RETURN:
		//		= String representation of this value
		std::wstring str;

		switch (type)
		{
		case CRVT_INTEGER:
		{
			WCHAR buff[128];
			buff[0] = 0;
			WCHAR* pEnd = NULL;
			RES_YES_NO_ERR res64bit = IsValue32BitInteger(TRUE);
			if (res64bit != RYNE_ERROR)
			{
				HRESULT hr;
				if (res64bit == RYNE_YES)
				{
					//32-bit value
					int nVal = (int)uiVal;
					hr = ::StringCchPrintfEx(buff, _countof(buff), &pEnd, NULL, STRSAFE_IGNORE_NULLS | STRSAFE_NO_TRUNCATION, L"%d", nVal);
				}
				else
				{
					//64-bit value
					hr = ::StringCchPrintfEx(buff, _countof(buff), &pEnd, NULL, STRSAFE_IGNORE_NULLS | STRSAFE_NO_TRUNCATION, L"%I64d", uiVal);
				}

				if (SUCCEEDED(hr))
				{
					assert(pEnd > buff);
					str.assign(buff, pEnd - buff);
				}
				else
				{
					::SetLastError((int)hr);
					assert(NULL);
				}
			}
			else
			{
				::SetLastError(ERROR_BAD_FORMAT);
				assert(NULL);
			}
		}
		break;

		case CRVT_STRING:
		{
			//Use string as-is
			str = strVal;
		}
		break;

		default:
		{
			//Must be no value
			::SetLastError(ERROR_EMPTY);
			assert(NULL);
		}
		break;
		}

		return str;
	}
};



enum VER_CMP_RES {
	VCRES_ERROR = -1,				//Error
	VCRES_EQUAL = 0,				//Both versions are equal
	VCRES_V1_LESS_THAN_V2,
	VCRES_V1_GREATER_THAN_V2,
};



struct SECURITY_DESCRIPTOR_W_LABEL {
	SECURITY_DESCRIPTOR sd;

	struct : public ::ACL
	{
		ACE_HEADER Ace;
		ACCESS_MASK Mask;
		SID Sid;
	} Label;

	SECURITY_DESCRIPTOR_W_LABEL()
	{
		memset(this, 0, sizeof(*this));
	}
};




struct AUX_FUNCS
{
	static int GetLastErrorNotNULL(int nFallbackErrorCode = ERROR_GEN_FAILURE)
	{
		//RETURN:
		//		= Last error code from GetLastError() if it's not 0, or
		//		= nFallbackErrorCode value
		int nErr = ::GetLastError();
		return nErr != 0 ? nErr : nFallbackErrorCode;
	}

	static RES_YES_NO_ERR Is64BitOS()
	{
		//Checks if the OS is 32-bit or 64-bit
		//RETURN:
		//		= RYNE_NO if 32-bit OS
		//		= RYNE_YES if 64-bit OS
		//		= RYNE_ERROR if error

		SYSTEM_INFO si;

		//Erase with -1, since 0 has a meaning below
		memset(&si, -1, sizeof(si));

		::GetNativeSystemInfo(&si);

		if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		{
			//64-bit OS
			return RYNE_YES;
		}
		else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		{
			//32-bit OS
			return RYNE_NO;
		}

		return RYNE_ERROR;
	}

	static BOOL AdjustPrivilege(LPCTSTR pPrivilegeName, BOOL bEnable, HANDLE hProcess)
	{
		//Tries to adjust the 'pPrivilegeName' privilege for the process
		//'bEnable' = TRUE to enable, FALSE to disable a privilege
		//'hProcess' = Process to adjust privilege for, or NULL for current process
		//RETURN: - TRUE if done;
		//		  - FALSE if privileges not adjusted (check GetLastError() for details)
		BOOL bRes = FALSE;
		int nOSError = NO_ERROR;

		HANDLE hToken; 
		TOKEN_PRIVILEGES tkp; 

		//Get a token for this process. 
		if(!OpenProcessToken(hProcess ? hProcess : GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
			return FALSE; 

		//Get the LUID for the shutdown privilege. 
		if(LookupPrivilegeValue(NULL, pPrivilegeName, &tkp.Privileges[0].Luid))
		{
			//One privilege to set
			tkp.PrivilegeCount = 1;  
			tkp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0; 

			//Adjust it now
			bRes = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
			nOSError = GetLastError();
			if(bRes)
			{
				//See if no error
				if(nOSError != ERROR_SUCCESS)
					bRes = FALSE;
			}
		}
		else
		{
			//Failed
			nOSError = ::GetLastError();
		}

		//Close handle
		CloseHandle(hToken);

		::SetLastError(nOSError);
		return bRes;
	}


	static BOOL WriteSettingsInt32(LPCTSTR pStrValueName, UINT nValue)
	{
		//Save int32 into settings
		//'pStrValueName' = name of Registry value to save into
		//'nValue' = value to save
		//RETURN:
		//		= TRUE if success
		//		= FALSE if failed (check GetLastError() if error)

		DWORD dwR = ::RegSetKeyValue(HKEY_LOCAL_MACHINE, REG_KEY_SETTINGS, pStrValueName, REG_DWORD, &nValue, sizeof(nValue));

		::SetLastError(dwR);
		return dwR == ERROR_SUCCESS;
	}


	static UINT ReadSettingsInt32(LPCTSTR pStrValueName, UINT nDefault, BOOL* pbOutSuccess = NULL)
	{
		//Read int32 from settings
		//'pStrValueName' = name of Registry value to read
		//'nDefault' = default value if none available, or if error reading
		//'pbOutSuccess' = if not NULL, receives TRUE if success
		//RETURN:
		//		= Value read, or default
		UINT nResult = nDefault;
		int nOSError = 0;

		BYTE data[128] = {};
		DWORD dwcbSzData = sizeof(data);
		DWORD dwType = 0;
		DWORD dwR = ::RegGetValue(HKEY_LOCAL_MACHINE, REG_KEY_SETTINGS, pStrValueName, RRF_RT_ANY | RRF_ZEROONFAILURE, &dwType, data, &dwcbSzData);
		if(dwR == ERROR_SUCCESS)
		{
			if(dwType == REG_DWORD)
			{
				if(dwcbSzData == sizeof(DWORD))
				{
					nResult = *(UINT*)data;
				}
				else
					nOSError = 1462;
			}
			else if(dwType == REG_QWORD)
			{
				if(dwcbSzData == sizeof(LONGLONG))
				{
					LONGLONG ui = *(LONGLONG*)data;
					nResult = (INT)(ui);
					if(ui < INT_MIN || ui > INT_MAX)
					{
						nOSError = 2289;
					}
				}
				else
					nOSError = 1462;
			}
			else if(dwType == REG_SZ ||
				dwType == REG_EXPAND_SZ)
			{
				*(WCHAR*)&data[sizeof(data) - sizeof(WCHAR)] = (WCHAR)0;		//Safety null

				LONGLONG ui = 0;
				if(swscanf_s((const WCHAR*)data, L"%I64d", &ui) == 1)
				{
					nResult = (INT)(ui);
					if (ui < INT_MIN || ui > INT_MAX)
					{
						nOSError = 2289;
					}
				}
				else
					nOSError = 160;
			}
		}
		else
			nOSError = dwR;

		::SetLastError(nOSError);
		return nResult;
	}

	static BOOL CreateHKLMSharedKey()
	{
		//Create Registry shared key that can be read/written to from a service and from a user account
		//RETURN:
		//		= TRUE if success
		//		= FALSE if failed (check GetLastError() if error)
		BOOL bRes = FALSE;
		int nOSError = 0;

		//Create the key first
		HKEY hKey = NULL;
		DWORD dwR = ::RegCreateKeyEx(HKEY_LOCAL_MACHINE, REG_KEY_SHARED, NULL, NULL, 0, KEY_WRITE | READ_CONTROL | WRITE_DAC, NULL, &hKey, NULL);
		if(dwR == ERROR_SUCCESS)
		{
			//Set additional ACL for sharing for this folder
			if(MakeRegKeyShared(hKey))
			{
				//Done
				bRes = TRUE;
			}
			else
				nOSError = dwR;

			//Close it
			::RegCloseKey(hKey);
		}
		else
			nOSError = dwR;

		::SetLastError(nOSError);
		return bRes;
	}

	static BOOL MakeRegKeyShared(HKEY hKey, LPCTSTR pStrKey = NULL)
	{
		//Make 'hKey' or 'pStrKey' registry key to be accessible by everyone for setting values
		//'hKey' = if not NULL, it must be the key opened with READ_CONTROL | WRITE_DAC access rights
		//'pStrKey' = used only if 'hKey' is NULL
		//RETURN:
		//		= TRUE if success
		//		= FALSE if failed (check GetLastError() if error)
		BOOL bRes = FALSE;
		int nOSError = 0;

		//Create security descriptor:
		//
		//	https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings
		//
		//	- D  => DACL
		//
		//	- AI => SDDL_AUTO_INHERITED
		//
		//	- A  => "Allowed Permissions":
		//
		//	- CI => SDDL_CONTAINER_INHERIT
		//
		//	- CC => "Query value"
		//	- DC => "Set value"
		//	- SW => "Enumerate subkeys"
		//	- RP => "Notify"
		//	- RC => "Read Control"
		//
		//	https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-strings
		//
		//	- WD => SDDL_EVERYONE

		PSECURITY_DESCRIPTOR pSD = NULL;
		if(::ConvertStringSecurityDescriptorToSecurityDescriptor(
			L"D:AI(A;CI;CCDCSWRPRC;;;WD)",
			SDDL_REVISION_1, &pSD, NULL))
		{
			//Open the key to set descriptor
			DWORD dwR;
			BOOL bOpenedKey = TRUE;

			if (!hKey)
			{
				//Open our needed key
				dwR = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE, pStrKey, 0, READ_CONTROL | WRITE_DAC, &hKey);
			}
			else
			{
				//Key was provided from outside
				bOpenedKey = FALSE;
				dwR = ERROR_SUCCESS;
			}

			if(dwR == ERROR_SUCCESS)
			{
				//Get DACL from the key
				PSECURITY_DESCRIPTOR pOldSD = NULL;
				PACL pOldDACL = NULL;
				dwR = ::GetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pOldSD);
				if(dwR == ERROR_SUCCESS)
				{
					//Get DACL from the SD that we've created
					BOOL bHaveDACL = -1;
					BOOL bDACLDefaulted = -1;
					PACL pDACL = NULL;
					if(::GetSecurityDescriptorDacl(pSD, &bHaveDACL, &pDACL, &bDACLDefaulted))
					{
						//We need our first and only ACE
						void* pNewACE = NULL;
						if(::GetAce(pDACL, 0, &pNewACE))
						{
							//Get out ACE size
							DWORD dwcbNewACE = ((PACE_HEADER)pNewACE)->AceSize;

							HANDLE hHeap = ::GetProcessHeap();



							//Get old ACL info
							ACL_SIZE_INFORMATION asi = {};
							if(::GetAclInformation(pOldDACL, &asi, sizeof(asi), AclSizeInformation))
							{
								//Get size of the new ACL
								DWORD dwcbSzNewACL = asi.AclBytesInUse + dwcbNewACE;


								//Build a new DACL by combining old ACEs and a new one

								//Reserve mem
								PACL pNewDACL = (PACL)::HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwcbSzNewACL);
								if(pNewDACL)
								{
									//Create a new ACL
									if(::InitializeAcl(pNewDACL, dwcbSzNewACL, ACL_REVISION))
									{
										//Add our ace first
										if(::AddAce(pNewDACL, ACL_REVISION, MAXDWORD, pNewACE, dwcbNewACE))
										{
											//Then add existing ACEs
											BOOL bAddedOK = TRUE;
											BOOL bAlreadyExists = FALSE;
											void* pACE = NULL;

											for(DWORD a = 0; a < asi.AceCount; a++)
											{
												//Read ACE
												if(::GetAce(pOldDACL, a, &pACE))
												{
													//See if ACE is the same
													DWORD dwcbSzACE = ((PACE_HEADER)pACE)->AceSize;
													if(dwcbSzACE == dwcbNewACE &&
														memcmp(pNewACE, pACE, dwcbSzACE) == 0)
													{
														//Same ACE already exists, no need to do anything else
														bAlreadyExists = TRUE;
														break;
													}

													if(!::AddAce(pNewDACL, ACL_REVISION, MAXDWORD, pACE, dwcbSzACE))
													{
														//Failed
														bAddedOK = FALSE;
														nOSError = ::GetLastError();
														break;
													}
												}
												else
												{
													//Failed
													bAddedOK = FALSE;
													nOSError = ::GetLastError();
													break;
												}
											}

											if(bAddedOK)
											{
												//Only if we don't have it already
												if(!bAlreadyExists)
												{
													//Create new SD
													PSECURITY_DESCRIPTOR psdNew = NULL;
													DWORD dwSidSize = 0, dwSdSizeNeeded = 0;
													SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
													if(!::GetUserObjectSecurity(hKey, &si, psdNew, dwSidSize, &dwSdSizeNeeded) &&
														::GetLastError() == ERROR_INSUFFICIENT_BUFFER)
													{
														psdNew = (PSECURITY_DESCRIPTOR)::HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSdSizeNeeded);
														if(psdNew)
														{
															//Init new SD
															if(::InitializeSecurityDescriptor(psdNew,SECURITY_DESCRIPTOR_REVISION))
															{
																//Set new DACL in the new SD
																if(::SetSecurityDescriptorDacl(psdNew, TRUE, pNewDACL, FALSE))
																{


																	//Set new DACL back to the key
																	if(::SetKernelObjectSecurity(hKey, DACL_SECURITY_INFORMATION, psdNew))
																	{
																		//Done
																		bRes = TRUE;
																	}
																	else
																		nOSError = ::GetLastError();

																}
																else
																	nOSError = ::GetLastError();

															}
															else
																nOSError = ::GetLastError();


															//Free mem
															::HeapFree(hHeap, 0, psdNew);
															psdNew = NULL;
														}
														else
															nOSError = ERROR_OUTOFMEMORY;
													}
													else
														nOSError = ::GetLastError();
												}
												else
												{
													//All good
													bRes = TRUE;
												}
											}
										}
										else
											nOSError = ::GetLastError();
									}
									else
										nOSError = ::GetLastError();


									//Free mem
									::HeapFree(hHeap, 0, pNewDACL);
									pNewDACL = NULL;
								}
								else
									nOSError = ERROR_OUTOFMEMORY;
								


							}
							else
								nOSError = ::GetLastError();
						}
						else
							nOSError = ::GetLastError();
					}
					else
						nOSError = ::GetLastError();
				}
				else
					nOSError = dwR;


				//Free old SD
				if(pOldSD)
				{
					::LocalFree(pOldSD);
					pOldSD = NULL;
				}

				if (bOpenedKey)
				{
					//Close key
					::RegCloseKey(hKey);
				}
			}
			else
				nOSError = dwR;
		}
		else
			nOSError = ::GetLastError();

		if(pSD)
		{
			//Free memory
			::LocalFree(pSD);
			pSD = NULL;
		}

		::SetLastError(nOSError);
		return bRes;
	}



	static HANDLE CreateSharedEvent(LPCTSTR pStrName, BOOL bAllowModify, BOOL bAutoReset = FALSE, BOOL bInitialState = FALSE)
	{
		//Open event that can be shared among several running instances
		//'pStrName' = unique name of the event
		//'bAllowModify' = FALSE for read-only access to the event (this includes: synchronization and reading it signaled state. TRUE to also allow to signal this event
		//'bAutoReset' = TRUE for event to auto-reset, FALSE for manual reset event
		//'bInitialState' = TRUE if event is initially signaled
		//RETURN:
		//		= Event handle - must be closed with CloseHandle()
		//			INFO: Check GetLastError() to be ERROR_ALREADY_EXISTS if event already existed
		//		= NULL if error - check GetLastError() for info
		HANDLE hEvent = NULL;

		if (pStrName &&
			pStrName[0])
		{
			WCHAR buffName[256];
			buffName[0] = 0;
			WCHAR* pEnd;
			HRESULT hr = ::StringCchPrintfEx(buffName, _countof(buffName), &pEnd, NULL, 
				STRSAFE_IGNORE_NULLS | STRSAFE_NO_TRUNCATION,
//				L"\\BaseNamedObjects\\%s",
				L"Global\\%s",
				pStrName);

			if (SUCCEEDED(hr))
			{
				size_t nchLn = pEnd - buffName;
				if (nchLn < USHRT_MAX / sizeof(WCHAR))
				{
					//Create DACL for access to everyone (including processes with untrusted MIL)
					SECURITY_DESCRIPTOR_W_LABEL sd4e;
					if (get_SECURITY_DESCRIPTOR_FullAccess(sd4e))
					{
						SECURITY_ATTRIBUTES sa = { sizeof(sa), &sd4e.sd, FALSE };

						hEvent = ::CreateEventEx(&sa, buffName, 
							(bAutoReset ? 0 : CREATE_EVENT_MANUAL_RESET) | (bInitialState ? CREATE_EVENT_INITIAL_SET : 0),
							SYNCHRONIZE | 0x1 /*EVENT_QUERY_STATE*/ | (bAllowModify ? EVENT_MODIFY_STATE : 0));
					}
				}
				else
					::SetLastError(8248);
			}
			else
				::SetLastError(hr);
		}
		else
			::SetLastError(ERROR_EMPTY);

		return hEvent;
	}

	static BOOL get_SECURITY_DESCRIPTOR_FullAccess(SECURITY_DESCRIPTOR_W_LABEL& sd)
	{
		//Fill in security descriptor in 'sd' with access to everyone (including processes with untrusted MIL)
		//RETURN:
		//		= TRUE if success
		//		= FALSE if error (check GetLastError() for info)

		//Create DACL for access to everyone (including processes with untrusted MIL)
		static const SID UntrustedSid = {
			SID_REVISION, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, { SECURITY_MANDATORY_UNTRUSTED_RID }
		};

		if (::InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) &&
			::InitializeAcl(&sd.Label, sizeof(sd.Label), ACL_REVISION) &&
			::AddMandatoryAce(&sd.Label, ACL_REVISION, 0, 0, const_cast<SID*>(&UntrustedSid)) &&
			::SetSecurityDescriptorSacl(&sd, TRUE, &sd.Label, FALSE) &&
			::SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE) &&
			::SetSecurityDescriptorControl(&sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED))
		{
			return TRUE;
		}

		return FALSE;
	}

	static const WCHAR* getFormattedErrorMsg(int nOSError, WCHAR* pBuffer, size_t szchBuffer)
	{
		//'pBuffer' = buffer to fill in with error description
		//'szchBuffer' = size of 'pBuffer' in WCHARs
		//RETURN:
		//		= Pointer to 'pBuffer' (always NULL-terminated)
		int nPrev_OSError = ::GetLastError();

		if(szchBuffer)
		{
			if(nOSError)
			{
				LPVOID lpMsgBuf = NULL;
				DWORD dwRes;

				pBuffer[0] = 0;

				dwRes = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL,
					nOSError,
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
					(LPTSTR) &lpMsgBuf, 0, NULL);

				if(lpMsgBuf)
				{	
					::StringCchCopy(pBuffer, szchBuffer, (LPCTSTR)lpMsgBuf);
					::LocalFree(lpMsgBuf);
				}

				//Safety null
				pBuffer[szchBuffer - 1] = 0;
			}
			else
			{
				//No errors
				pBuffer[0] = 0;
			}
		}
		else
			assert(NULL);

		::SetLastError(nPrev_OSError);
		return pBuffer;
	}

private:
	static HMODULE _getDPI_APIs_ptrs(UINT(WINAPI **ppfnGetDpiForWindow)(HWND hwnd) = NULL)
	{
		static HMODULE hModUser32 = NULL;
		static UINT(WINAPI *pfnGetDpiForWindow)(HWND hwnd) = NULL;

		if (!hModUser32)
		{
			hModUser32 = ::GetModuleHandle(L"User32.dll");
			assert(hModUser32);
		}

		if (!pfnGetDpiForWindow)
		{
			(FARPROC&)pfnGetDpiForWindow = ::GetProcAddress(hModUser32, "GetDpiForWindow");
			assert(pfnGetDpiForWindow);
		}

		if(ppfnGetDpiForWindow)
			*ppfnGetDpiForWindow = pfnGetDpiForWindow;

		return hModUser32;
	}

public:

	static int GetSystemMetricsWithDPI(int nIndex, HWND hWnd)
	{
		//'hWnd' = window handle to retrieve a setting for (used for DPI scaling)
		//RETURN:
		//		= System metrics setting for 'nIndex' -- see GetSystemMetrics()

		UINT(WINAPI *pfnGetDpiForWindow)(HWND hwnd);
		HMODULE hModUsr32 = _getDPI_APIs_ptrs(&pfnGetDpiForWindow);

		if (pfnGetDpiForWindow)
		{
			int nDpiAwareness = pfnGetDpiForWindow(hWnd);
			if (nDpiAwareness)
			{
				static int (WINAPI *pfnGetSystemMetricsForDpi)(
					int  nIndex,
					UINT dpi
					) = NULL;

				if (!pfnGetSystemMetricsForDpi)
				{
					assert(hModUsr32);
					(FARPROC&)pfnGetSystemMetricsForDpi = ::GetProcAddress(hModUsr32, "GetSystemMetricsForDpi");
					assert(pfnGetSystemMetricsForDpi);
				}

				if (pfnGetSystemMetricsForDpi)
				{
					//Invoke newer API
					return pfnGetSystemMetricsForDpi(nIndex, nDpiAwareness);
				}
				else
					assert(false);
			}
			else
				assert(false);
		}
		else
			assert(false);

		//Fallback
		return ::GetSystemMetrics(nIndex);
	}

	static BOOL GetDPI(HWND hWnd, double* pfOutX = NULL, double* pfOutY = NULL)
	{
		//Get current DPI setting for 'hWnd' window
		//INFO: Usually X and Y axis DPI scaling are the same.
		//'pfOutX' = if not NULL, DPI scaling along the x-axis.
		//'pfOutY' = if not NULL, DPI scaling along the y-axis. (Old - don't use!)
		//RETURN:
		//		= TRUE if success
		//		= FALSE if failed (in this case 'pfOutX' and 'pfOutY' will be set to 1.0)
		BOOL bRes = FALSE;
		double fX = 1.0;
		double fY = 1.0;

		//First try newer API
		UINT (WINAPI *pfnGetDpiForWindow)(HWND hwnd);
		_getDPI_APIs_ptrs(&pfnGetDpiForWindow);

		if(pfnGetDpiForWindow)
		{
			//Will return 0 if error
			int nDpiAwareness = pfnGetDpiForWindow(hWnd);
			if (nDpiAwareness > 0)
			{
				//Done
				fY = fX = nDpiAwareness / 96.0;

				bRes = TRUE;
			}
			else
				assert(false);
		}
		else
		{
			//Fallback method

			//Get device context
			HDC hDC = ::GetDC(hWnd);
			if (hDC)
			{
				//Calculate DPI settings
				int nCx = ::GetDeviceCaps(hDC, LOGPIXELSX);
				int nCy = ::GetDeviceCaps(hDC, LOGPIXELSY);

				if (nCx > 0 &&
					nCy > 0)
				{
					//Done
					fX = (double)nCx / 96.0;
					fY = (double)nCy / 96.0;

					bRes = TRUE;
				}

				::ReleaseDC(hWnd, hDC);
			}
		}

		if(pfOutX)
			*pfOutX = fX;
		if(pfOutY)
			*pfOutY = fY;

		return bRes;
	}


	static BOOL CheckWindowsVersion(RTL_OSVERSIONINFOEXW* pOutVer = NULL)
	{
		//'pOutVer' = if not NULL, receives Windows version (without Microsoft bullshit)
		//RETURN:
		//		= TRUE if success
		//		= FALSE if failed (check GetLastError() for info)
		int nOSError = 0;
		BOOL bRes = FALSE;

		RTL_OSVERSIONINFOEXW ver = {};
		ver.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);

		static LONG (WINAPI *pfnRtlGetVersion)(RTL_OSVERSIONINFOEXW*) = NULL;
		if (!pfnRtlGetVersion)
		{
			static HMODULE hModNtDll = NULL;
			if (!hModNtDll)
			{
				hModNtDll = GetModuleHandle(L"ntdll.dll");
				assert(hModNtDll);
			}

			(FARPROC&)pfnRtlGetVersion = GetProcAddress(hModNtDll, "RtlGetVersion");
			assert(pfnRtlGetVersion);
		}

		if(pfnRtlGetVersion)
		{
			LONG status = pfnRtlGetVersion(&ver);
			if(status == 0)
			{
				//Done
				bRes = TRUE;
			}
			else
				nOSError = status;
		}
		else
			nOSError = ERROR_FUNCTION_FAILED;

		if(pOutVer)
			*pOutVer = ver;

		::SetLastError(nOSError);
		return bRes;
	}

	static bool IsNullOrEmpty(const WCHAR* pStr)
	{
		//		= TRUE if 'pStr' is a NULL, or points to an empty string with whitespaces
		if (!pStr)
			return TRUE;

		for (;; pStr++)
		{
			WCHAR z = *pStr;
			if (!z)
				return TRUE;

			if (!IsCharWhitespace(z) &&
				!IsCharNewline(z))
			{
				break;
			}
		}

		return FALSE;
	}
	static bool IsNullOrEmpty(std::wstring& str)
	{
		//		= TRUE if 'str' is an empty string with spaces
		return IsNullOrEmpty(str.c_str());
	}
	static BOOL IsCharWhitespace(const WCHAR ch)
	{
		//RETURN:
		//		= TRUE if 'ch' is an English language whitespace
		return ch == L' ' || ch == L'\t' ||
			//Account for other possible whitespaces:
			ch == 0x85 || ch == 0xA0 ||
			(ch >= 0x2000 && ch <= 0x200A) ||
			ch == 0x2028 || ch == 0x2029 || ch == 0x202f ||
			ch == 0x205F || ch == 0x3000 ||
			//Also assume that the user could have copy-and-pasted it from some outside
			//software that was coded in a very dumb way:
			//	https://superuser.com/questions/1361155/how-to-stop-windows-10-calculator-from-enclosing-copied-text-in-202d-and-202c-un
			ch == 0x202c || ch == 0x202d;
	}
	static BOOL IsCharNewline(const WCHAR ch)
	{
		//RETURN:
		//		= TRUE if 'ch' is a newline
		return ch == L'\n' || ch == L'\r';
	}
	static BOOL IsCharADigit(const WCHAR ch)
	{
		//RETURN:
		//		= TRUE if 'ch' is a digit
		return ch >= L'0' && ch <= L'9';
	}

	static void Format(std::wstring& s, LPCTSTR pszFormat, ...)
	{
		//Format the string
		int nOSErr = ::GetLastError();

		va_list argList;
		va_start(argList, pszFormat);

		//Get length
		int nLnBuff = _vscwprintf(pszFormat, argList);

		//Reserve a buffer
		TCHAR* pBuff = new (std::nothrow) TCHAR[nLnBuff + 1];
		if (pBuff)
		{
			//Do formatting
			vswprintf_s(pBuff, nLnBuff + 1, pszFormat, argList);

			//And set to string
			s.assign(pBuff, nLnBuff);

			//Free mem
			delete[] pBuff;
		}

		va_end(argList);

		::SetLastError(nOSErr);
	}

	static void Format(std::wstring* pStr, LPCTSTR pszFormat, ...)
	{
		//Format the string
		int nOSErr = ::GetLastError();
		ASSERT(pStr);

		va_list argList;
		va_start(argList, pszFormat);

		//Get length
		int nLnBuff = _vscwprintf(pszFormat, argList);

		//Reserve a buffer
		TCHAR* pBuff = new (std::nothrow) TCHAR[nLnBuff + 1];
		if (pBuff)
		{
			//Do formatting
			vswprintf_s(pBuff, nLnBuff + 1, pszFormat, argList);

			if (pStr)
			{
				//And set to string
				pStr->assign(pBuff, nLnBuff);
			}

			//Free mem
			delete[] pBuff;
		}

		va_end(argList);

		::SetLastError(nOSErr);
	}

	static void AppendFormat(std::wstring& s, LPCTSTR pszFormat, ...)
	{
		//Format the string
		int nOSErr = ::GetLastError();

		va_list argList;
		va_start(argList, pszFormat);

		//s.FormatV(pszFormat, argList);

		//Get length
		int nLnBuff = _vscwprintf(pszFormat, argList);

		//Reserve a buffer
		TCHAR* pBuff = new (std::nothrow) TCHAR[nLnBuff + 1];
		if (pBuff)
		{
			//Do formatting
			vswprintf_s(pBuff, nLnBuff + 1, pszFormat, argList);

			//And add to string
			s.append(pBuff, nLnBuff);

			//Free mem
			delete[] pBuff;
		}

		va_end(argList);
		::SetLastError(nOSErr);
	}

	static std::wstring EasyFormat(LPCTSTR pszFormat, ...)
	{
		//RETURN:
		//		= Formatted string according to 'pszFormat' specifiers
		int nOSErr = ::GetLastError();

		va_list argList;
		va_start(argList, pszFormat);

		std::wstring s;

		//Get length
		int nLnBuff = _vscwprintf(pszFormat, argList);

		//Reserve space
		s.resize(nLnBuff);

		//Do formatting
		vswprintf_s(&s[0], nLnBuff + 1, pszFormat, argList);

		va_end(argList);
		::SetLastError(nOSErr);
		return s;
	}


	static std::wstring Left(std::wstring &s, size_t nCount)
	{
		return s.substr(0, nCount);
	}

	static std::wstring Right(std::wstring &s, size_t nCount)
	{
		return s.substr(s.length() - nCount, nCount);
	}

	static std::wstring Mid(std::wstring &s, int iFirst, int nCount)
	{
		return s.substr(iFirst, nCount);
	}

	static std::wstring& lTrim(std::wstring &s)
	{
		//Trim all white-spaces from the left side of 's'
		//RETURN: = Same trimmed string
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
		return s;
	}

	static std::wstring& rTrim(std::wstring &s)
	{
		//Trim all white-spaces from the right side of 's'
		//RETURN: = Same trimmed string
		s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
		return s;
	}

	static std::wstring& Trim(std::wstring &s)
	{
		//Trim all white-spaces from 's'
		//RETURN: = Same trimmed string
		return lTrim(rTrim(s));
	}

	static void ReplaceAll(std::wstring& str, const std::wstring& from, const std::wstring& to)
	{
		//Replace all occurances of 'from' in 'str' with 'to'
		size_t nLn_from = from.length();
		size_t nLn_to = to.length();

		size_t start_pos = 0;
		while ((start_pos = str.find(from, start_pos)) != std::wstring::npos)
		{
			str.replace(start_pos, nLn_from, to);
			start_pos += nLn_to;			 // Handles case where 'to' is a substring of 'from'
		}
	}

	static void ReplaceAll(std::wstring& str, LPCTSTR from, LPCTSTR to)
	{
		//Get string length
		size_t nLn_from = 0;
		while (from[nLn_from])
		{
			nLn_from++;
		}

		//Get string length
		size_t nLn_to = 0;
		while (to[nLn_to])
		{
			nLn_to++;
		}

		size_t start_pos = 0;
		while ((start_pos = str.find(from, start_pos)) != std::wstring::npos) {
			str.replace(start_pos, nLn_from, to);
			start_pos += nLn_to; // Handles case where 'to' is a substring of 'from'
		}
	}

	static void ReplaceAll(std::wstring& str, TCHAR chFrom, TCHAR chTo)
	{
		//Replace all occurances of 'chFrom' in 'str' with 'chTo'
		TCHAR* pStr = &str[0];
		size_t nLn = str.size();

		for (size_t i = 0; i < nLn; i++)
		{
			if (pStr[i] == chFrom)
				pStr[i] = chTo;
		}
	}

	static intptr_t FindAnyOf(std::wstring& str, LPCTSTR pStrSearch, intptr_t nBeginIndex)
	{
		//Case-sensitive search of 'pStrSearch' in 'str'
		//'nBeginIndex' = index in 'str' to begin from
		//RETURN:
		//		= [0 and up) Index of the first ocurrence of any chars from 'pStrSearch' in 'str'
		//		= -1 if not found
		intptr_t nLnStr = str.length();

		for (intptr_t i = nBeginIndex; i < nLnStr; i++)
		{
			TCHAR z = str[i];
			for (int c = 0;; c++)
			{
				TCHAR x = pStrSearch[c];
				if (!x)
					break;

				if (z == x)
				{
					//Match
					return i;
				}
			}
		}

		return -1;
	}

	static std::wstring Tokenize(std::wstring& str, LPCTSTR pStrSearch, intptr_t& nPos)
	{
		//Tokenize string in 'str'
		//'strSearch' = separator chars (can be 1 or more)
		//'nPos' = current position to search. Will be updated upon return. Must be set to 0 or initial index in 'str' to begin from
		//			INFO: Will be set to -1 if no more found. Use it to stop the tokenization
		//RETURN:
		//		= Token found
		std::wstring strRet;

		if (nPos != -1)
		{
			//Search must not be empty
			if (pStrSearch &&
				pStrSearch[0])
			{
				if (nPos >= 0 && nPos < (intptr_t)str.length())
				{
					intptr_t nIniPos = nPos;
					nPos = FindAnyOf(str, pStrSearch, nIniPos);
					if (nPos != -1)
					{
						ASSERT(nPos >= nIniPos);
						//strRet = pStr->Mid(nIniPos, nPos - nIniPos);
						strRet.assign(str, nIniPos, nPos - nIniPos);
						nPos += 1;
					}
					else
					{
						if ((intptr_t)str.length() >= nIniPos)
						{
							//strRet = pStr->Mid(nIniPos, pStr->GetLength() - nIniPos);
							strRet.assign(str, nIniPos, str.length() - nIniPos);
							nPos = str.length() + 1;
						}
						else
							nPos = -1;
					}

				}
				else if (nPos == str.length())
				{
					strRet = L"";
					nPos = str.length() + 1;
				}
				else
					nPos = -1;
			}
			else
				nPos = -1;
		}

		return strRet;
	}



	static std::wstring MakeFolderPathEndWithSlash(const std::wstring& strPath, BOOL bAttachSlash = TRUE)
	{
		//RETURN: = Folder always ending with a slash, except empty string path, if 'bAttachSlash' == TRUE, or
		//			 always without it if 'bAttachSlash' == FALSE
		return MakeFolderPathEndWithSlash(strPath.c_str(), bAttachSlash);
	}

	static std::wstring MakeFolderPathEndWithSlash(LPCTSTR pPath, BOOL bAttachSlash = TRUE)
	{
		//RETURN: = Folder always ending with a slash, except empty string path, if 'bAttachSlash' == TRUE, or
		//			 always without it if 'bAttachSlash' == FALSE
		std::wstring FolderPath = pPath ? pPath : L"";

		size_t nLn = FolderPath.size();
		if (nLn > 0)
		{
			TCHAR c = FolderPath[nLn - 1];
			if (bAttachSlash)
			{
				if (c != '/' && c != '\\')
				{
					//Find previous slash
					TCHAR ch = '\\';
					for (size_t i = FolderPath.size() - 1; i >= 0; i--)
					{
						TCHAR z = FolderPath[i];
						if (z == '\\' || z == '/')
						{
							ch = z;
							break;
						}
					}

					FolderPath += ch;
				}
			}
			else
			{
				if (c == '/' || c == '\\')
					FolderPath = AUX_FUNCS::Left(FolderPath, nLn - 1);
			}
		}

		return FolderPath;
	}

	static BOOL MakeFolderPathEndWithSlash_Buff(WCHAR* buffer, size_t szchBuffer, BOOL bAttachSlash = TRUE)
	{
		//Make sure that the path specified in 'buffer' has, or doesn't have a slash at the end, depending on 'bAttachSlash'
		//'szchBuffer' = size of 'buffer' in WCHARs
		//'bAttachSlash' = TRUE to add last slash, FALSE = to remove it
		//RETURN:
		//		= TRUE if success
		//		= FALSE if error (check GetLastError() for info)
		BOOL bRes = FALSE;

		size_t szchLn = 0;
		HRESULT hr = ::StringCchLength(buffer, szchBuffer, &szchLn);
		if (hr == S_OK)
		{
			BOOL bHasLastSlash = FALSE;

			if (szchLn != 0)
			{
				WCHAR z = buffer[szchLn - 1];
				if (z == '\\' || z == '/')
					bHasLastSlash = TRUE;
			}

			if (bHasLastSlash == (!!bAttachSlash))
			{
				//No need to do anything
				bRes = TRUE;
			}
			else
			{
				if (bAttachSlash)
				{
					//Add slash if we have room
					if (szchLn + 1 < szchBuffer)
					{
						buffer[szchLn] = '\\';
						buffer[szchLn + 1] = 0;

						bRes = TRUE;
					}
					else
						::SetLastError(ERROR_BUFFER_OVERFLOW);
				}
				else
				{
					//Remove it
					buffer[szchLn - 1] = 0;

					bRes = TRUE;
				}
			}
		}
		else
			::SetLastError((int)hr);

		return bRes;
	}


	static BOOL IsFileByFilePath(LPCTSTR pFilePath)
	{
		//Determines if 'pFilePath' is a valid file path
		//(May be a network path too)
		//RETURN:
		//		= TRUE if it is pointing to a file
		//		= FALSE if it is not (check GetLastError() for more info)
		//					- ERROR_FILE_NOT_FOUND if it does not exist
		//					- ERROR_PATH_NOT_FOUND if it does not exist
		//					- ERROR_BAD_FORMAT if it exists, but it is not a file
		//					- can be others
		assert(pFilePath);
		int nOSError = NO_ERROR;

		//Do the check
		BOOL bRes = FALSE;
		if (PathFileExists(pFilePath))
		{
			if (!PathIsDirectory(pFilePath))
			{
				//Yes, it is a file
				bRes = TRUE;
			}
			else
				nOSError = ERROR_BAD_FORMAT;
		}
		else
			nOSError = ::GetLastError();

		::SetLastError(nOSError);
		return bRes;
	}

	static BOOL IsFolderByFilePath(LPCTSTR pFolderPath)
	{
		//Determines if 'pFolderPath' is a valid folder path
		//(May be a network path too)
		//RETURN:
		//		= TRUE if it is pointing to a folder
		//		= FALSE if it is not (check GetLastError() for more info)
		//					- ERROR_FILE_NOT_FOUND if it does not exist
		//					- ERROR_PATH_NOT_FOUND if it does not exist
		//					- ERROR_BAD_FORMAT if it exists, but it is not a folder
		//					- can be others
		assert(pFolderPath);
		int nOSError = NO_ERROR;

		//Do the check
		BOOL bRes = FALSE;
		if (PathFileExists(pFolderPath))
		{
			if (PathIsDirectory(pFolderPath))
			{
				//Yes, it is
				bRes = TRUE;
			}
			else
				nOSError = ERROR_BAD_FORMAT;
		}
		else
			nOSError = ::GetLastError();

		::SetLastError(nOSError);
		return bRes;
	}



	static BOOL _parseRegConfigContents(const WCHAR* pData, size_t szchSz, std::vector<CUSTOM_REG_VALUE>& arrDataOut)
	{
		//Read contents of 'pData' string buffer, laid out as such (on each line):
		//  ; comment
		//	Name = Value
		//
		//  where Value could be one of two formats:
		//		integer			ex: name=123
		//		string			ex: name="john"  - can accept \ as escape char, such as in \"
		//
		//'szchSz' = size of 'pData' in WCHARs
		//'arrDataOut' = receives all Name=Value pairs read
		//RETURN:
		//		= TRUE if success parsing
		//		= FALSE if error (check GetLastError() for info)
		BOOL bRes = TRUE;
		int nOSError = 0;

		arrDataOut.clear();

		if (pData &&
			(intptr_t)szchSz > 0)
		{
			//Assume failure for now
			bRes = FALSE;

			enum {
				PARSE_COMMENT,
				LOOK_4_NAME,
				PARSE_NAME,
				LOOK_4_EQUAL_SIGN,
				LOOK_4_VALUE,
				PARSE_VALUE_STRING,
				PARSE_VALUE_INTEGER,
			}
			parseMode = LOOK_4_NAME;

			CUSTOM_REG_VALUE crv;
			BOOL bNegativeInteger = FALSE;
			WCHAR buff[128];
			HRESULT hr;

			WCHAR z;
			const WCHAR* pS = pData;
			const WCHAR* pEnd = pData + szchSz;

			for (; ; pS++)
			{
				//Check for the end
				if (pS >= pEnd)
				{
					if (parseMode == LOOK_4_NAME ||
						parseMode == PARSE_COMMENT)
					{
						//All good
						bRes = TRUE;
					}
					else if (parseMode == PARSE_VALUE_INTEGER)
					{
						z = 0;
						goto lbl_end_val_number;
					}
					else
					{
						//Unexpected end of file
						nOSError = 38;
					}

					break;
				}



				z = *pS;

				if (parseMode == LOOK_4_NAME)
				{
					if (IsCharWhitespace(z) || IsCharNewline(z))
						continue;

					if (z == ';')
					{
						parseMode = PARSE_COMMENT;
						continue;
					}

					//Start over
					crv.EmptyIt();
					bNegativeInteger = FALSE;

					parseMode = PARSE_NAME;
					pS--;
				}
				else if (parseMode == PARSE_NAME)
				{
					if (IsCharWhitespace(z))
					{
						parseMode = LOOK_4_EQUAL_SIGN;

						goto lbl_chk_name;
					}
					else if (z == L'=')
					{
						parseMode = LOOK_4_VALUE;
					lbl_chk_name:
						if (crv.strName.empty())
						{
							//Empty name
							nOSError = 1755;
							break;
						}
					}
					else if (IsCharNewline(z))
					{
						//Bad newline
						nOSError = 1706;
						break;
					}
					else
					{
						crv.strName += z;
					}
				}
				else if (parseMode == LOOK_4_EQUAL_SIGN)
				{
					if (z == L'=')
					{
						parseMode = LOOK_4_VALUE;
					}
					else if (!IsCharWhitespace(z))
					{
						//bad char
						nOSError = 1799;
						break;
					}
				}
				else if (parseMode == LOOK_4_VALUE)
				{
					if (IsCharWhitespace(z))
						continue;

					if (z == L'"')
					{
						//String value
						parseMode = PARSE_VALUE_STRING;
					}
					else if (z == L'+' || z == L'-')
					{
						//See if followed by a digit
						if (pS + 1 < pEnd &&
							IsCharADigit(*(pS + 1)))
						{
							//Begin parsing
							parseMode = PARSE_VALUE_INTEGER;

							bNegativeInteger = z == L'-';
						}
						else
						{
							//Bad format
							nOSError = 3505;
							break;
						}
					}
					else if (IsCharADigit(z))
					{
						//Digit value
						crv.strVal = z;
						parseMode = PARSE_VALUE_INTEGER;
					}
					else
					{
						//Bad format of value
						nOSError = 4063;
						break;
					}
				}
				else if (parseMode == PARSE_VALUE_STRING)
				{
					if (z == L'"')
					{
						//End of value
						crv.type = CRVT_STRING;
						arrDataOut.push_back(crv);

						parseMode = LOOK_4_NAME;
					}
					else if (z == L'\\')
					{
						//Escape sequence: as in \"
						if (pS + 1 < pEnd)
						{
							pS++;
							crv.strVal += *pS;
						}
						else
						{
							//Error
							nOSError = 5921;
							break;
						}
					}
					else
					{
						crv.strVal += z;
					}
				}
				else if (parseMode == PARSE_VALUE_INTEGER)
				{
					if (IsCharADigit(z))
					{
						crv.strVal += z;
					}
					else if (z == L';' || IsCharWhitespace(z) || IsCharNewline(z))
					{
lbl_end_val_number:
						//End of value
						if (!crv.strVal.empty())
						{
							const WCHAR* pNum = crv.strVal.c_str();
							LONGLONG uiV = _wtoi64(pNum);

							//See if read the value correctly
							buff[0] = 0;
							hr = ::StringCchPrintf(buff, _countof(buff), L"%I64u", uiV);
							if (SUCCEEDED(hr))
							{
								//Does what we scanned match the original?
								size_t szchNumLn = crv.strVal.size();
								if (wcslen(buff) == szchNumLn &&
									wmemcmp(buff, pNum, szchNumLn) == 0)
								{
									//Add value
									crv.uiVal = !bNegativeInteger ? uiV : -uiV;
									crv.strVal.clear();

									crv.type = CRVT_INTEGER;
									arrDataOut.push_back(crv);

									parseMode = LOOK_4_NAME;
								}
								else
								{
									//Format overflow
									nOSError = 1781;
									break;
								}
							}
							else
							{
								//Failed
								nOSError = (int)hr;
								break;
							}
						}
						else
						{
							//Empty number
							nOSError = 2115;
							break;
						}
					}
					else
					{
						//Bad number format
						nOSError = 1343;
						break;
					}
				}
				else if (parseMode == PARSE_COMMENT)
				{
					//Skip comments
					if (IsCharNewline(z))
					{
						parseMode = LOOK_4_NAME;
					}
				}
				else
				{
					//Bad parseMode
					nOSError = 6846;
					break;
				}
			}
		}

		::SetLastError(nOSError);
		return bRes;
	}

	static BOOL GetRegConfigFileContents(LPCTSTR pStrFilePath, std::vector<CUSTOM_REG_VALUE>* p_arrDataOut)
	{
		//Read registry configuration file contents
		//'pStrFilePath' = file path. It must be a text file with the format specified in the _parseRegConfigContents() function.
		//'p_arrDataOut' = if not NULL, receives data parsed (if success)
		//RETURN:
		//		= TRUE if success parsing
		//		= FALSE if error (check GetLastError() for info)
		BOOL bRes = FALSE;
		int nOSError = 0;

		std::vector<CUSTOM_REG_VALUE> arrDummyCRVs;
		if (!p_arrDataOut)
			p_arrDataOut = &arrDummyCRVs;

		//Clear output array
		p_arrDataOut->clear();

		if (pStrFilePath &&
			pStrFilePath[0])
		{
			HANDLE hFile = ::CreateFile(pStrFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				LARGE_INTEGER liFileSz;
				if (::GetFileSizeEx(hFile, &liFileSz))
				{
					//Make sure the file is not too large
					if ((ULONGLONG)liFileSz.QuadPart <= 0x400000)			//4MB max
					{
						DWORD dwcbFileSz = (DWORD)liFileSz.QuadPart;

						BYTE* pData = new (std::nothrow) BYTE[dwcbFileSz];
						if (pData)
						{
							DWORD dwcbRead = 0;
							if (::ReadFile(hFile, pData, dwcbFileSz, &dwcbRead, NULL))
							{
								if (dwcbRead == dwcbFileSz)
								{
									DWORD dwchLen;
									UINT nCodePage;
									const char* pS;
									WCHAR* pTxt;

									//Check file BOM
									if (dwcbRead >= 2 &&
										pData[0] == 0xff && pData[1] == 0xfe)
									{
										//UTF-16 LE
										dwchLen = (dwcbRead - 2) / sizeof(WCHAR);
										if ((dwcbRead % sizeof(WCHAR)) == 0)
										{
											//Parse now
											if (_parseRegConfigContents((const WCHAR*)(pData + 2), dwchLen, *p_arrDataOut))
											{
												//Done
												bRes = TRUE;
											}
											else
												nOSError = ::GetLastError();
										}
										else
											nOSError = 4815;
									}
									else if (dwcbRead >= 2 &&
										pData[0] == 0xfe && pData[1] == 0xff)
									{
										//UTF-16 BE
										dwchLen = (dwcbRead - 2) / sizeof(WCHAR);
										if ((dwcbRead % sizeof(WCHAR)) == 0)
										{
											pTxt = new (std::nothrow) WCHAR[dwchLen];
											if (pTxt)
											{
												//Convert text
												char* pD = (char*)pTxt;
												pS = (const char*)(pData + 2);
												const char* pE = (const char*)(pData + dwcbRead);

												for (; pS < pE; )
												{
													BYTE b1 = *pS++;
													BYTE b2 = *pS++;

													*pD++ = b2;
													*pD++ = b1;
												}

												assert(pS == pE);
												assert(pD == (const char*)(pTxt + dwchLen));

												//Parse now
												if (_parseRegConfigContents(pTxt, dwchLen, *p_arrDataOut))
												{
													//Done
													bRes = TRUE;
												}
												else
													nOSError = ::GetLastError();


												//Free mem
												delete pTxt;
												pTxt = NULL;
											}
											else
												nOSError = ERROR_OUTOFMEMORY;
										}
										else
											nOSError = 4815;
									}
									else if (dwcbRead >= 3 &&
										pData[0] == 0xef && pData[1] == 0xbb && pData[2] == 0xbf)
									{
										//UTF-8
										if (dwcbRead > 3)
										{
											nCodePage = CP_UTF8;
											pS = (const char*)(pData + 3);
											dwchLen = dwcbRead - 3;

											goto lbl_conv;
										}
										else
										{
											//Empty file
											bRes = TRUE;
										}
									}
									else
									{
										//Assume ANSI
										if (dwcbRead != 0)
										{
											nCodePage = CP_ACP;
											pS = (const char*)pData;
											dwchLen = dwcbRead;
										lbl_conv:
											//Convert encoding first
											int nchLnConv = ::MultiByteToWideChar(nCodePage, 0, (LPCCH)pS, dwchLen, NULL, 0);
											if (nchLnConv)
											{
												pTxt = new (std::nothrow) WCHAR[nchLnConv];
												if (pTxt)
												{
													if (::MultiByteToWideChar(nCodePage, 0, (LPCCH)pS, dwchLen, pTxt, nchLnConv) == nchLnConv)
													{
														//Parse now
														if (_parseRegConfigContents(pTxt, nchLnConv, *p_arrDataOut))
														{
															//Done
															bRes = TRUE;
														}
														else
															nOSError = ::GetLastError();

													}
													else
														nOSError = ::GetLastError();

													//Free mem
													delete[] pTxt;
													pTxt = NULL;
												}
												else
													nOSError = ERROR_OUTOFMEMORY;
											}
											else
												nOSError = ::GetLastError();
										}
										else
										{
											//Empty file
											bRes = TRUE;
										}
									}
								}
								else
									nOSError = ERROR_READ_FAULT;
							}
							else
								nOSError = ::GetLastError();

							//Free mem
							delete[] pData;
							pData = NULL;
						}
						else
							nOSError = ERROR_OUTOFMEMORY;
					}
					else
						nOSError = 8312;
				}
				else
					nOSError = ::GetLastError();

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

	static std::wstring EscapeDoubleQuoteString(std::wstring& str)
	{
		//Escape all double-quotes inside 'str' with \"
		//RETURN:
		//		= Escaped string
		return EscapeDoubleQuoteString(str.c_str());
	}
	static std::wstring EscapeDoubleQuoteString(LPCTSTR pStr)
	{
		//Escape all double-quotes inside 'pStr' with \"
		//RETURN:
		//		= Escaped string

		//Count double-quotes and a new length
		size_t nszLn = 0;
		const WCHAR* pS = pStr;
		for (;; pS++)
		{
			WCHAR z = *pS;
			if (!z)
				break;
			else if (z == L'"')
				nszLn++;
		}

		nszLn += pS - pStr;

		//Reserve mem
		std::wstring str;
		str.resize(nszLn);

		//Fill in new string
		WCHAR* pD = &str[0];
		const WCHAR* pE = pS;
		for (pS = pStr; pS < pE; pS++, pD++)
		{
			WCHAR z = *pS;
			if (z == L'"')
			{
				*pD = L'\\';
				pD++;
			}

			*pD = z;
		}

		//Check mem allocation
		assert(pD - &str[0] == nszLn);

		return str;
	}


	static BOOL DeleteFileSmart(LPCTSTR pStrFilePath)
	{
		//Delete the 'pStrFilePath' file by its path
		//INFO: Removes file attributes first (in case the file is read-only)
		//RETURN:
		//		= TRUE if no error
		//		= FALSE if error (check GetLastError() for more info)
		BOOL bRes = FALSE;
		int nOSError = NO_ERROR;

		//We must have a file path
		if (pStrFilePath &&
			pStrFilePath[0] != 0)
		{
			//Get attributes first
			DWORD dwOldAttrs = ::GetFileAttributes(pStrFilePath);

			if (dwOldAttrs != INVALID_FILE_ATTRIBUTES)
			{
				if (dwOldAttrs != FILE_ATTRIBUTE_NORMAL &&
					dwOldAttrs != FILE_ATTRIBUTE_ARCHIVE &&
					(dwOldAttrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
				{
					//Clear attributes
					::SetFileAttributes(pStrFilePath, FILE_ATTRIBUTE_NORMAL);
				}
			}

			//Try to delete the file
			bRes = ::DeleteFile(pStrFilePath);
			nOSError = ::GetLastError();

			if (!bRes)
			{
				//Failed to delete file

				//Reset attributes back
				if (dwOldAttrs != INVALID_FILE_ATTRIBUTES &&
					dwOldAttrs != FILE_ATTRIBUTE_NORMAL &&
					dwOldAttrs != FILE_ATTRIBUTE_ARCHIVE &&
					(dwOldAttrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
				{
					::SetFileAttributes(pStrFilePath, dwOldAttrs);
				}

				//See if file did not exist previously
				if (nOSError == ERROR_FILE_NOT_FOUND ||
					nOSError == ERROR_PATH_NOT_FOUND)
				{
					//Still success
					bRes = TRUE;
				}
			}
		}
		else
		{
			//Nothing to delete
			bRes = TRUE;
		}

		//Set last error
		::SetLastError(nOSError);

		return bRes;
	}


	static CUSTOM_REG_VALUE* find_CUSTOM_REG_VALUE_byName(std::vector<CUSTOM_REG_VALUE>&arrCRVs, LPCTSTR pStrName)
	{
		//Find specific element in 'arrCRVs' by name
		//'pStrName' = case insensitive name to use
		//RETURN:
		//		= Pointer to the found element in 'arrCRVs', or
		//		= NULL if none

		if (pStrName &&
			pStrName[0])
		{
			UINT nchLnName = 0;
			while (pStrName[nchLnName])
				nchLnName++;

			CUSTOM_REG_VALUE* pS = arrCRVs.data();
			for (const CUSTOM_REG_VALUE* pEnd = pS + arrCRVs.size(); pS < pEnd; ++pS)
			{
				if (::CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE, pS->strName.c_str(), (int)pS->strName.size(), pStrName, nchLnName) == CSTR_EQUAL)
				{
					//Found it
					return pS;
				}
			}
		}

		return NULL;
	}


	static std::wstring CUSTOM_REG_VALUE_to_NameValue_Str(const CUSTOM_REG_VALUE* p_crv)
	{
		//Convert 'crv' into a string version of name=value pair
		//RETURN:
		//		= Resulting string
		assert(p_crv);
		BOOL bString = p_crv->type == CRVT_STRING;
		std::wstring str;
		LPCTSTR pUseQuotes = bString ? L"\"" : L"";

		AUX_FUNCS::Format(str,
			L"%s=%s%s%s"
			,
			p_crv->strName.c_str(),
			pUseQuotes,
			bString ? AUX_FUNCS::EscapeDoubleQuoteString(p_crv->toValueString().c_str()).c_str() : p_crv->toValueString().c_str(),
			pUseQuotes
		);

		return str;
	}


	static VER_CMP_RES CompareVersions(LPCTSTR pStrVer1, LPCTSTR pStrVer2, LPCTSTR pSeparator = L".")
	{
		//Compare string version from 'pStrVer1' to 'pStrVer2'
		//'pStrVer*' = version parameter as string. Cannot be empty. All end-spaces will be trimmed out. It can contain any number of segments. Each must contain one integer. Ex: "1.234.34 beta"
		//'pSeparator' = version segment separator, L"." by default
		//RETURN:
		//		= Result
		VER_CMP_RES res = VCRES_ERROR;
		int nOSError = 0;

		if (pSeparator &&
			pSeparator[0])
		{
			if (pStrVer1 &&
				pStrVer2)
			{
				std::wstring strVer1 = pStrVer1;
				std::wstring strVer2 = pStrVer2;

				if (!AUX_FUNCS::Trim(strVer1).empty() &&
					!AUX_FUNCS::Trim(strVer2).empty())
				{
					std::vector<ULONGLONG> arrCompV1;
					if (_spliceVerComponent(strVer1, arrCompV1, pSeparator, nOSError))
					{
						std::vector<ULONGLONG> arrCompV2;
						if (_spliceVerComponent(strVer2, arrCompV2, pSeparator, nOSError))
						{
							intptr_t nCnt_V1 = arrCompV1.size();
							intptr_t nCnt_V2 = arrCompV2.size();

							if (nCnt_V1 > 0 &&
								nCnt_V2 > 0)
							{
								if (nCnt_V1 < nCnt_V2)
								{
									//Add missing components on the right
									for (intptr_t i = nCnt_V2 - nCnt_V1; i > 0; i--)
									{
										arrCompV1.push_back(0);
									}
								}
								else if (nCnt_V1 > nCnt_V2)
								{
									//Add missing components on the right
									for (intptr_t i = nCnt_V1 - nCnt_V2; i > 0; i--)
									{
										arrCompV2.push_back(0);
									}
								}

								//And now compare
								ASSERT(arrCompV1.size() == arrCompV2.size());

								//Assume equal
								res = VCRES_EQUAL;

								intptr_t nCnt_V = arrCompV1.size();
								for (intptr_t i = 0; i < nCnt_V; i++)
								{
									ULONGLONG v1 = arrCompV1[i];
									ULONGLONG v2 = arrCompV2[i];

									if (v1 < v2)
									{
										res = VCRES_V1_LESS_THAN_V2;
										break;
									}
									else if (v1 > v2)
									{
										res = VCRES_V1_GREATER_THAN_V2;
										break;
									}
								}

							}
							else
								nOSError = 4647;
						}
					}
				}
				else
					nOSError = ERROR_EMPTY;
			}
			else
				nOSError = ERROR_EMPTY;
		}
		else
			nOSError = 1799;

		::SetLastError(nOSError);
		return res;
	}

private:
	static BOOL _spliceVerComponent(std::wstring& strVer, std::vector<ULONGLONG>& arrComponents, LPCTSTR pSeparator, int& nOSError)
	{
		intptr_t nIdx = 0;
		while (true)
		{
			std::wstring strComp = AUX_FUNCS::Tokenize(strVer, pSeparator, nIdx);
			if (nIdx == -1)
				break;

			if (AUX_FUNCS::Trim(strComp).empty())
			{
				//Empty string
				nOSError = 2356;
				return FALSE;
			}

			//Get first digits only
			intptr_t i = 0;
			intptr_t nLnCmp = strComp.size();
			LPCTSTR pStrCmp = strComp.c_str();
			for (; i < nLnCmp; i++)
			{
				WCHAR z = pStrCmp[i];
				if (z >= L'0' && z <= L'9')
				{
				}
				else
					break;
			}

			if (i == 0)
			{
				//No digits
				nOSError = 777;
				return FALSE;
			}

			ULONGLONG v = _wtoi64(AUX_FUNCS::Left(strComp, i).c_str());

			arrComponents.push_back(v);

		}

		return TRUE;
	}



};

