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
#include "pch.h"
#include "CCaMain.h"


EXTERN_C IMAGE_DOS_HEADER __ImageBase;



BOOL CCaMain::getMSIProperty(MSIHANDLE hInstall, LPCTSTR pName, TCHAR* pBuffValue, int nchLenBuffValue)
{
	//Get the property
	//'pName' = property name
	//'pBuffValue' = buffer to be filled out with property value
	//'nchLenBuffValue' = length of 'pBuffValue' in TCHARs
	//RETURN:
	//		= TRUE if value was read into 'pBuffValue', or
	//		= FALSE if error (check GetLastError() for details)
	BOOL bRes = FALSE;
	int nOSError = 0;

	if (nchLenBuffValue > 0)
	{
		//Get size
		DWORD dwBuffSz = 0;
		WCHAR chDummy[1] = {};
		if ((nOSError = ::MsiGetProperty(hInstall, pName, chDummy, &dwBuffSz)) == ERROR_MORE_DATA)
		{
			//Is string long enough
			DWORD dwBuffNeededSz = dwBuffSz + 1;
			if ((int)(dwBuffNeededSz) <= nchLenBuffValue)
			{
				//Now read value
				DWORD dwBuffReadSz = dwBuffNeededSz;
				if ((nOSError = ::MsiGetProperty(hInstall, pName, pBuffValue, &dwBuffReadSz)) == ERROR_SUCCESS)
				{
					//Check length of return buffer
					if ((dwBuffReadSz + 1) <= dwBuffNeededSz)
					{
						//Ensure that there's a last null
						pBuffValue[dwBuffReadSz + 1] = 0;

						//Safety null
						pBuffValue[nchLenBuffValue - 1] = 0;

						//Done
						nOSError = NO_ERROR;
						bRes = TRUE;
					}
					else
						nOSError = ERROR_BAD_LENGTH;
				}
			}
		}
	}
	else
		nOSError = ERROR_MORE_DATA;

	::SetLastError(nOSError);
	return bRes;
}




BOOL CCaMain::determineStage(MSIHANDLE hInstall, BOOL bAfter, MSI_INFO& msiInfo)
{
	//Determine current MSI stage
	//'hInstall' = handle passed from MSI
	//'bAfter' = true if called after the stage, false - if before
	//'msiInfo' = [valid only if returns success] receives current MSI installer info
	//RETURN:
	//		= TRUE if value was read into 'pBuffValue', or
	//		= FALSE if error (check GetLastError() for details)
	BOOL bRes = FALSE;
	int nOSError = 0;
	HRESULT hr;

	WCHAR buffCmd[0x1000];
	buffCmd[0] = 0;

	if (CCaMain::getMSIProperty(hInstall, L"CustomActionData", buffCmd, _countof(buffCmd)))
	{
		//Split special string into an array
		std::vector<std::wstring> arrParts;

		//[Installed]|||[REINSTALL]|||[UPGRADINGPRODUCTCODE]|||[REMOVE]|||[INSTALLDIR]|||[SourceDir]
		// ||| ||| ||| |||C:\Program Files(x86)\dennisbabkin.com\Windows 10 Update Restart Blocker\|||C:\Users\Admin\Desktop\ 
		const WCHAR* pEnd = buffCmd + _countof(buffCmd);
		const WCHAR* pS = buffCmd;
		const WCHAR* pB = pS;

		std::wstring strPart;

		for (; pS < pEnd; pS++)
		{
			WCHAR z = *pS;
			if (!z ||
				(z == L'|' &&
				pS + 2 < pEnd &&
				pS[1] == L'|' &&
				pS[2] == L'|')
				)
			{
				assert(pB <= pS);

				AUX_FUNCS::Trim(strPart.assign(pB, pS - pB));
				arrParts.push_back(strPart);

				if (!z)
					break;

				pS += 2;
				pB = pS + 1;
			}
		}

		//See if we have all parts provided
		size_t szcntParts = arrParts.size();
		if (szcntParts == IDX_P_Count)
		{
			//Set stage type
			msiInfo.bAfterStage = !!bAfter;
			msiInfo.strRawCAData = buffCmd;


			//Set install folder
			msiInfo.strInstallFolder = AUX_FUNCS::MakeFolderPathEndWithSlash(arrParts[IDX_P_INSTALLFOLDER]);
			AUX_FUNCS::Trim(msiInfo.strInstallFolder);

			//Set folder the MSI was running from
			msiInfo.strMSIFolder = AUX_FUNCS::MakeFolderPathEndWithSlash(arrParts[IDX_P_MSI_FOLDER]);
			AUX_FUNCS::Trim(msiInfo.strMSIFolder);


			//Check parameters for correctness
			if (!msiInfo.strInstallFolder.empty() /*&&
				(!msiInfo.strMSIFolder.empty() || !msiInfo.bAfterStage)*/)
			{

				//See if we're running as admin
				HKEY hKey = NULL;
				DWORD dwR = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_WRITE, &hKey);
				if (dwR == ERROR_SUCCESS)
				{
					msiInfo.resAdmin = RYNE_YES;

					::RegCloseKey(hKey);
				}
				else if (dwR == ERROR_ACCESS_DENIED)
				{
					msiInfo.resAdmin = RYNE_NO;
				}
				else
				{
					//Error
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(550, L"h=%X, bAfter=%d", hInstall, bAfter);
					assert(NULL);
				}


				//Get product code (use PID of the MSI.exe process)
				WCHAR buffProductCode[256];
				buffProductCode[0] = 0;
				hr = ::StringCchPrintf(buffProductCode, _countof(buffProductCode), L"x%X", ::GetCurrentProcessId());
				if(SUCCEEDED(hr))
				{
					if (!buffProductCode[0])
					{
						//Empty product code
						nOSError = 2115;
						EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(554, L"h=%X, bAfter=%d, prop: %s", hInstall, bAfter, buffCmd);
						assert(NULL);
					}
				}
				else
				{
					//Failed to get product code
					nOSError = (int)hr;
					::SetLastError(nOSError);
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(553, L"h=%X, bAfter=%d, prop: %s", hInstall, bAfter, buffCmd);
					assert(NULL);
				}



				//Make registry key to store temp values in
#define MSI_CA_TEMP_KEYS L"SOFTWARE\\DB_MSI_CA_Temp"
				WCHAR buffRegKey[256];
				hr = ::StringCchPrintf(buffRegKey, _countof(buffRegKey), MSI_CA_TEMP_KEYS L"\\%s", buffProductCode[0] ? buffProductCode : L"{8A41ABBB-F153-4A21-8245-672AAFA48917}");
				if (FAILED(hr))
				{
					nOSError = (int)hr;
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(555, L"hr=0x%X, h=%X, bAfter=%d, ProdCode: %s, prop: %s", hr, hInstall, bAfter, buffProductCode, buffCmd);
					assert(NULL);
				}

				//Define main temp registry key
				HKEY hRegKey = msiInfo.resAdmin == RYNE_YES ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;



				//SOURCE:
				//		https://stackoverflow.com/a/17608049/843732

				//Tested the following experimentally with this particular installer:
				//	[0] = Installed
				//	[1] = REINSTALL
				//	[2] = UPGRADINGPRODUCTCODE
				//	[3] = REMOVE
				//
				//									[0]			[1]			[2]			[3]
				//FRESH INSTALL:					-			-			-			-	
				//
				//UNINSTALL:						???			-			-			Str==ALL
				//(From Control Panel or via
				// context-menu "Uninstall" command
				// in Windows Explorer)
				//
				//Repeat Install:					Str			-			-			-	
				//(When MSI file is double-													
				// clicked when that same													
				// version is already														
				// installed)
				//
				//CHANGE:							Str			-			-			???
				//(From Control Panel)
				//
				//REPAIR:							Str			Str			-			-	
				//(From Control Panel)
				//
				//REPAIR:							Str			Str			-			-	
				//(Via context-menu "Repair"
				// command in Windows Explorer)
				//
				//UPGRADE (old):					Str			-			Str			Str
				//(IMPORTANT: Called from MSI of
				// previous/old version!)
				// and then
				//
				//UPGRADE (new):					-			-			-			-	
				//(Called from new MSI version)

				if (!isStagePartOn(arrParts, IDX_P_INSTALLED) && !isStagePartOn(arrParts, IDX_P_REINSTALL) &&
					!isStagePartOn(arrParts, IDX_P_UPGRADEPRODUCTCODE) && !isStagePartOn(arrParts, IDX_P_REMOVE))
				{
					//Determine what stage we're on
					BOOL bInstallFldrExisted;

					//Try to read the key first
					dwR = ::RegOpenKeyEx(hRegKey, buffRegKey, 0, KEY_READ, &hKey);
					if (dwR == ERROR_SUCCESS)
					{
						//Read its value then
						bInstallFldrExisted = FALSE;

						BYTE byData[16];
						byData[0] = 0;
						DWORD dwszData = sizeof(byData);
						dwR = ::RegQueryValueEx(hKey, NULL, NULL, NULL, byData, &dwszData);
						if (dwR == ERROR_SUCCESS &&
							dwszData > 0)
						{
							bInstallFldrExisted = !!byData[0];
						}

						::RegCloseKey(hKey);

						//Now determine the stage
						msiInfo.stage = !bInstallFldrExisted ? MS_INSTALL : MS_UPGRADE_NEW;
						bRes = TRUE;
					}
					else if (dwR == ERROR_FILE_NOT_FOUND)
					{
						//No key - then it's the first call to INSTALL stage

						//See if installation folder exists
						bInstallFldrExisted = AUX_FUNCS::IsFolderByFilePath(msiInfo.strInstallFolder.c_str());

						//Set it in a temp registry
						dwR = ::RegCreateKeyEx(hRegKey, buffRegKey, NULL, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
						if (dwR == ERROR_SUCCESS)
						{
							DWORD dwV = bInstallFldrExisted ? -1 : 0;
							dwR = ::RegSetValueEx(hKey, NULL, NULL, REG_DWORD, (const BYTE*)&dwV, sizeof(dwV));
							if (dwR == ERROR_SUCCESS)
							{
								//Pick result for the stage
								msiInfo.stage = !bInstallFldrExisted ? MS_INSTALL : MS_UPGRADE_NEW;
								bRes = TRUE;
							}
							else
							{
								//Error
								::SetLastError(dwR);
								EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(559, L"hv=0x%p, key=%s, h=%X, bAfter=%d, prop: %s", hRegKey, buffRegKey, hInstall, bAfter, buffCmd);
								assert(NULL);
								nOSError = dwR;
							}

							::RegCloseKey(hKey);
						}
						else
						{
							//Error
							::SetLastError(dwR);
							EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(558, L"hv=0x%p, key=%s, h=%X, bAfter=%d, prop: %s", hRegKey, buffRegKey, hInstall, bAfter, buffCmd);
							assert(NULL);
							nOSError = dwR;
						}
					}
					else
					{
						//Error
						::SetLastError(dwR);
						EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(556, L"hv=0x%p, key=%s, h=%X, bAfter=%d, prop: %s", hRegKey, buffRegKey, hInstall, bAfter, buffCmd);
						assert(NULL);
						nOSError = 8400;
					}


					if (bAfter)
					{
						//Delete registry value
						dwR = ::RegDeleteKey(hRegKey, buffRegKey);
						if (dwR != ERROR_SUCCESS &&
							dwR != ERROR_FILE_NOT_FOUND)
						{
							//Error
							::SetLastError(dwR);
							EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(560, L"hv=0x%p, key=%s, h=%X, bAfter=%d, prop: %s", hRegKey, buffRegKey, hInstall, bAfter, buffCmd);
							assert(NULL);
							nOSError = dwR;
						}

						::RegDeleteKey(hRegKey, MSI_CA_TEMP_KEYS);
					}
				}
				else if (/*isStagePartOn(arrParts, IDX_P_INSTALLED) &&*/ !isStagePartOn(arrParts, IDX_P_REINSTALL) &&
					!isStagePartOn(arrParts, IDX_P_UPGRADEPRODUCTCODE) && isStagePartOn(arrParts, IDX_P_REMOVE))
				{
					//Remove our temp reg value
					dwR = ::RegDeleteKey(hRegKey, buffRegKey);
					if (dwR != ERROR_SUCCESS &&
						dwR != ERROR_FILE_NOT_FOUND)
					{
						//Error
						::SetLastError(dwR);
						EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(561, L"hv=0x%p, key=%s, h=%X, bAfter=%d, prop: %s", hRegKey, buffRegKey, hInstall, bAfter, buffCmd);
						assert(NULL);
						nOSError = dwR;
					}

					::RegDeleteKey(hRegKey, MSI_CA_TEMP_KEYS);


					//Set the stage
					msiInfo.stage = lstrcmpi(arrParts[IDX_P_REMOVE].c_str(), L"ALL") == 0 ? MS_UNINSTALL : MS_CHANGE;
					bRes = TRUE;
				}
				else if (isStagePartOn(arrParts, IDX_P_INSTALLED) && !isStagePartOn(arrParts, IDX_P_REINSTALL) &&
					!isStagePartOn(arrParts, IDX_P_UPGRADEPRODUCTCODE) /*&& !isStagePartOn(arrParts, IDX_P_REMOVE)*/)
				{
					//Set the stage
					msiInfo.stage = MS_CHANGE;
					bRes = TRUE;
				}
				else if (isStagePartOn(arrParts, IDX_P_INSTALLED) && isStagePartOn(arrParts, IDX_P_REINSTALL) &&
					!isStagePartOn(arrParts, IDX_P_UPGRADEPRODUCTCODE) && !isStagePartOn(arrParts, IDX_P_REMOVE))
				{
					//Set the stage
					msiInfo.stage = MS_REPAIR;
					bRes = TRUE;
				}
				else if (isStagePartOn(arrParts, IDX_P_INSTALLED) && !isStagePartOn(arrParts, IDX_P_REINSTALL) &&
					isStagePartOn(arrParts, IDX_P_UPGRADEPRODUCTCODE) && isStagePartOn(arrParts, IDX_P_REMOVE))
				{
					if (!bAfter)
					{
						//See if installation folder exists
						BOOL bInstallFldrExisted = AUX_FUNCS::IsFolderByFilePath(msiInfo.strInstallFolder.c_str());

						//Set it in a temp registry
						dwR = ::RegCreateKeyEx(hRegKey, buffRegKey, NULL, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
						if (dwR == ERROR_SUCCESS)
						{
							DWORD dwV = bInstallFldrExisted ? -1 : 0;
							dwR = ::RegSetValueEx(hKey, NULL, NULL, REG_DWORD, (const BYTE*)&dwV, sizeof(dwV));
							if (dwR != ERROR_SUCCESS)
							{
								//Error
								::SetLastError(dwR);
								EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(563, L"hv=0x%p, key=%s, h=%X, bAfter=%d, prop: %s", hRegKey, buffRegKey, hInstall, bAfter, buffCmd);
								assert(NULL);
								nOSError = dwR;
							}

							::RegCloseKey(hKey);
						}
						else
						{
							//Error
							::SetLastError(dwR);
							EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(562, L"hv=0x%p, key=%s, h=%X, bAfter=%d, prop: %s", hRegKey, buffRegKey, hInstall, bAfter, buffCmd);
							assert(NULL);
							nOSError = dwR;
						}

					}

					//Set the stage
					msiInfo.stage = MS_UPGRADE_PREV;
					bRes = TRUE;
				}
				else
				{
					//Failed to determine the stage
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(551, L"h=%X, bAfter=%d, prop: %s", hInstall, bAfter, buffCmd);
					assert(NULL);
					nOSError = 4985;
				}
			}
			else
			{
				//Error
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(557, L"h=%X, bAfter=%d, prop: %s", hInstall, bAfter, buffCmd);
				assert(NULL);
				nOSError = ERROR_INVALID_ORDINAL;
			}
		}
		else
		{
			//Error
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(549, L"cnt=%Iu, h=%X, bAfter=%d, prop: %s", szcntParts, hInstall, bAfter, buffCmd);
			assert(NULL);
			nOSError = 1782;
		}
	}
	else
	{
		//Didn't get the custom action property
		nOSError = ::GetLastError();
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(548, L"h=%X, bAfter=%d", hInstall, bAfter);
		assert(NULL);
	}

	::SetLastError(nOSError);
	return bRes;
}

BOOL CCaMain::isStagePartOn(std::vector<std::wstring>& arrParts, IDX_PART idx)
{
	//RETURN:
	//		= TRUE if 'idx' part in 'arrParts' is not empty
	assert((size_t)idx < arrParts.size());

	return AUX_FUNCS::IsNullOrEmpty(arrParts.at(idx)) ? FALSE : TRUE;
}




BOOL CCaMain::RegisterEventLogSource(LPCTSTR pModPath)
{
	//Register Event source for the Windows Event Log
	//'pModPath' = Path to the module containing registration resources, or NULL to use this app by default
	//RETURN:
	//		= TRUE if success
	//		= FALSE if error (check GetLastError() for more info)
	BOOL bRes = FALSE;
	int nOSError = NO_ERROR;

	HKEY hKey;
	DWORD dwDisp, dwR;
	if ((dwR = ::RegCreateKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" EVENT_LOG_APP_NAME, 0, NULL, REG_OPTION_NON_VOLATILE,
		KEY_WRITE, NULL, &hKey, &dwDisp)) == ERROR_SUCCESS)
	{
		// Set the name of the message file
		if ((dwR = ::RegSetValueEx(hKey, L"EventMessageFile", 0, REG_EXPAND_SZ, (LPBYTE)pModPath,
			(DWORD)(lstrlen(pModPath) + 1) * sizeof(WCHAR))) == ERROR_SUCCESS)
		{
			// Set the supported event types
			DWORD dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
			if ((dwR = ::RegSetValueEx(hKey, L"TypesSupported", 0, REG_DWORD, (LPBYTE)&dwData, sizeof(dwData))) == ERROR_SUCCESS)
			{
				//Don't need more, call it done!
				bRes = TRUE;
			}
			else
				nOSError = dwR;
		}
		else
			nOSError = dwR;

		//Close key
		::RegCloseKey(hKey);
	}
	else
		nOSError = dwR;

	::SetLastError(nOSError);
	return bRes;
}


int CCaMain::msiMessageBox(MSIHANDLE hInstall, LPCTSTR pStrMsg, DWORD dwMSIType, DWORD dwMsgType)
{
	//Display a message box in the MSI installer
	//INFO: The message box is not displayed in case of a silent installation:
	//			http://msdn.microsoft.com/en-us/library/windows/desktop/aa372096(v=vs.85).aspx
	//'hInstall' = MSI handle
	//'pStrMsg' = Message to display
	//'dwMSIType' = can be one of the following, to give MSI type of this message:
	//				 - INSTALLMESSAGE_ERROR
	//				 - INSTALLMESSAGE_WARNING
	//				 - INSTALLMESSAGE_USER
	//'dwMsgType' = Appearance of the message box. Bitwise combination of the following groups:
	//				- Button type (use only one):
	//					- MB_OK
	//					- MB_OKCANCEL
	//					- MB_ABORTRETRYIGNORE
	//					- MB_YESNOCANCEL
	//					- MB_YESNO
	//					- MB_RETRYCANCEL
	//				- Default buttons (use only one):
	//					- MB_DEFBUTTON1
	//					- MB_DEFBUTTON2
	//					- MB_DEFBUTTON3
	//				- Icon type (use only one):
	//					- MB_ICONERROR
	//					- MB_ICONQUESTION
	//					- MB_ICONWARNING
	//					- MB_ICONINFORMATION
	//RETURN:
	//		-1			= An invalid parameter or handle was supplied -- nothing was shown.
	//		0			= No action was taken.
	//		IDABORT		= The process was stopped.
	//		IDCANCEL	= The process was canceled.
	//		IDIGNORE	= The process was ignored.
	//		IDOK		= The function succeeded.
	//		IDNO		= No.
	//		IDRETRY		= Retry.
	//		IDYES		= Yes.
	int nRet = -1;

	PMSIHANDLE record = MsiCreateRecord(0);		//Info 'PMSIHANDLE' will close our handle internally
	MSIHANDLE hRecord = record.operator MSIHANDLE();
	if (hRecord)
	{
		//Substitute all [] to () as they have special meaning
		std::wstring strMsg = pStrMsg ? pStrMsg : L"";
		AUX_FUNCS::ReplaceAll(strMsg, L'[', L'(');
		AUX_FUNCS::ReplaceAll(strMsg, L']', L')');

		if (MsiRecordSetString(hRecord, 0, strMsg.c_str()) == ERROR_SUCCESS)
		{
			//Show message
			nRet = MsiProcessMessage(hInstall, INSTALLMESSAGE(dwMSIType | dwMsgType), hRecord);
		}
		else
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(571, L"h=0x%x, hR=0x%x, msg: %s", hInstall, hRecord, pStrMsg ? pStrMsg : L"<null>");
	}
	else
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(570, L"h=0x%x, msg: %s", hInstall, pStrMsg ? pStrMsg : L"<null>");

	return nRet;
}


BOOL CCaMain::Show_MSI_ErrorMessageBox(MSIHANDLE hInstall, LPCTSTR pStrMsg)
{
	//Show an error message box for the current MSI
	//INFO: It may not show it if installation is set to silent
	//'hInstall' = MSI handle
	//'pStrMsg' = error message to display
	//RETURN:
	//		= TRUE if no error

	int nR = msiMessageBox(hInstall, pStrMsg ? pStrMsg : L"[572] Unspecified error", INSTALLMESSAGE_ERROR, MB_OKCANCEL | MB_ICONERROR);

	return nR != -1;
}


BOOL CCaMain::DeregisterEventLogSource()
{
	//De-Register Event source for the Windows Event Log
	//RETURN:
	//		= TRUE if success
	//		= FALSE if error (check GetLastError() for more info)

	int nRes = ::SHDeleteKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" EVENT_LOG_APP_NAME);
	::SetLastError(nRes);
	return nRes == ERROR_SUCCESS ||
		nRes == ERROR_FILE_NOT_FOUND ||
		nRes == ERROR_PATH_NOT_FOUND;
}


BOOL CCaMain::GetFileVersionAndOtherParameter(LPCTSTR pFilePath, VS_FIXEDFILEINFO* pOutVersionInfo, LPCTSTR pStrParamName, std::wstring* pOutParam)
{
	//Retrieve a module/file's version from the version resource
	//'pFilePath' = Path to the executable file
	//'pOutVersionInfo' = Receives the version info, if not NULL
	//						INFO: Uses 'dwProductVersionMS' for major, and 'dwProductVersionLS'  for minor, to get version numbers
	//'pStrParamName' = if not NULL, or not L"", additional version resource parameter name to retrieve additionally. Ex: "ProductName", "FileDescription"
	//					One of:
	//						https://docs.microsoft.com/en-us/windows/desktop/menurc/stringfileinfo-block
	//'pOutProductName' = if not NULL, receives the value for 'pStrParamName' parameter
	//RETURN:
	//		= TRUE if found
	//		= FALSE if error (check GetLastError() for more info)
	//				INFO: Returns error code ERROR_RESOURCE_TYPE_NOT_FOUND if file has no version resource
	BOOL bRes = FALSE;
	int nOSError = NO_ERROR;
	std::wstring strFilePath = pFilePath;
	LPCTSTR pDescBuf = NULL;

	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	};

	std::wstring strParamName;

	//Do we have a file?
	BYTE* pData = NULL;
	if (!strFilePath.empty())
	{
		//Get size needed
		DWORD dwDummy;
		DWORD dwSz = ::GetFileVersionInfoSize((LPTSTR)strFilePath.c_str(), &dwDummy);
		if (dwSz > 0)
		{
			//Reserve mem
			pData = new (std::nothrow)BYTE[dwSz];
			if (pData)
			{
				//Retrieve version info
				if (::GetFileVersionInfo((LPTSTR)strFilePath.c_str(), NULL, dwSz, pData))
				{
					UINT nczBufLn;
					VS_FIXEDFILEINFO* pVi = NULL;
					if (VerQueryValue(pData, _T("\\"), (VOID**)&pVi, &nczBufLn))
					{
						if (pVi &&
							nczBufLn >= sizeof(*pVi) &&
							pVi->dwSignature == 0xFEEF04BD)
						{
							//Got it
							bRes = TRUE;

							if (pOutVersionInfo)
								*pOutVersionInfo = *pVi;
						}
						else
							nOSError = ERROR_ARENA_TRASHED;
					}
					else
						nOSError = ERROR_INVALID_DATA;


					//Do we need a param too?
					if (pStrParamName &&
						pStrParamName[0])
					{
						struct LANGANDCODEPAGE
						{
							WORD wLanguage;
							WORD wCodePage;
						} *lpTranslate = NULL;

						// Read the list of languages and code pages.
						UINT cbTranslate;
						if (VerQueryValue(pData, L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate))
						{
							//Get first language
							if (lpTranslate &&
								cbTranslate >= sizeof(*lpTranslate))
							{
								//Retrieve product name
								WCHAR buff_strBlock[1024] = {};
								HRESULT hr = ::StringCchPrintf(buff_strBlock, _countof(buff_strBlock),
									L"\\StringFileInfo\\%04x%04x\\%s",
									lpTranslate[0].wLanguage,
									lpTranslate[0].wCodePage,
									pStrParamName);
								if (hr == S_OK)
								{
									UINT dwProdLn = 0;
									VOID* lpBufferName = NULL;
									if (VerQueryValue(pData, buff_strBlock, &lpBufferName, &dwProdLn))
									{
										//Get name
										strParamName.resize(dwProdLn);
										memcpy(&strParamName[0], lpBufferName, dwProdLn * sizeof(TCHAR));
									}
									else
									{
										nOSError = ::GetLastError();
									}
								}
								else
									nOSError = (int)hr;
							}
						}
					}
				}
				else
					nOSError = ::GetLastError();
			}
			else
			{
				//Mem fault
				nOSError = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
			nOSError = ::GetLastError();
	}
	else
		nOSError = ERROR_FILE_NOT_FOUND;


	if (pOutParam)
		*pOutParam = strParamName;

	//Free mem
	if (pData)
		delete[] pData;

	::SetLastError(nOSError);
	return bRes;
}

RES_YES_NO_ERR CCaMain::DoesOriginalShellChromeAPIExist(LPCTSTR pStrSystem32Fldr)
{
	//Check that a original ShellChromeAPI.dll exists in the system folder
	//INFO: We don't want to overwrite it if it's actually there....
	//'pStrSystem32Fldr' = path to the System32 folder
	//RETURN:
	//		= RYNE_YES if that DLL already exists and we shouldn't mess with it
	//		= RYNE_NO if that DLL does not exist, or if it exists but it's not the original copy -- in that case GetLastError() will be set to one of:
	//					1760 = if it's copy of that DLL
	//		= RYNE_ERROR if error - check GetLastError() for details
	RES_YES_NO_ERR res = RYNE_ERROR;
	int nOSError = 0;

	if (pStrSystem32Fldr &&
		pStrSystem32Fldr[0])
	{
		//Get path to this DLL
		WCHAR buffDll[MAX_PATH];
		buffDll[0] = 0;
		HRESULT hr = ::StringCchPrintf(buffDll, _countof(buffDll), L"%s%s",
			AUX_FUNCS::MakeFolderPathEndWithSlash(pStrSystem32Fldr, TRUE).c_str(),
			VULN_SHELL_DLL_FILE_NAME);

		if (SUCCEEDED(hr))
		{
			//Check the company name from the resource
			std::wstring strName;
			if (GetFileVersionAndOtherParameter(buffDll, NULL, L"CompanyName", &strName))
			{
				//We put our own name into the "patch" ShellChromeAPI.dll so that we can distinguish it.
				if (lstrcmpi(strName.c_str(), L"dennisbabkin.com") == 0)
				{
					//It's our DLL -- we probably placed it there before during a previous run of this app
					nOSError = 1760;
					res = RYNE_NO;
				}
				else
				{
					//Some other DLL is there
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(577, L"CompanyName=\"%s\", Path=\"%s\"", strName.c_str(), buffDll);
					nOSError = 5010;
				}
			}
			else
			{
				//See why we failed
				nOSError = ::GetLastError();

				if (nOSError == ERROR_FILE_NOT_FOUND)
				{
					//No such DLL -- like it should be originally
					res = RYNE_NO;
				}
				else
				{
					//Some other error
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(576, L"%s", buffDll);
				}
			}
		}
		else
			nOSError = (int)hr;
	}
	else
		nOSError = 12009;

	::SetLastError(nOSError);
	return res;
}

BOOL CCaMain::DeployFileFromResource(LPCTSTR pDestFilePath, UINT nResID, LPCTSTR pResType)
{
	//Deploy the file from a resource to 'pDestFilePath' file
	//'pDestFilePath' = file path to save data in
	//'nResID' = Resource ID for the file data
	//'pResType' = Resource type (see FindResource() for types)
	//RETURN:
	//		= TRUE if success
	//		= FALSE if error (check GetLastError() for info)
	BOOL bRes = FALSE;
	int nOSError = NO_ERROR;

	HMODULE hModule = (HMODULE)&__ImageBase;	// ::GetModuleHandle(NULL);
	HRSRC hRes = ::FindResource(hModule, MAKEINTRESOURCE(nResID), pResType);
	if (hRes)
	{
		DWORD dwSz = ::SizeofResource(hModule, hRes);
		HGLOBAL hGlobal = ::LoadResource(hModule, hRes);
		if (dwSz && hGlobal)
		{
			//Get resource data & size
			LPVOID pData = LockResource(hGlobal);
			if (pData && dwSz)
			{
				//Create file
				//INFO: No sharing for reading, in case the file is attempted to executed...
				HANDLE hFile = ::CreateFile(pDestFilePath, GENERIC_WRITE, 0 /*FILE_SHARE_READ*/, NULL, CREATE_ALWAYS,
					FILE_ATTRIBUTE_NORMAL, NULL);
				if (hFile != INVALID_HANDLE_VALUE)
				{
					//Write file
					DWORD dwcbWrtn = 0;
					if (::WriteFile(hFile, pData, dwSz, &dwcbWrtn, NULL) &&
						dwcbWrtn == dwSz)
					{
						//Done
						bRes = TRUE;
					}
					else
					{
						nOSError = ::GetLastError();
						if (nOSError == NO_ERROR)
							nOSError = ERROR_WRITE_FAULT;
					}

					::CloseHandle(hFile);
				}
				else
					nOSError = ::GetLastError();

			}
			else
				nOSError = ERROR_ARENA_TRASHED;
		}
		else
			nOSError = ERROR_INVALID_HANDLE;
	}
	else
		nOSError = ERROR_INVALID_FUNCTION;

	::SetLastError(nOSError);
	return bRes;
}


std::wstring CCaMain::GetSystem32FolderPath(BOOL b64BitOS)
{
	//'b64BitOS' = TRUE if we're running on a 64-bit OS
	//RETURN:
	//		= Slash terminated path to the System32 folder (for a 32-bit process)
	//		= L"" if error (wrong build of this module)
	std::wstring strSysFldrs;
	WCHAR buff[MAX_PATH];

#ifndef _M_X64
	if (b64BitOS)
	{
		//64-bit OS
		buff[0] = 0;
		::GetWindowsDirectory(buff, _countof(buff));

		//We're 32-bit process on 64-bit OS -- use redirected "C:\Windows\SysNative" to access 64-bit folder
		strSysFldrs = AUX_FUNCS::MakeFolderPathEndWithSlash(AUX_FUNCS::MakeFolderPathEndWithSlash(buff, TRUE) + L"SysNative", TRUE);
	}
	else
	{
		//32-bit OS
		buff[0] = 0;
		::GetSystemDirectory(buff, _countof(buff));
		strSysFldrs = AUX_FUNCS::MakeFolderPathEndWithSlash(buff, TRUE);
	}
#else
	//64-bit OS - can't use this build!
	buff[0] = 0;
	EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(575);
	assert(NULL);
#endif

	return strSysFldrs;
}





int CCaMain::CloseMainGUIApps(DWORD dwmsTimeout)
{
	//Try to close all open main GUI apps
	//'dwmsTimeout' = timeout to wait for, in ms
	//RETURN:
	//		= 0 if there was no GUI apps to close
	//		= 1 if at least one GUI app was closed
	//		= -1 if failed
	//		= -2 if timed out
	int nRes = 0;

	DWORD dwmsIniTicks = ::GetTickCount();

	for (;;)
	{
		//Open shared named event
		HANDLE hEventQuit = AUX_FUNCS::CreateSharedEvent(EVENT_NAME_GUI_APP_CLOSE_NOW, TRUE);
		if (hEventQuit)
		{
			//See if event existed before - this would mean that at least one GUI app was running
			BOOL bNeed2Wait = ::GetLastError() == ERROR_ALREADY_EXISTS;

			if (bNeed2Wait)
			{
				//Need to signal the app and wait for it to close ...
				nRes = 1;

				//Set the event to signal all GUI apps to close
				if (::SetEvent(hEventQuit))
				{
					//Give it some time
					::Sleep(100);
				}
				else
				{
					//Error
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(617);

					bNeed2Wait = FALSE;
					nRes = -1;
				}
			}

			//Close event
			::CloseHandle(hEventQuit);

			if (!bNeed2Wait)
				break;

			//Check for timeout
			DWORD dwmsElapsed = ::GetTickCount() - dwmsIniTicks;
			if (dwmsElapsed > dwmsTimeout)
			{
				//Timed out
				::SetLastError(ERROR_TIMEOUT);
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(618, L"to=%u, t=%u", dwmsTimeout, dwmsElapsed);

				nRes = -2;
				break;
			}
		}
		else
		{
			//Error
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(616);

			nRes = -1;
			break;
		}
	}

	return nRes;
}




BOOL CCaMain::OnInstallation(BOOL bFirstInstall, MSI_INFO& msiInfo, std::wstring& strOutUserErrMsg)
{
	//Is called to install the product
	//'bFirstInstall' = TRUE if we're installing it for the first time
	//'msiInfo' = MSI installer stage parameters
	//RETURN:
	//		= TRUE to continue with installation
	//		= FALSE to display an error that must be returned in 'strOutUserErrMsg' and abort installation
	BOOL bResult = TRUE;

	//Clear error message
	strOutUserErrMsg.clear();

	DWORD dwR;


	//Get installation folder (always has last slash!)
	std::wstring strInstallFldr = AUX_FUNCS::MakeFolderPathEndWithSlash(msiInfo.strInstallFolder, FALSE);
	if (!strInstallFldr.empty())
	{
		strInstallFldr = AUX_FUNCS::MakeFolderPathEndWithSlash(strInstallFldr, TRUE);


		if (!bFirstInstall)
		{
			//Before we begin re-install, repair, or upgrade close all open GUI apps if we have any
			//		= 0 if there was no GUI apps to close
			//		= 1 if at least one GUI app was closed
			//		= -1 if failed
			//		= -2 if timed out
			int nRzCMGA = CCaMain::CloseMainGUIApps();
			if (nRzCMGA < 0)
			{
				//Error
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(622, L"r=%d", nRzCMGA);
			}
		}


		//Is it a 64-bit OS?
		RES_YES_NO_ERR res64bit = AUX_FUNCS::Is64BitOS();
		if (res64bit == RYNE_ERROR)
		{
			//Error
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(574);
		}


		if (bFirstInstall)
		{
			//Set which OS we're installing on
			EVENT_LOG_REPORTS::ReportEventLogMsgInfo_WithFormat(L"[684] Installing on %s OS", 
				res64bit != RYNE_ERROR ? (res64bit == RYNE_YES ? L"64-bit" : L"32-bit") : L"unknown-bitness"
			);
		}


		//Get System32 folder path - always has last slash
		BOOL b64bit = res64bit == RYNE_YES ;
		std::wstring strSysFldrs = GetSystem32FolderPath(b64bit);


		//Make sure that the System32 folder doesn't contain the original patch module VULN_SHELL_DLL_FILE_NAME
		//INFO: In case Microsoft has already patched it!
		//		= RYNE_YES if that DLL already exists and we shouldn't mess with it
		//		= RYNE_NO if that DLL does not exist, or if it exists but it's not the original copy -- in that case GetLastError() will be set to one of:
		//					1760 = if it's copy of that DLL
		//		= RYNE_ERROR if error - check GetLastError() for details
		RES_YES_NO_ERR resDll = DoesOriginalShellChromeAPIExist(strSysFldrs.c_str());

		if (resDll == RYNE_NO)
		{
			//System DLL is good - can install now!

			//Make installation paths
			std::wstring strFile_GUIapp;
			std::wstring strFile_SysDll;
			std::wstring strBuff;
			HKEY hKey = NULL;
			HKEY hKeyShared = NULL;
			WCHAR buffErr[1024];
			std::vector<CUSTOM_REG_VALUE> arrCRVs;
			int nSpecErr = 0;

			std::wstring strErrDesc_ComponentErr = L" Failed to deploy component";


			AUX_FUNCS::Format(strFile_GUIapp, L"%s%s", strInstallFldr.c_str(), MAIN_UI_PROC_FILE_NAME);
			AUX_FUNCS::Format(strFile_SysDll, L"%s%s", strSysFldrs.c_str(), VULN_SHELL_DLL_FILE_NAME);


			//Install the UI settings app
			if(!CCaMain::DeployFileFromResource(strFile_GUIapp.c_str(), b64bit ? IDR_RT_RCD_MAIN_UI_PROC_FILE_x64 : IDR_RT_RCD_MAIN_UI_PROC_FILE_x86))
			{
				//Failed
				nSpecErr = 585;
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(584, L"path: %s >> %s", strFile_GUIapp.c_str(), msiInfo.toDebugStr().c_str());

lbl_comp_err:
				//Set error message to show to the user
				dwR = ::GetLastError();
				AUX_FUNCS::Format(strOutUserErrMsg, L"[%d] %s:\n\n"
					L"(%d) %s"
					,
					nSpecErr,
					strErrDesc_ComponentErr.c_str(),
					dwR,
					AUX_FUNCS::getFormattedErrorMsg(dwR, buffErr, _countof(buffErr))
				);

				//And fail
				bResult = FALSE;
				goto lbl_cleanup;
			}


			//Install VULN_SHELL_DLL_FILE_NAME module into the system folder
			if (!CCaMain::DeployFileFromResource(strFile_SysDll.c_str(), b64bit ? IDR_RT_RCD_VULN_SHELL_DLL_x64 : IDR_RT_RCD_VULN_SHELL_DLL_x86))
			{
				//Failed
				nSpecErr = 587;
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(586, L"path: %s >> %s", strFile_SysDll.c_str(), msiInfo.toDebugStr().c_str());
				goto lbl_comp_err;
			}


			//Add registry keys
			dwR = ::RegCreateKeyEx(HKEY_LOCAL_MACHINE, REG_KEY_SETTINGS, NULL, NULL, 0, 
				KEY_WRITE | (b64bit ? KEY_WOW64_64KEY : 0),
				NULL, &hKey, NULL);
			if (dwR != ERROR_SUCCESS)
			{
				//Failed
				nSpecErr = 589;
				::SetLastError(dwR);
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(588, L"b=%d >> %s", b64bit, msiInfo.toDebugStr().c_str());
				goto lbl_comp_err;
			}


			//Set any user provided options
			if (bFirstInstall)
			{
				if (!msiInfo.strMSIFolder.empty())
				{
					//Get registry settings from a special registry configuration file file
					std::wstring strConfigFilePath = AUX_FUNCS::MakeFolderPathEndWithSlash(msiInfo.strMSIFolder, TRUE) + REG_CONFILE_FILE_NAME;

					//Does such file exist
					if (AUX_FUNCS::IsFileByFilePath(strConfigFilePath.c_str()))
					{
						//Read all the configuration parameters
						if (AUX_FUNCS::GetRegConfigFileContents(strConfigFilePath.c_str(), &arrCRVs))
						{
							//Find version
							CUSTOM_REG_VALUE* pVer = AUX_FUNCS::find_CUSTOM_REG_VALUE_byName(arrCRVs, REG_VAL_NAME__VERSION);
							if (pVer &&
								pVer->type == CRVT_STRING)
							{
								//Check version against the current one
								BOOL bVersionOK = FALSE;
								VER_CMP_RES rezVer = AUX_FUNCS::CompareVersions(pVer->strVal.c_str(), MAIN_APP_VER);
								if (rezVer == VCRES_EQUAL ||
									rezVer == VCRES_V1_LESS_THAN_V2)
								{
									//All good
									bVersionOK = TRUE;
								}
								else if (rezVer == VCRES_V1_GREATER_THAN_V2)
								{
									//Config file of newer version
									bVersionOK = FALSE;
								}
								else
								{
									//Error
									EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(679, L"ver=\"%s\"", pVer->strVal.c_str());

									AUX_FUNCS::Format(strOutUserErrMsg, L"[680] Failed to parse version in provided configuration file:\n%s", strConfigFilePath.c_str());

									bResult = FALSE;
									goto lbl_cleanup;
								}



								//Apply configuration file into registry
#define MAX_ALLOWED_EVENT_VWR_ENTRIES 16
								size_t nCntApplied = 0, nCntShwn = 0;
								strBuff.clear();

								size_t szCntCRVs = arrCRVs.size();
								if (szCntCRVs)
								{
									const CUSTOM_REG_VALUE* pCRV = &arrCRVs[0];
									for (const CUSTOM_REG_VALUE* pE = pCRV + szCntCRVs; pCRV < pE; pCRV++)
									{
										if (!pCRV->strName.empty())
										{
											DWORD dwType;
											const BYTE* pS;
											DWORD dwcbSzS;

											if (pCRV->type == CRVT_INTEGER)
											{
												pS = (const BYTE*)&pCRV->uiVal;

												if (pCRV->IsValue32BitInteger(TRUE))
												{
													//32-bit
													dwType = REG_DWORD;
													dwcbSzS = sizeof(int);
												}
												else
												{
													//64-bit
													dwType = REG_QWORD;
													dwcbSzS = sizeof(LONGLONG);
												}
											}
											else if (pCRV->type == CRVT_STRING)
											{
												dwType = REG_SZ;
												pS = (const BYTE*)pCRV->strVal.c_str();
												dwcbSzS = (DWORD)((pCRV->strVal.size() + 1) * sizeof(WCHAR));
											}
											else
											{
												//Bad type
												EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(599, L"t=%d >> %s", pCRV->type, msiInfo.toDebugStr().c_str());
												continue;
											}


											//Set registry value
											dwR = ::RegSetValueEx(hKey, pCRV->strName.c_str(), NULL, dwType, pS, dwcbSzS);
											if (dwR == ERROR_SUCCESS)
											{

												//Count it
												nCntApplied++;

												if (nCntShwn < MAX_ALLOWED_EVENT_VWR_ENTRIES)
												{
													//Format for event log
													AUX_FUNCS::AppendFormat(strBuff, L"%s\n",
														AUX_FUNCS::CUSTOM_REG_VALUE_to_NameValue_Str(pCRV).c_str());

													nCntShwn++;
												}
											}
											else
											{
												//Failed to set
												::SetLastError(dwR);
												EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(600, L"%s, type=%d, dwType=%d, sz=%d >> %s",
													pCRV->strName.c_str(),
													pCRV->type,
													dwType,
													dwcbSzS,
													msiInfo.toDebugStr().c_str());

												nSpecErr = 604;
												AUX_FUNCS::Format(strErrDesc_ComponentErr, L"Failed to set system registry key: '%s'",
													pCRV->strName.c_str()
												);

												::SetLastError(dwR);
												goto lbl_comp_err;
											}
										}
									}
								}


								//Put message about it into the event log
								BOOL(*pfnReportEventLog)(LPCTSTR pDescFormat, ...);
								pfnReportEventLog = bVersionOK ? EVENT_LOG_REPORTS::ReportEventLogMsgInfo_WithFormat : EVENT_LOG_REPORTS::ReportEventLogMsgWARNING_WithFormat;

								pfnReportEventLog(L"[674] Applied %Id system registry setting(s) from config file%s:\n%s\n\n%s%s"
									,
									nCntApplied,
									bVersionOK ? L"" : AUX_FUNCS::EasyFormat(L", from newer version file (v.%s)", pVer->strVal.c_str()).c_str(),
									strConfigFilePath.c_str(),
									strBuff.c_str(),
									nCntApplied <= MAX_ALLOWED_EVENT_VWR_ENTRIES ? L"" : L"**Abridged**"
								);
							}
							else
							{
								//Bad version in config file
								EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(677, L"pV=0x%p, type=%d", pVer, pVer ? pVer->type : -1);

								AUX_FUNCS::Format(strOutUserErrMsg, L"[678] Unknown or misconfigured version of provided configuration file:\n%s", strConfigFilePath.c_str());

								bResult = FALSE;
								goto lbl_cleanup;
							}
						}
						else
						{
							//Failed to read config file
							dwR = ::GetLastError();
							EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(597, L"path=\"%s\" >> %s", strConfigFilePath.c_str(), msiInfo.toDebugStr().c_str());

							AUX_FUNCS::Format(strOutUserErrMsg, L"[598] Failed to read provided configuration file:\n"
								L"%s\n\n"
								L"(%d) %s"
								,
								strConfigFilePath.c_str(),
								dwR,
								AUX_FUNCS::getFormattedErrorMsg(dwR, buffErr, _countof(buffErr))
							);

							bResult = FALSE;
							goto lbl_cleanup;
						}
					}
				}
				else
				{
					//Error
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(596, L"%s", msiInfo.toDebugStr().c_str());
				}
			}


			//Set installation folder
			if ((dwR = ::RegSetValueEx(hKey, REG_VAL_NAME__GUI_APP_PATH, NULL, REG_SZ, (const BYTE*)strFile_GUIapp.c_str(), (DWORD)(strFile_GUIapp.size() + 1) * sizeof(WCHAR))) != ERROR_SUCCESS)
			{
				//Failed
				::SetLastError(dwR);
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(590, L"%s >> %s", strFile_GUIapp.c_str(), msiInfo.toDebugStr().c_str());
			}

			//Set version
			if ((dwR = ::RegSetValueEx(hKey, REG_VAL_NAME__VERSION, NULL, REG_SZ, (const BYTE*)MAIN_APP_VER, sizeof(MAIN_APP_VER))) != ERROR_SUCCESS)
			{
				//Failed
				::SetLastError(dwR);
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(591, L"%s", msiInfo.toDebugStr().c_str());
			}



			//Create a Shared subkey
			dwR = ::RegCreateKeyEx(HKEY_LOCAL_MACHINE, REG_KEY_SHARED, NULL, NULL, 0,
				KEY_WRITE | READ_CONTROL | WRITE_DAC | (b64bit ? KEY_WOW64_64KEY : 0),
				NULL, &hKeyShared, NULL);
			if (dwR == ERROR_SUCCESS)
			{
				//Set its sharing
				if (!AUX_FUNCS::MakeRegKeyShared(hKeyShared))
				{
					//Failed to set sharing on the key
					EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(632, L"%s", msiInfo.toDebugStr().c_str());
				}

				//Close key
				::RegCloseKey(hKeyShared);
				hKeyShared = NULL;
			}
			else
			{
				//Failed
				::SetLastError(dwR);
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(631, L"%s", msiInfo.toDebugStr().c_str());
			}




lbl_cleanup:
			//See if everything was fine?
			///////////////////////////////////
			if (hKey)
			{
				::RegCloseKey(hKey);
				hKey = NULL;
			}

			if (!bResult)
			{
				//Recover all changes
				AUX_FUNCS::DeleteFileSmart(strFile_GUIapp.c_str());
				AUX_FUNCS::DeleteFileSmart(strFile_SysDll.c_str());

				if (hKey)
				{
					//Delete registry key
					::RegDeleteKeyEx(HKEY_LOCAL_MACHINE, REG_KEY_SETTINGS, KEY_WRITE | (b64bit ? KEY_WOW64_64KEY : 0), NULL);
				}
			}

		}
		else if (resDll == RYNE_YES)
		{
			//Origina VULN_SHELL_DLL_FILE_NAME module is there!
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(580, L"path: %s >> %s", strSysFldrs.c_str(), msiInfo.toDebugStr().c_str());

			strOutUserErrMsg = L"[581] The system component has already been patched. Installation on this computer is not possible.";
			bResult = FALSE;
		}
		else
		{
			//Error determening type of the VULN_SHELL_DLL_FILE_NAME module
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(578, L"r=%d, path: %s >> %s", resDll, strSysFldrs.c_str(), msiInfo.toDebugStr().c_str());

			strOutUserErrMsg = L"[579] Failed to determine the type of the system component. Contact support at " SUPPORT_EMAIL;
			bResult = FALSE;
		}
	}
	else
	{
		//No installation folder
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(582, L"%s", msiInfo.toDebugStr().c_str());

		strOutUserErrMsg = L"[583] Incorrect installation parameter. Contact support at " SUPPORT_EMAIL;
		bResult = FALSE;
	}

	return bResult;
}







void CCaMain::OnUninstallation(BOOL bUpgrade, MSI_INFO& msiInfo)
{
	//Is called to uninstall the product
	//'bUpgrade' = TRUE if we're uninstalling before an upgrade to a newer version, or FALSE if we're uninstalling the app
	//'msiInfo' = MSI installer stage parameters
	DWORD dwR;


	//First close the running GUI app
	//		= 0 if there was no GUI apps to close
	//		= 1 if at least one GUI app was closed
	//		= -1 if failed
	//		= -2 if timed out
	int nRzCMGA = CCaMain::CloseMainGUIApps();
	if (nRzCMGA < 0)
	{
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(623, L"r=%d", nRzCMGA);
	}


	//Is it a 64-bit OS?
	RES_YES_NO_ERR res64bit = AUX_FUNCS::Is64BitOS();
	if (res64bit == RYNE_ERROR)
	{
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(592);
	}


	//Get System32 folder path - always has last slash
	BOOL b64bit = res64bit == RYNE_YES;
	std::wstring strSysFldrs = GetSystem32FolderPath(b64bit);

	//Get installation folder (always has last slash!)
	std::wstring strInstallFldr = AUX_FUNCS::MakeFolderPathEndWithSlash(msiInfo.strInstallFolder, FALSE);
	if (!strInstallFldr.empty())
	{
		strInstallFldr = AUX_FUNCS::MakeFolderPathEndWithSlash(strInstallFldr, TRUE);
	}


	std::wstring strFile_SysDll;

	AUX_FUNCS::Format(strFile_SysDll, L"%s%s", strSysFldrs.c_str(), VULN_SHELL_DLL_FILE_NAME);



	//Delete VULN_SHELL_DLL_FILE_NAME module
	if (!AUX_FUNCS::DeleteFileSmart(strFile_SysDll.c_str()))
	{
		//Error
		EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(594, L"path=\"%s\" >> %s", strFile_SysDll.c_str(), msiInfo.toDebugStr().c_str());
	}

	if (!strInstallFldr.empty())
	{
		std::wstring strFile_GUIapp;
		AUX_FUNCS::Format(strFile_GUIapp, L"%s%s", strInstallFldr.c_str(), MAIN_UI_PROC_FILE_NAME);

		//Delete Settings UI file
		if (!AUX_FUNCS::DeleteFileSmart(strFile_GUIapp.c_str()))
		{
			//Error
			EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(595, L"path=\"%s\" >> %s", strFile_GUIapp.c_str(), msiInfo.toDebugStr().c_str());
		}

	}


	
	//Only if uninstalling completely
	if (!bUpgrade)
	{
		//Remove registry keys
		struct {
			LPCTSTR pStrKeyName;
			BOOL bMustBeDeleted;
		}
		delRegKeys[] = {
			{REG_KEY_SHARED,		TRUE,},
			{REG_KEY_SETTINGS,		TRUE,},
			{REG_KEY_APP,			TRUE,},
			{REG_KEY_COMPANY,		FALSE,},
		};

		for (int d = 0; d < _countof(delRegKeys); d++)
		{
			dwR = ::RegDeleteKeyEx(HKEY_LOCAL_MACHINE, delRegKeys[d].pStrKeyName, KEY_WRITE | (b64bit ? KEY_WOW64_64KEY : 0), NULL);

			BOOL bOk;
			if (delRegKeys[d].bMustBeDeleted)
			{
				//Key must be deleted
				bOk = dwR == ERROR_SUCCESS || dwR == ERROR_FILE_NOT_FOUND;
			}
			else
			{
				//Key can be deleted or it may fail if it's not empty
				bOk = dwR == ERROR_SUCCESS || dwR == ERROR_ACCESS_DENIED;
			}

			if (!bOk)
			{
				::SetLastError(dwR);
				EVENT_LOG_REPORTS::ReportEventLogMsgERROR_Spec_WithFormat(626, L"key=\"%s\", %s", delRegKeys[d].pStrKeyName, msiInfo.toDebugStr().c_str());
			}
		}


	}

}

