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

#include "caTypes.h"

#include "resource.h"



class CCaMain
{
public:
	static BOOL getMSIProperty(MSIHANDLE hInstall, LPCTSTR pName, TCHAR * pBuffValue, int nchLenBuffValue);
	static BOOL determineStage(MSIHANDLE hInstall, BOOL bAfter, MSI_INFO & msiInfo);



protected:
	static BOOL isStagePartOn(std::vector<std::wstring>& arrParts, IDX_PART idx);
	static int msiMessageBox(MSIHANDLE hInstall, LPCTSTR pStrMsg, DWORD dwMSIType, DWORD dwMsgType);
public:
	static BOOL RegisterEventLogSource(LPCTSTR pModPath);
	static BOOL DeregisterEventLogSource();
	static BOOL Show_MSI_ErrorMessageBox(MSIHANDLE hInstall, LPCTSTR pStrMsg);
	static BOOL OnInstallation(BOOL bFirstInstall, MSI_INFO& msiInfo, std::wstring & strOutUserErrMsg);
	static void OnUninstallation(BOOL bUpgrade, MSI_INFO& msiInfo);
protected:
	static BOOL GetFileVersionAndOtherParameter(LPCTSTR pFilePath, VS_FIXEDFILEINFO * pOutVersionInfo = NULL, LPCTSTR pStrParamName = NULL, std::wstring * pOutParam = NULL);
	static RES_YES_NO_ERR DoesOriginalShellChromeAPIExist(LPCTSTR pStrSystem32Fldr);
	static BOOL DeployFileFromResource(LPCTSTR pDestFilePath, UINT nResID, LPCTSTR pResType = L"RT_RCDATA");
	static std::wstring GetSystem32FolderPath(BOOL b64BitOS);
	static int CloseMainGUIApps(DWORD dwmsTimeout = 5 * 1000);
};

