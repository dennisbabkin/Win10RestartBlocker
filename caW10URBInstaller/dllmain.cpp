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


//Custom action DLL for the installer
#include "pch.h"

#include "CCaMain.h"




BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}



extern "C" UINT APIENTRY caFirstStage(MSIHANDLE hInstall)
{
	//Called by the MSI as a part of its "Custom Action" execution sequence -- it is called at the beginning of the MSI stage
	//INFO: The MSI installer won't continue until this method returns.
	//RETURN:
	//		INFO: http://blogs.technet.com/b/alexshev/archive/2008/02/21/from-msi-to-wix-part-5-custom-actions.aspx
	//		= ERROR_SUCCESS	0					Completed actions successfully.
	//		= ERROR_FUNCTION_NOT_CALLED	1626	Action not executed.
	//		= ERROR_INSTALL_USEREXIT	1602	User terminated prematurely.
	//		= ERROR_INSTALL_FAILURE	1603		Unrecoverable error occurred.
	//		= ERROR_NO_MORE_ITEMS	259			Skip remaining actions, not an error.
	UINT nRes = ERROR_INSTALL_FAILURE;

	//This is the exported "C" function
	EXPORTED_C_FUNCTION;

	MSI_INFO msiInfo;
	if (CCaMain::determineStage(hInstall, FALSE, msiInfo))
	{
		if (msiInfo.stage == MS_INSTALL ||
			msiInfo.stage == MS_REPAIR)
		{
			//Register event log source
			std::wstring strModPath = msiInfo.strInstallFolder + MAIN_UI_PROC_FILE_NAME;
			if (!CCaMain::RegisterEventLogSource(strModPath.c_str()))
			{
				//Error
				ReportEventLogMsgERROR_Spec_WithFormat(564, L"path: %s", strModPath.c_str());
			}
		}

		//Report an event
		ReportEventLogMsgInfo_WithFormat(L"[566] %s", msiInfo.toDebugStr(FALSE).c_str());

		//Assume success
		nRes = ERROR_SUCCESS;



		if (msiInfo.stage == MS_UNINSTALL ||
			msiInfo.stage == MS_UPGRADE_PREV)
		{
			//Do the uninstallation or upgrade
			CCaMain::OnUninstallation(msiInfo.stage == MS_UPGRADE_PREV, msiInfo);
		}

	}
	else
		ReportEventLogMsgERROR_Spec_WithFormat(552, L"h=%X", hInstall);

	return nRes;
}


extern "C" UINT APIENTRY caLastStage(MSIHANDLE hInstall)
{
	//Called by the MSI as a part of its "Custom Action" execution sequence -- it is called at the end of the MSI stage
	//INFO: The MSI installer won't continue until this method returns.
	//RETURN:
	//		INFO: http://blogs.technet.com/b/alexshev/archive/2008/02/21/from-msi-to-wix-part-5-custom-actions.aspx
	//		= ERROR_SUCCESS	0					Completed actions successfully.
	//		= ERROR_FUNCTION_NOT_CALLED	1626	Action not executed.
	//		= ERROR_INSTALL_USEREXIT	1602	User terminated prematurely.
	//		= ERROR_INSTALL_FAILURE	1603		Unrecoverable error occurred.
	//		= ERROR_NO_MORE_ITEMS	259			Skip remaining actions, not an error.
	UINT nRes = ERROR_INSTALL_FAILURE;

	//This is the exported "C" function
	EXPORTED_C_FUNCTION;

	MSI_INFO msiInfo;
	if (CCaMain::determineStage(hInstall, TRUE, msiInfo))
	{
		//Report an event
		ReportEventLogMsgInfo_WithFormat(L"[567] %s", msiInfo.toDebugStr(FALSE).c_str());

		//Assume success
		nRes = ERROR_SUCCESS;




		if (msiInfo.stage == MS_INSTALL ||
			//msiInfo.stage == MS_CHANGE ||			//We don't install anything here in the "change" notification
			msiInfo.stage == MS_REPAIR ||
			msiInfo.stage == MS_UPGRADE_NEW)
		{
			//Do the installation
			std::wstring strUsrErrDesc;
			if (!CCaMain::OnInstallation(msiInfo.stage == MS_INSTALL, msiInfo, strUsrErrDesc))
			{
				//Failed
				ReportEventLogMsgERROR_Spec_WithFormat(568, L"stage=%d, UsrErrMsg: %s", msiInfo.stage, strUsrErrDesc.c_str());

				//Return appropriate error code back to installer to abort installation
				nRes = ERROR_INSTALL_FAILURE;

				//Show error to the user
				AUX_FUNCS::Trim(strUsrErrDesc);
				if (strUsrErrDesc.empty())
					strUsrErrDesc = L"[569] Installation encountered an error and has to be aborted.";

				//Display to the user
				if (!CCaMain::Show_MSI_ErrorMessageBox(hInstall, strUsrErrDesc.c_str()))
				{
					//Failed
					ReportEventLogMsgERROR_Spec_WithFormat(573, L"stage=%d, UsrErrMsg: %s", msiInfo.stage, strUsrErrDesc.c_str());
				}
			}
		}


		
		
		if (msiInfo.stage == MS_UNINSTALL)
		{
			//Deregister event source
			if (!CCaMain::DeregisterEventLogSource())
			{
				//Error
				ReportEventLogMsgERROR_Spec_WithFormat0(565);
			}
		}

	}
	else
		ReportEventLogMsgERROR_Spec_WithFormat(547, L"h=%X", hInstall);

	return nRes;
}


