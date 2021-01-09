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



enum MSI_STAGE
{
	MS_Unknown,				//Error, or when stage is not known yet

	MS_INSTALL,				//Called when installing new app (when it was never installed before)
							//IMPORTANT: If 'bAfter' is true, registry keys/values that were marked as HKCU will not be set here, if installer is running as system!
	MS_UNINSTALL,			//Called to completely remove the app (when user chose to uninstall it)
	MS_CHANGE,				//Called to change installation features
	MS_REPAIR,				//Called to repair existing installation (files, registry settings, etc.)
	MS_UPGRADE_PREV,		//Called by the previous version of MSI when upgrading from it to the new version of MSI (it is called first)
	MS_UPGRADE_NEW,			//Called by the new version of MSI when upgrading to it from an old version of MSI (it is called second)
							//IMPORTANT: The sequence is executed as follows:
							//				MS_UPGRADE_PREV,	'bAfter' = false	=> installation files and registry are still from previous version
							//				MS_UPGRADE_PREV,	'bAfter' = true		=> installation files may've been deleted (if there were changes between versions), and registry keys may've been deleted (if there were changes between versions). Note that if there's no changes - they will not be deleted here!
							//				MS_UPGRADE_NEW,		'bAfter' = false	=> no change since last stage
							//				MS_UPGRADE_NEW,		'bAfter' = true		=> installed files and registry keys have been updated
};



struct MSI_INFO {
	BOOL bAfterStage;					//TRUE for "After" stage
	MSI_STAGE stage;					//MSI installer stage

	RES_YES_NO_ERR resAdmin;			//Whether or not the custom action script was running elevated

	std::wstring strRawCAData;			//Raw string passed into `CustomActionData` property

	std::wstring strInstallFolder;		//Folder where the app is being installed to (always has no terminating slash) -- ex: "C:\Program Files(x86)\dennisbabkin.com\Windows 10 Update Restart Blocker\"
	std::wstring strMSIFolder;			//[Valid only if 'bAfterStage' == TRUE && stage != MS_UNINSTALL] Folder where the MSI package is being called from (always has no terminating slash) -- ex: "C:\Users\Admin\Desktop\"

	MSI_INFO()
		: bAfterStage(FALSE)
		, stage(MS_Unknown)
		, resAdmin(RYNE_ERROR)
	{}

	std::wstring toDebugStr(BOOL bIncludeRaw = TRUE)
	{
		std::wstring str = L"stage=";
		WCHAR buff[128];

		switch (stage)
		{
		case MS_Unknown:
			str += L"Unknown";
			break;
		case MS_INSTALL:
			str += L"INSTALL";
			break;
		case MS_UNINSTALL:
			str += L"UNINSTALL";
			break;
		case MS_CHANGE:
			str += L"CHANGE";
			break;
		case MS_REPAIR:
			str += L"REPAIR";
			break;
		case MS_UPGRADE_PREV:
			str += L"UPGRADE_PREV";
			break;
		case MS_UPGRADE_NEW:
			str += L"UPGRADE_NEW";
			break;
		default:
			buff[0] = 0;
			::StringCchPrintf(buff, _countof(buff), L"%d", stage);
			str += buff;
			break;
		}

		str += bAfterStage ? L"(After)" : L"(Before)";

		str += L"; admin=";
		switch (resAdmin)
		{
		case RYNE_YES:
			str += L"Yes";
			break;
		case RYNE_NO:
			str += L"No";
			break;
		default:
			assert(resAdmin == RYNE_ERROR);
			str += L"Err";
			break;
		}

		str += L"; InstallFolder=\"";
		str += strInstallFolder;
		str += L"\"";

		str += L"; MSIFolder=\"";
		str += strMSIFolder;
		str += L"\"";

		if (bIncludeRaw)
		{
			str += L"; raw: ";
			str += strRawCAData;
		}

		return str;
	}
};



enum IDX_PART {
	IDX_P_INSTALLED,
	IDX_P_REINSTALL,
	IDX_P_UPGRADEPRODUCTCODE,
	IDX_P_REMOVE,

	IDX_P_INSTALLFOLDER,
	IDX_P_MSI_FOLDER,

	IDX_P_Count						//Must be last
};



