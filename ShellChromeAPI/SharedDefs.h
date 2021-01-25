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


//Definitions shared among several projects & solutions
#pragma once

#define MAIN_APP_NAME L"Windows 10 Update Restart Blocker"
#define MAIN_APP_VER L"1.2.0"								//Main app version (don't use the 4th digit for compatibility with MSI) - if changed here, make sure to change Version in resources too!

#define EVENT_LOG_APP_NAME MAIN_APP_NAME

#define REG_KEY_SFTWR L"Software"
#define REG_KEY_COMPANY REG_KEY_SFTWR L"\\www.dennisbabkin.com"
#define REG_KEY_APP REG_KEY_COMPANY L"\\Win10RestartBlocker"
#define REG_KEY_SETTINGS REG_KEY_APP L"\\Settings"
#define REG_KEY_SHARED REG_KEY_APP L"\\Shared"

#define CLASS_NAME_SETTINGS_MAIN_WND L"www.dennisbabkin.com_win10_restart_blocker_wnd"

#define URL_DENNISBABKIN L"https://dennisbabkin.com"
#define URL_ONLINE_HELP L"https://dennisbabkin.com/php/docs.php?what=w10urb&ver=%s"
#define URL_CHECK_UPDATES L"https://dennisbabkin.com/php/update.php?name=w10urb&ver=%s"
#define URL_SUBMIT_BUG_REPORT L"https://dennisbabkin.com/sfb/?what=bug&name=%s&ver=%s&desc=%s"
#define URL_BLOG_POST L"https://dennisbabkin.com/blog/?i=AAA07000"		//Pick specific blog post here that describes how this app was researched & made

#define SUPPORT_EMAIL L"support@dennisbabkin.com"

#define REG_CONFILE_FILE_EXT L"txt"						//Do not use the dot!
#define REG_CONFILE_FILE_NAME_ONLY L"w10urbConfig"		//File name only
#define REG_CONFILE_FILE_NAME REG_CONFILE_FILE_NAME_ONLY L"." REG_CONFILE_FILE_EXT



#include <limits.h>
#include "Auxiliary.h"


#define VULN_SHELL_DLL_FILE_NAME L"ShellChromeAPI.dll"			//File Name of the vulnerable DLL
#define MAIN_UI_PROC_FILE_NAME L"Win10RestartBlockerUI.exe"		//File name of the main UI process for this app


//Names of system registry values
#define REG_VAL_NAME__VERSION L"ver"					//Installed version of the app
#define REG_VAL_NAME__GUI_APP_PATH L"path"				//Full path to the installed GUI app
#define REG_VAL_NAME__BLOCK_ENABLED L"Enabled"
#define REG_VAL_NAME__UI_TIMEOUT_SEC L"UI_Timeout"
#define REG_VAL_NAME__UI_ALLOW_SOUND L"UI_AllowSound"
#define REG_VAL_NAME__UI_ALLOW_SLEEP L"UI_AllowSleep"
#define REG_VAL_NAME__UI_SHOW_TYPE L"UI_ShowType"
#define REG_VAL_NAME__UI_SHOW_VAL_1 L"UI_ShowValue1"



#define MAX_ALLOWED_DONT_SHOW_POPUP_IN_MINS (12 * 7 * 24 * 60)			//Expressed in minutes (inclusively allowed value)

#define EVENT_NAME_GUI_APP_CLOSE_NOW L"293BD41D-ED4E-484B-B215-CCC4F8A6A38B"		//[Manual] event that can be set from outside to close the GUI settings app


//Macro to export a function
#define EXPORTED_C_FUNCTION __pragma(comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__))


//Macros for testing variadic functions
#if _MSC_VER >= 1916
#define CHECK_VARIADIC(f, ...) (_sntprintf_s(NULL, 0, 0, __VA_ARGS__), f(__VA_ARGS__))
#define CHECK_VARIADIC_P1(f, p, ...) (_sntprintf_s(NULL, 0, 0, __VA_ARGS__), f(p, __VA_ARGS__))
#else
#error Your_compiler_doesnt_support_it
#endif



//When to show reboot UI
enum UI_SHOW_TYPE{
	UI_SH_T_SHOW_ALWAYS = 0,			//Always show
	UI_SH_T_SHOW_EVERY_N_MINS,			//Only every N minutes, see "UI_ShowValue1" setting for number of minutes (can't be longer than MAX_ALLOWED_DONT_SHOW_POPUP_IN_MINS)

	UI_SH_T_COUNT						//Must be last!
};



struct APP_SETTINGS_SV_OFFSETS {
	CUST_REG_VAL_TYPE type;
	LPCTSTR pRegValName;
	size_t ncbOffset;
	size_t ncbSz;
};




struct APP_SETTINGS{

	//Read settings
	BOOL bBlockEnabled;				//TRUE to do any of the actions shown below
	int nUI_TimeOutSec;				//How soon to hide the popup (in seconds.) Or 0 to show it until user interacts with it
	BOOL bUI_AllowSound;			//TRUE to play sound when popup is shown
	BOOL bAllowSleep;				//TRUE to allow calling thread to resume idle sleep timer
	UI_SHOW_TYPE UI_ShowType;		//When popup is allowed to be shown
	int nUI_ShowVal1;				//Used depending on 'UI_ShowType'


	APP_SETTINGS(BOOL bReadFromPersistentStorage = FALSE)
		: bBlockEnabled(FALSE)
		, nUI_TimeOutSec(0)
		, bUI_AllowSound(FALSE)
		, bAllowSleep(FALSE)
		, UI_ShowType(UI_SH_T_SHOW_ALWAYS)
		, nUI_ShowVal1(0)
	{
		if(bReadFromPersistentStorage)
		{
			readAll();
		}
	}

	void setDefaults()
	{
		//Set default settings values
		bBlockEnabled = TRUE;
		nUI_TimeOutSec = 0;
		bUI_AllowSound = TRUE;
		bAllowSleep = TRUE;
		UI_ShowType = UI_SH_T_SHOW_ALWAYS;
		nUI_ShowVal1 = 0;
	}

	void readAll()
	{
		//Get defaults
		APP_SETTINGS defs(FALSE);
		defs.setDefaults();

		//Read settings
		bBlockEnabled = !!AUX_FUNCS::ReadSettingsInt32(REG_VAL_NAME__BLOCK_ENABLED, defs.bBlockEnabled);
		nUI_TimeOutSec = AUX_FUNCS::ReadSettingsInt32(REG_VAL_NAME__UI_TIMEOUT_SEC, defs.nUI_TimeOutSec);
		bUI_AllowSound = !!AUX_FUNCS::ReadSettingsInt32(REG_VAL_NAME__UI_ALLOW_SOUND, defs.bUI_AllowSound);
		bAllowSleep = !!AUX_FUNCS::ReadSettingsInt32(REG_VAL_NAME__UI_ALLOW_SLEEP, defs.bAllowSleep);
		UI_ShowType = (UI_SHOW_TYPE)AUX_FUNCS::ReadSettingsInt32(REG_VAL_NAME__UI_SHOW_TYPE, defs.UI_ShowType);
		nUI_ShowVal1 = AUX_FUNCS::ReadSettingsInt32(REG_VAL_NAME__UI_SHOW_VAL_1, defs.nUI_ShowVal1);

		//Check for correctness
		if(nUI_TimeOutSec < 0)
			nUI_TimeOutSec = INT_MAX;

		if((UINT)UI_ShowType >= UI_SH_T_COUNT)
			UI_ShowType = UI_SH_T_SHOW_ALWAYS;
	}

private:
	static const APP_SETTINGS_SV_OFFSETS* _get_APP_SETTINGS_SV_OFFSETS(intptr_t& szOutCount)
	{
		static APP_SETTINGS_SV_OFFSETS pEntries[] = {
			{CRVT_INTEGER,		REG_VAL_NAME__BLOCK_ENABLED,	offsetof(APP_SETTINGS, bBlockEnabled),	sizeof(bBlockEnabled),	},
			{CRVT_INTEGER,		REG_VAL_NAME__UI_TIMEOUT_SEC,	offsetof(APP_SETTINGS, nUI_TimeOutSec),	sizeof(nUI_TimeOutSec),	},
			{CRVT_INTEGER,		REG_VAL_NAME__UI_ALLOW_SOUND,	offsetof(APP_SETTINGS, bUI_AllowSound),	sizeof(bUI_AllowSound),	},
			{CRVT_INTEGER,		REG_VAL_NAME__UI_ALLOW_SLEEP,	offsetof(APP_SETTINGS, bAllowSleep),	sizeof(bAllowSleep),	},
			{CRVT_INTEGER,		REG_VAL_NAME__UI_SHOW_TYPE,		offsetof(APP_SETTINGS, UI_ShowType),	sizeof(UI_ShowType),	},
			{CRVT_INTEGER,		REG_VAL_NAME__UI_SHOW_VAL_1,	offsetof(APP_SETTINGS, nUI_ShowVal1),	sizeof(nUI_ShowVal1),	},
		};

		szOutCount = _countof(pEntries);

		return pEntries;
	}

public:

	BOOL to_CUSTOM_REG_VALUE_array(std::vector<CUSTOM_REG_VALUE>& arrOut)
	{
		//Convert these settings to an array in 'arrOut'
		//RETURN:
		//		= TRUE if success
		BOOL bRes = TRUE;
		CUSTOM_REG_VALUE crv;

		//Clear array
		arrOut.clear();

		intptr_t szCntEntries;
		const APP_SETTINGS_SV_OFFSETS* pEntries = _get_APP_SETTINGS_SV_OFFSETS(szCntEntries);

		for (intptr_t i = 0; i < szCntEntries; i++)
		{
			crv.type = pEntries[i].type;
			crv.strName = pEntries[i].pRegValName;

			size_t szOffs = pEntries[i].ncbOffset;
			CUST_REG_VAL_TYPE tp = pEntries[i].type;

			if (tp == CRVT_INTEGER)
			{
				//Integer
				size_t sz = pEntries[i].ncbSz;
				if (sz == sizeof(int))
				{
					crv.uiVal = *(int*)((BYTE*)this + szOffs);
				}
				else if (sz == sizeof(LONGLONG))
				{
					crv.uiVal = *(LONGLONG*)((BYTE*)this + szOffs);
				}
				else
				{
					//Bad size
					bRes = FALSE;
					break;
				}
			}
			else if (tp == CRVT_STRING)
			{
				//String
				crv.strVal = *(std::wstring*)((BYTE*)this + szOffs);
			}
			else
			{
				//Bad type
				bRes = FALSE;
				break;
			}

			arrOut.push_back(crv);
		}

		return bRes;
	}

	BOOL from_CUSTOM_REG_VALUE_array(const std::vector<CUSTOM_REG_VALUE>& arrIn)
	{
		//Convert from 'arrIn' into these settings
		//IMPORTANT: This function does not check authenticity of the data!
		//RETURN:
		//		= TRUE if success
		//		= FALSE if failed (settings in this struct could have been affected!) - check GetLastError() for info
		BOOL bRes = TRUE;
		int nOSError = 0;

		intptr_t szCntEntries;
		const APP_SETTINGS_SV_OFFSETS* pEntries = _get_APP_SETTINGS_SV_OFFSETS(szCntEntries);
		const APP_SETTINGS_SV_OFFSETS* pEntriesEnd = pEntries + szCntEntries;

		const CUSTOM_REG_VALUE* pCRV = arrIn.data();
		for (const CUSTOM_REG_VALUE* pEnd = pCRV + arrIn.size(); pCRV < pEnd; ++pCRV)
		{
			const WCHAR* pName = pCRV->strName.c_str();

			for (const APP_SETTINGS_SV_OFFSETS* pS = pEntries; pS < pEntriesEnd; ++pS)
			{
				//Registry value names are case insensitive
				if (lstrcmpi(pName, pS->pRegValName) == 0)
				{
					//Matched
					if (pS->type == CRVT_INTEGER)
					{
						if (pS->ncbSz == sizeof(int))
						{
							if (pCRV->uiVal >= INT_MIN &&
								pCRV->uiVal <= INT_MAX)
							{
								*(int*)((BYTE*)this + pS->ncbOffset) = (int)pCRV->uiVal;
							}
							else
							{
								//Overflow
								nOSError = 8322;
								bRes = FALSE;
							}
						}
						else if (pS->ncbSz == sizeof(LONGLONG))
						{
							*(LONGLONG*)((BYTE*)this + pS->ncbOffset) = pCRV->uiVal;
						}
						else
						{
							//Bad size
							nOSError = 1462;
							bRes = FALSE;
						}
					}
					else if (pS->type == CRVT_STRING)
					{
						*(std::wstring*)((BYTE*)this + pS->ncbOffset) = pCRV->strVal;
					}
					else
					{
						//Bad type
						nOSError = 8513;
						bRes = FALSE;
					}

					break;
				}
			}
		}

		::SetLastError(nOSError);
		return bRes;
	}

};


