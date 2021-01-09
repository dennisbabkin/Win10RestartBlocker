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


//Custom types for this project
#pragma once


#define TSIZEOF(f) (_countof(f) - 1)


enum MSG_ID{
	MSG_ID_POST_INIT_DIALOG = (WM_APP + 1),
	MSG_ID_DRAG_N_DROP_FILE,
};



enum SAVE_OP{
	SV_O_None,

	SV_O_OK,
	SV_O_APPLY,
};


#define CMD_PARAM_RUN L"r"

struct SAVED_DATA{
	SAVE_OP saveOp;				//How data was saved

	APP_SETTINGS Sttgs;			//Settings

	SAVED_DATA()
		: saveOp(SV_O_None)
		, Sttgs(FALSE)
	{
	}

	void* toBytes(size_t* pcbOutSz)
	{
		//Serialize to byte array
		//'pcbOutSz' = if not NULL, receives size of returned array in BYTEs
		//RETURN:
		//		= Byte array (must be removed with delete[]!)
		//		= NULL if error (check GetLastError() for info)

		//Collect size
		size_t szCb = getNeededArraySz();

		BYTE* pData = new (std::nothrow) BYTE[szCb];
		if(pData)
		{
			//Fill out data
			BYTE* pD = pData;

			*(SAVE_OP*)pD = saveOp;
			pD += sizeof(saveOp);
			*(BOOL*)pD = Sttgs.bBlockEnabled;
			pD += sizeof(Sttgs.bBlockEnabled);
			*(int*)pD = Sttgs.nUI_TimeOutSec;
			pD += sizeof(Sttgs.nUI_TimeOutSec);
			*(BOOL*)pD = Sttgs.bUI_AllowSound;
			pD += sizeof(Sttgs.bUI_AllowSound);
			*(BOOL*)pD = Sttgs.bAllowSleep;
			pD += sizeof(Sttgs.bAllowSleep);
			*(UI_SHOW_TYPE*)pD = Sttgs.UI_ShowType;
			pD += sizeof(Sttgs.UI_ShowType);
			*(int*)pD = Sttgs.nUI_ShowVal1;
			pD += sizeof(Sttgs.nUI_ShowVal1);

			//Check memory alloc
			ASSERT(pD - pData == szCb);
		}
		else
		{
			//Failed
			ASSERT(NULL);
			szCb = 0;
			::SetLastError(ERROR_OUTOFMEMORY);
		}

		if(pcbOutSz)
			*pcbOutSz = szCb;

		return pData;
	}



	BOOL fromBytes(const void* pData, size_t szcbSz)
	{
		//Deserialize from byte array in 'pData'
		//'szcbSz' = size of 'pData' in BYTEs
		//RETURN:
		//		= TRUE if success
		//		= FALSE if failed (check GetLastError() for info)
		BOOL bRes = FALSE;
		int nOSError = 0;

		if(pData)
		{
			//Check size
			if(getNeededArraySz() == szcbSz)
			{
				//Collect in local var
				SAVED_DATA sd;

				const BYTE* pS = (const BYTE*)pData;

				sd.saveOp = *(SAVE_OP*)pS;
				pS += sizeof(sd.saveOp);

				sd.Sttgs.bBlockEnabled = !!*(BOOL*)pS;
				pS += sizeof(sd.Sttgs.bBlockEnabled);
				sd.Sttgs.nUI_TimeOutSec = *(int*)pS;
				pS += sizeof(sd.Sttgs.nUI_TimeOutSec);
				sd.Sttgs.bUI_AllowSound = !!*(BOOL*)pS;
				pS += sizeof(sd.Sttgs.bUI_AllowSound);
				sd.Sttgs.bAllowSleep = !!*(BOOL*)pS;
				pS += sizeof(sd.Sttgs.bAllowSleep);
				sd.Sttgs.UI_ShowType = *(UI_SHOW_TYPE*)pS;
				pS += sizeof(sd.Sttgs.UI_ShowType);
				sd.Sttgs.nUI_ShowVal1 = *(int*)pS;
				pS += sizeof(sd.Sttgs.nUI_ShowVal1);


				//Check alloc
				if(pS - (const BYTE*)pData == szcbSz)
				{
					//Check for correctness
					if(sd.Sttgs.nUI_TimeOutSec >= 0 &&
						sd.Sttgs.UI_ShowType >= 0 && sd.Sttgs.UI_ShowType < UI_SH_T_COUNT &&
						sd.Sttgs.nUI_ShowVal1 >= 0 && sd.Sttgs.nUI_ShowVal1 <= MAX_ALLOWED_DONT_SHOW_POPUP_IN_MINS)
					{
						//All good, use the data read
						*this = sd;

						bRes = TRUE;
					}
					else
					{
						//Bad data
						nOSError = ERROR_BAD_FORMAT;
					}
				}
				else
				{
					//Shouldn't get here!
					ASSERT(NULL);
					nOSError = ERROR_GEN_FAILURE;
				}
			}
			else
			{
				//Bad size
				nOSError = 24;
			}
		}
		else
			nOSError = ERROR_EMPTY;

		::SetLastError(nOSError);
		return bRes;
	}

private:
	size_t getNeededArraySz()
	{
		//Size of needed array size to serialize
		return sizeof(saveOp) + 
			sizeof(Sttgs.bBlockEnabled) + 
			sizeof(Sttgs.nUI_TimeOutSec) + 
			sizeof(Sttgs.bUI_AllowSound) + 
			sizeof(Sttgs.bAllowSleep) + 
			sizeof(Sttgs.UI_ShowType) + 
			sizeof(Sttgs.nUI_ShowVal1);
	}


};





enum CMD_LINE_PARSE_RESULTS{
	CLPR_None = 0,

	CLPR_AUTO_SAVE_ELEVATED = 0x1,		//Set when our app was started elevated from within
};




struct SHOW_WAIT_CURSOR{
	SHOW_WAIT_CURSOR()
	{
		//Set wait cursor
		hcurPrev = ::SetCursor(::LoadCursor(NULL, IDC_WAIT));
	}

	~SHOW_WAIT_CURSOR()
	{
		//Restore cursor
		::SetCursor(hcurPrev);
	}

private:
	HCURSOR hcurPrev;
};



#define HRS_UNKNOWN (-1)
#define HRS_NONE (-2)


// If you set the maximum number of files to be selected to n, the necessary buffer size is n*(_MAX_PATH + 1) + 1.
//		http://msdn.microsoft.com/library/dk77e5e7(VS.90).aspx
#define MAX_PATH_LONG_UNICODE 32767			//See: http://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx



enum POWER_OP {
	PWR_OP_REBOOT,
	PWR_OP_SHUTDOWN,
	PWR_OP_BSOD,

};



#pragma comment(lib, "ntdll.lib")

extern "C"
ULONG
NTAPI
RtlNtStatusToDosError(
	_In_ LONG Status
);


