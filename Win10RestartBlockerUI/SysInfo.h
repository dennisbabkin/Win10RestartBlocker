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


//Class that collects information about this system for reporting purposes

#pragma once

#ifndef SIZEOF
#define SIZEOF(f) (sizeof(f) / sizeof(f[0]))
#endif

#include <new>

#include <Strsafe.h>
#include <ctype.h>
#include <math.h>

#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#include <Wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")


#pragma warning( push )
#pragma warning( disable : 4995 )	//C4995
#include <algorithm>
#include <functional>
#include <cctype>
#pragma warning( pop )


namespace SysInfo{


enum COLLECT_SYS_INFO
{
	CSI_DATE_TIME = 0x1,				//Current date & time
	CSI_OS_NAME = 0x2,					//OS name, build, bitness
	CSI_LOCALE = 0x4,					//Language and locale info
	CSI_RAM = 0x8,						//RAM info: total and free
	CSI_DISK_OS = 0x10,					//System disk (c:) info: total and free
	CSI_DISK_APP = 0x20,				//Disk where app runs from info: total and free
	CSI_PROC_ELEV_GUEST_RDC = 0x40,		//App proc info: elevated, guest, remote desktop connection

	CSI_MASK_ALL = (CSI_DATE_TIME | CSI_OS_NAME | CSI_LOCALE | CSI_RAM | CSI_DISK_OS | CSI_DISK_APP | CSI_PROC_ELEV_GUEST_RDC),
	CSI_MASK_ALL_EXCEPT_DISK = (CSI_DATE_TIME | CSI_OS_NAME | CSI_LOCALE | CSI_RAM | CSI_PROC_ELEV_GUEST_RDC),
};



#ifndef FILETIME_TO_NS
#define FILETIME_TO_NS(ft) ((((ULONGLONG)ft.dwHighDateTime) << 32) | (ULONGLONG)ft.dwLowDateTime)
#endif

#ifndef NS_TO_FILETIME
#define NS_TO_FILETIME(ns, ft) ft.dwHighDateTime = (DWORD)(ns >> 32); ft.dwLowDateTime = (DWORD)ns;
#endif

enum PATH_PREFIX_TYPE
{
	PPT_UNKNOWN,
	PPT_ABSOLUTE,					//Found absolute path that is none of the other types
	PPT_UNC,						//Found \\server\share\ prefix
	PPT_LONG_UNICODE,				//Found \\?\ prefix
	PPT_LONG_UNICODE_UNC,			//Found \\?\UNC\ prefix
};






struct SYS_INFO_COLLECTOR{

static std::wstring EscapeURL(LPCTSTR pStrURL)
{
	//Escape characters in 'pStrURL' to be inseted into URL
	//RETURN:
	//		= Escaped URL string

	//Convert to UTF-8
	std::string strA;
	if(GetUTF8String(pStrURL, strA))
	{
		return EscapeURL(strA.c_str());
	}

	return std::wstring();
}

static std::wstring EscapeURL(LPCSTR pStrURL)
{
	//Escape characters in 'pStrURL' to be inseted into URL
	//RETURN:
	//		= Escaped URL string
	std::wstring strOut;

	int nLn = pStrURL ? lstrlenA(pStrURL) : 0;
	for(int i = 0; i < nLn; i++)
	{
		BYTE z = pStrURL[i];

		//The following has been checked with Server.UrlEncode(s); in C#!!!!!
		if(z == ' ')
		{
			strOut += _T('+');
		}
		else if(z == '-' ||
			z == '_' ||
			z == '!' ||
			z == '*' ||
			z == '(' ||
			z == ')' ||
			z == '.' ||
			(z < 0x80 && _istalnum(z)))
		{
			strOut += z;
		}
		else //if(z < 0x100)
		{
			__AppendFormat(strOut, 
				_T("%%%x%x"), 
				(BYTE)(z >> 4),
				(BYTE)(z & 0xf));
		}
	}

	return strOut;
}

static void __Format(std::wstring& s, LPCTSTR pszFormat, ...)
{
	//Format the string
	int nOSErr = ::GetLastError();

	va_list argList;
	va_start( argList, pszFormat );
	
	//Get length
	int nLnBuff = _vscwprintf(pszFormat, argList);

	//Reserve a buffer
	TCHAR* pBuff = new (std::nothrow) TCHAR[nLnBuff + 1];
	if(pBuff)
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

static void __Format(std::wstring* pStr, LPCTSTR pszFormat, ...)
{
	//Format the string
	int nOSErr = ::GetLastError();
	ASSERT(pStr);

	va_list argList;
	va_start( argList, pszFormat );
	
	//Get length
	int nLnBuff = _vscwprintf(pszFormat, argList);

	//Reserve a buffer
	TCHAR* pBuff = new (std::nothrow) TCHAR[nLnBuff + 1];
	if(pBuff)
	{
		//Do formatting
		vswprintf_s(pBuff, nLnBuff + 1, pszFormat, argList);

		if(pStr)
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

static void __AppendFormat(std::wstring& s, LPCTSTR pszFormat, ...)
{
	//Format the string
	int nOSErr = ::GetLastError();

	va_list argList;
	va_start( argList, pszFormat );
	
	//Get length
	int nLnBuff = _vscwprintf(pszFormat, argList);

	//Reserve a buffer
	TCHAR* pBuff = new (std::nothrow) TCHAR[nLnBuff + 1];
	if(pBuff)
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

static std::wstring __Left(std::wstring &s, size_t nCount)
{
	return s.substr(0, nCount);
}

static std::wstring __Right(std::wstring &s, size_t nCount)
{
	return s.substr(s.length() - nCount, nCount);
}

static std::wstring __Mid(std::wstring &s, int iFirst, int nCount)
{
	return s.substr(iFirst, nCount);
}

static std::wstring& __lTrim(std::wstring &s)
{
	//Trim all white-spaces from the left side of 's'
	//RETURN: = Same trimmed string
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
	return s;
}

static std::wstring& __rTrim(std::wstring &s)
{
	//Trim all white-spaces from the right side of 's'
	//RETURN: = Same trimmed string
	s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
	return s;
}

static std::wstring& __Trim(std::wstring &s)
{
	//Trim all white-spaces from 's'
	//RETURN: = Same trimmed string
	return __lTrim(__rTrim(s));
}

static void __replaceAll(std::wstring& str, const std::wstring& from, const std::wstring& to)
{
	//Replace all occurances of 'from' in 'str' with 'to'
	size_t nLn_from = from.length();
	size_t nLn_to = to.length();

	size_t start_pos = 0;
	while((start_pos = str.find(from, start_pos)) != std::wstring::npos)
	{
		str.replace(start_pos, nLn_from, to);
		start_pos += nLn_to;			 // Handles case where 'to' is a substring of 'from'
	}
}

static void __replaceAll(std::wstring& str, LPCTSTR from, LPCTSTR to)
{
	//Get string length
	size_t nLn_from = 0;
	while(from[nLn_from])
	{
		nLn_from++;
	}

	//Get string length
	size_t nLn_to = 0;
	while(to[nLn_to])
	{
		nLn_to++;
	}

    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::wstring::npos) {
        str.replace(start_pos, nLn_from, to);
        start_pos += nLn_to; // Handles case where 'to' is a substring of 'from'
    }
}

static void __replaceAll(std::wstring& str, TCHAR chFrom, TCHAR chTo)
{
	//Replace all occurances of 'chFrom' in 'str' with 'chTo'
	TCHAR* pStr = &str[0];
	size_t nLn = str.size();

	for(size_t i = 0; i < nLn; i++)
	{
		if(pStr[i] == chFrom)
			pStr[i] = chTo;
	}
}


static BOOL GetUTF8String(LPCTSTR pStr, std::string& strOutUTF8)
{
	//Convert UNICODE string into UTF-8 string
	//RETURN:
	//		= TRUE if success
	return GetStringForEncoding(pStr, CP_UTF8, strOutUTF8);
}

static BOOL GetStringForEncoding(LPCTSTR pStr, UINT nCodePage, std::string& strOut, BOOL* pbOutDataLoss = NULL)
{
	//Convert UNICODE string into UTF-8 string
	//'pbOutDataLoss' = if not NULL, will receive TRUE if data loss occurred during conversion
	//RETURN:
	//		= TRUE if success
	//		= FALSE if error -- check GetLastError() for info
	BOOL bRes = FALSE;
	BOOL bUsedDefault = FALSE;
	int nOSError = NO_ERROR;

	//Free string
	strOut.clear();

	if(pStr &&
		pStr[0])
	{
		//Get length needed
		int ncbLen = ::WideCharToMultiByte(nCodePage, 0, pStr, -1, 0, 0, NULL, NULL);
		if(ncbLen > 0)
		{
			//Check if code page accepts default char
			BOOL bUseDefChar = pbOutDataLoss &&
				nCodePage != CP_UTF8 &&
				nCodePage != CP_UTF7;

			//Reserve mem
			strOut.resize(ncbLen);

			//Convert
			const char def[] = "?";
			if(::WideCharToMultiByte(nCodePage, 0, pStr, -1, &strOut[0], ncbLen, 
				bUseDefChar ? def : NULL, bUseDefChar ? &bUsedDefault : NULL) == ncbLen)
			{
				//Success
				strOut[ncbLen - 1] = 0;
				bRes = TRUE;
			}
			else
				nOSError = ::GetLastError();
		}
		else
			nOSError = ::GetLastError();
	}
	else
	{
		//Empty string
		bRes = TRUE;
	}

	if(pbOutDataLoss)
		*pbOutDataLoss = bUsedDefault;

	::SetLastError(nOSError);
	return bRes;
}


static void GetBriefSystemInfo(std::wstring& str, DWORD dwTypeMask = CSI_MASK_ALL)
{
	//Collect brief system info for transmission to the web server during feedback submission
	//'str' = Collected data as string
	//'dwTypeMask' = bitmasked values from COLLECT_SYS_INFO enum

	__try
	{
		str.clear();

		__getBriefSystemInfo(str, (COLLECT_SYS_INFO)dwTypeMask);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		//Failed
#ifdef _DEBUG
		::DebugBreak();
#endif
	}
}


static std::wstring GetLocaleName(LCID lcid = LOCALE_USER_DEFAULT)
{
	//Get locale name by LCID
	//'lcid' = ID of the locale
	//			INFO: Can be set to LOCALE_USER_DEFAULT, etc.
	//RETURN: = Name of the locale by 'lcid', or
	//		  = Empty string if error
	std::wstring strLocale;

	TCHAR szBuf[MAX_PATH] = {0};
	if(::GetLocaleInfo(lcid, LOCALE_SENGLANGUAGE, szBuf, TSIZEOF(szBuf)))
	{
		strLocale = szBuf;
		if(::GetLocaleInfo(lcid, LOCALE_SENGCOUNTRY, szBuf, TSIZEOF(szBuf)))
		{
			if(_tcsclen(szBuf) != 0)
			{
				strLocale += _T("_");
				strLocale += szBuf;
			}
			if(::GetLocaleInfo(lcid, LOCALE_IDEFAULTANSICODEPAGE, szBuf, TSIZEOF(szBuf)))
			{
				if(_tcsclen(szBuf) != 0)
				{
					strLocale += _T(".");
					strLocale += szBuf;
				}
				else
					strLocale.clear();
			}
			else
				strLocale.clear();
		}
		else
			strLocale.clear();
	}

	return strLocale;
}


static std::wstring FormatKiloMegaGigaTera(ULONGLONG nVal, LPCTSTR pEndingStrShort = _T("B"), LPCTSTR pEndingStrLong = _T("Byte"), BOOL bUseExactThousands = FALSE, BOOL bUsePlurals = TRUE)
{
	//Convert 64 bit value from 'nVal' into formatted number
	//'pEndingStrShort' = Specify short abbreviation of units, example: "B" as in KB
	//'pEndingStrLong' = Specify long abbreviation of units, example: "Byte" as in Bytes
	//'bUseExactThousands' = TRUE to use 1000 as divider, or FALSE to use 1024
	//'bUsePlurals' = TRUE to add 's' to the end of a value less than 1K, like in "Byte" s
	std::wstring strSz;

	if(!pEndingStrShort)
		pEndingStrShort = L"";
	if(!pEndingStrLong)
		pEndingStrLong = L"";

	// http://en.wikipedia.org/wiki/Terabyte

	//Get divider
	unsigned __int64 nDividerK = bUseExactThousands ? 1000LL :					1024LL;
	unsigned __int64 nDividerM = bUseExactThousands ? 1000000LL :				1024LL * 1024;
	unsigned __int64 nDividerG = bUseExactThousands ? 1000000000LL :			1024LL * 1024 * 1024;
	unsigned __int64 nDividerT = bUseExactThousands ? 1000000000000LL :			1024LL * 1024 * 1024 * 1024;
	unsigned __int64 nDividerP = bUseExactThousands ? 1000000000000000LL :		1024LL * 1024 * 1024 * 1024 * 1024;				//PB	petabyte
	//unsigned __int64 nDividerE = bUseExactThousands ? 1000000000000000000LL :	1024LL * 1024 * 1024 * 1024 * 1024 * 1024;		//EB	exabyte

	if(nVal < nDividerK)
	{
		//Bytes
		int nV = (int)nVal;
		__Format(strSz, _T("%u %s%s"), 
			nV,
			pEndingStrLong,
			bUsePlurals && nVal != 1 ? _T("s") : _T(""));
	}
	else if(nVal < nDividerM)
	{
		//KBytes
		double fV = (double)nVal / nDividerK;
		__Format(strSz, _T("%.2f K%s"), fV, pEndingStrShort);
	}
	else if(nVal < nDividerG)
	{
		//MBytes
		double fV = (double)nVal / nDividerM;
		__Format(strSz, _T("%.2f M%s"), fV, pEndingStrShort);
	}
	else if(nVal < nDividerT)
	{
		//GBytes
		double fV = (double)nVal / nDividerG;
		__Format(strSz, _T("%.2f G%s"), fV, pEndingStrShort);
	}
	else if(nVal < nDividerP)
	{
		//TBytes
		double fV = (double)nVal / nDividerT;
		__Format(strSz, _T("%.2f T%s"), fV, pEndingStrShort);
	}
	else
	{
		//PBytes
		double fV = (double)nVal / nDividerP;
		__Format(strSz, _T("%.2f P%s"), fV, pEndingStrShort);
	}

	return strSz;
}


static std::wstring MakeFolderPathEndWithSlash(LPCTSTR pPath, BOOL bAttachSlash = TRUE)
{
	//RETURN: = Folder always ending with a slash, except empty string path, if 'bAttachSlash' == TRUE, or
	//			 always without it if 'bAttachSlash' == FALSE
	std::wstring FolderPath = pPath ? pPath : _T("");

	size_t nLn = FolderPath.size();
	if(nLn > 0)
	{
		TCHAR c = FolderPath[nLn - 1];
		if(bAttachSlash)
		{
			if(c != '/' && c != '\\')
			{
				//Find previous slash
				TCHAR ch = '\\';
				for(size_t i = FolderPath.size() - 1; i >= 0; i--)
				{
					TCHAR z = FolderPath[i];
					if(z == '\\' || z == '/')
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
			if(c == '/' || c == '\\')
				FolderPath = __Left(FolderPath, nLn - 1);
		}
	}

	return FolderPath;
}


static LPCTSTR PathSkipRoot_CorrectedForMicrosoftStupidity(LPCTSTR pszPath)
{
	//Correction for PathSkipRoot API
	//RETURN:
	//		= Pointer to the TCHAR after the root (Example: Pointer to "Folder\file.txt" for "C:\Folder\file.txt")
	//		= Pointer to "" if no path (Example: Pointer to "" for "C:" or "C:\")
	//		= NULL if failed because of no root

	//Check for NULL string
	if(!pszPath ||
		pszPath[0] == 0)
		return NULL;

	//Use local buffer
	std::wstring strPath;
	size_t nLn = lstrlen(pszPath);
	
	//Convert to a new buffer and add some additional data to the end
	//INFO: Evidently the API on some versions of Windows is pretty sloppy that keeps checking after the end of path!
	//		Check comments of this page for details:
	//			http://msdn.microsoft.com/en-us/library/windows/desktop/bb773754(v=vs.85).aspx
	strPath.resize(nLn + 32);		//Allow additional chars
	TCHAR* pBuff = &strPath[0];
	memcpy(pBuff, pszPath, (nLn + 1) * sizeof(TCHAR));

	//Replace all /'s with \'s because PathSkipRoot can't handle /'s
	for(size_t i = 0; i < nLn; i++)
	{
		if(pBuff[i] == L'/')
			pBuff[i] = L'\\';
	}

	//Now call the API
	LPCTSTR pResBuff = ::PathSkipRoot(pBuff);
	if(!pResBuff)
		return NULL;

	size_t nOffset = pResBuff - pBuff;
	if(nOffset >= 0 &&
		nOffset <= nLn)
	{
		return pszPath + nOffset;
	}

	return NULL;
}

static BOOL PathIsRelative_CorrectedForMicrosoftStupidity(LPCTSTR pszPath)
{
	//Correction for PathIsRelative API
	std::wstring strPath = pszPath;

	//Replace all /'s with \'s because PathIsRelative can't handle /'s
	__replaceAll(strPath, L'/', L'\\');

	//Now call the API
	return ::PathIsRelative(strPath.c_str());
}


static size_t GetOffsetAfterPathRoot(LPCTSTR pPath, PATH_PREFIX_TYPE* pOutPrefixType = NULL)
{
	//Checks if 'pPath' begins with the drive, share,  prefix, etc
	//EXAMPLES:
	//			Path							Return:			Points at:							PrefixType:
	//			Relative\Folder\File.txt		 0					Relative\Folder\File.txt			PPT_UNKNOWN
	//			\RelativeToRoot\Folder			 1					RelativeToRoot\Folder				PPT_ABSOLUTE
	//			C:\Windows\Folder				 3					Windows\Folder						PPT_ABSOLUTE
	//			\\server\share\Desktop			 15					Desktop								PPT_UNC
	//			\\?\C:\Windows\Folder			 7					Windows\Folder						PPT_LONG_UNICODE
	//			\\?\UNC\server\share\Desktop	 21					Desktop								PPT_LONG_UNICODE_UNC
	//RETURN:
	//		= Index in 'pPath' after the root, or
	//		= 0 if no root was found
	size_t nRetInd = 0;
	PATH_PREFIX_TYPE ppt = PPT_UNKNOWN;

	if(pPath &&
		pPath[0] != 0)
	{
		int nLen = lstrlen(pPath);

		//Determine version of Windows
		OSVERSIONINFO osi;
		osi.dwOSVersionInfoSize = sizeof(osi);
#pragma warning( push )
#pragma warning( disable : 4996 )
		BOOL bWinXPOnly = ::GetVersionEx(&osi) && osi.dwMajorVersion <= 5;
#pragma warning( pop )

		//The PathSkipRoot() doesn't work correctly on Windows XP
		if(!bWinXPOnly)
		{
			//Works since Vista and up
			LPCTSTR pPath2 = PathSkipRoot_CorrectedForMicrosoftStupidity(pPath);
			if(pPath2 &&
				pPath2 >= pPath)
			{
				nRetInd = pPath2 - pPath;
			}
		}

		//Now determine the type of prefix
		int nIndCheckUNC = -1;

		if(nLen >= 8 &&
			(pPath[0] == L'\\' || pPath[0] == L'/') &&
			(pPath[1] == L'\\' || pPath[1] == L'/') &&
			pPath[2] == L'?' &&
			(pPath[3] == L'\\' || pPath[3] == L'/') &&
			(pPath[4] == L'U' || pPath[4] == L'u') &&
			(pPath[5] == L'N' || pPath[5] == L'n') &&
			(pPath[6] == L'C' || pPath[6] == L'c') &&
			(pPath[7] == L'\\' || pPath[7] == L'/')
			)
		{
			//Found \\?\UNC\ prefix
			ppt = PPT_LONG_UNICODE_UNC;

			if(bWinXPOnly)
			{
				//For older Windows XP
				nRetInd += 8;
			}

			//Check for UNC share later
			nIndCheckUNC = 8;
		}
		else if(nLen >= 4 &&
			(pPath[0] == L'\\' || pPath[0] == L'/') &&
			(pPath[1] == L'\\' || pPath[1] == L'/') &&
			pPath[2] == L'?' &&
			(pPath[3] == L'\\' || pPath[3] == L'/')
			)
		{
			//Found \\?\ prefix
			ppt = PPT_LONG_UNICODE;

			if(bWinXPOnly)
			{
				//For older Windows XP
				nRetInd += 4;
			}
		}
		else if(nLen >= 2 &&
			(pPath[0] == L'\\' || pPath[0] == L'/') &&
			(pPath[1] == L'\\' || pPath[1] == L'/')
			)
		{
			//Check for UNC share later
			nIndCheckUNC = 2;
		}

		if(nIndCheckUNC >= 0)
		{
			//Check for UNC, i.e. \\server\share\ part
			int i = nIndCheckUNC;
			for(int nSkipSlashes = 2; nSkipSlashes > 0; nSkipSlashes--)
			{
				for(; i < nLen; i++)
				{
					TCHAR z = pPath[i];
					if(z == L'\\' ||
						z == L'/' ||
						i + 1 >= nLen)
					{
						i++;
						if(nSkipSlashes == 1)
						{
							if(ppt == PPT_UNKNOWN)
								ppt = PPT_UNC;

							if(bWinXPOnly)
							{
								//For older Windows XP
								nRetInd = i;
							}
						}

						break;
					}
				}
			}
		}

		if(bWinXPOnly)
		{
			//Only if we didn't determine any other type
			if(ppt == PPT_UNKNOWN)
			{
				if(!PathIsRelative_CorrectedForMicrosoftStupidity(pPath + nRetInd))
				{
					ppt = PPT_ABSOLUTE;
				}
			}

			//For older Windows XP
			LPCTSTR pPath2 = PathSkipRoot_CorrectedForMicrosoftStupidity(pPath + nRetInd);
			if(pPath2 &&
				pPath2 >= pPath)
			{
				nRetInd = pPath2 - pPath;
			}

		}
		else
		{
			//Only if we didn't determine any other type
			if(ppt == PPT_UNKNOWN)
			{
				if(!PathIsRelative_CorrectedForMicrosoftStupidity(pPath))
				{
					ppt = PPT_ABSOLUTE;
				}
			}
		}
	}

	if(pOutPrefixType)
		*pOutPrefixType = ppt;

	return nRetInd;
}


static std::wstring GetFolderOnly(LPCTSTR pFilePath, BOOL bKeepLastSlash = FALSE)
{
	//Removes file name from the path
	//INFO: Takes into account various path prefixes and roots, example: \\?\ or C:\ or \\server\share\
	//'bKeepLastSlash' = TRUE to keep folder terminating slash, if it was there
	//					(Example: For "C:\Windows\Calc.exe" will return "C:\Windows")
	//RETURN: 
	//		= Folder path only by the file path, or
	//		= Empty string if no folder found in the path

	std::wstring strRet, path = pFilePath ? pFilePath : L"";

	//Get the index when the prefix ends
	//			Path							Return:			Points at:							PrefixType:
	//			Relative\Folder\File.txt		 0					Relative\Folder\File.txt			PPT_UNKNOWN
	//			\RelativeToRoot\Folder			 1					RelativeToRoot\Folder				PPT_ABSOLUTE
	//			C:\Windows\Folder				 3					Windows\Folder						PPT_ABSOLUTE
	//			\\server\share\Desktop			 15					Desktop								PPT_UNC
	//			\\?\C:\Windows\Folder			 7					Windows\Folder						PPT_LONG_UNICODE
	//			\\?\UNC\server\share\Desktop	 21					Desktop								PPT_LONG_UNICODE_UNC
	size_t nIndRoot = GetOffsetAfterPathRoot(pFilePath);

	BOOL bLastForwardSlash = FALSE;
	size_t nFnd = path.find_last_of(L"\\");
	if(nFnd == std::wstring::npos)
	{
		nFnd = path.find_last_of('/');
		if(nFnd != -1)
			bLastForwardSlash = TRUE;
	}

	if(nFnd != -1)
	{
		size_t nSlashInd = nIndRoot - 1;
		if((size_t)nFnd <= nSlashInd)
		{
			nFnd = nIndRoot;

			if(path[nSlashInd] == '\\' || path[nSlashInd] == '/')
				nFnd--;
		}

		strRet = __Left(path, nFnd);

		if(bKeepLastSlash)
			strRet += !bLastForwardSlash ? L'\\' : L'/';
	}

	return strRet;
}


static int IsRunningUnderGuestAccount(void)
{
	//Determine if the current process was started from a guest account
	//PROBLEM: When this process is elevated under Guest acct!!!!
	//RETURN:
	//		= 0 if running under a Guest account
	//		= 1 if not running as Guest
	//		= -1 if error determining -- check GetLastError() for info
	int nRes = -1;
	int nOSError = NO_ERROR;

	HANDLE hUserToken;
	if(::OpenProcessToken(::GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hUserToken))
	{
		//Duplicate the token
		HANDLE hAccessToken;
		if(::DuplicateToken(hUserToken, SecurityIdentification, &hAccessToken))
		{
			//Allocate SID
			PSID psidGroupSid;
			SID_IDENTIFIER_AUTHORITY siaNtAuthority = SECURITY_NT_AUTHORITY;
			if(::AllocateAndInitializeSid(&siaNtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
				DOMAIN_ALIAS_RID_GUESTS, 0, 0, 0, 0, 0, 0, &psidGroupSid))
			{
				BOOL bIsMember;
				if(::CheckTokenMembership(hAccessToken, psidGroupSid, &bIsMember))
				{
					//Done it
					nRes = bIsMember != 0 ? 0 : 1;
				}
				else
				{
					//Failed
					nOSError = ::GetLastError();
				}

				//Free mem
				::FreeSid(psidGroupSid);
			}
			else
				nOSError = ::GetLastError();

			//Close token
			::CloseHandle(hAccessToken);
		}
		else
			nOSError = ::GetLastError();

		//Close token
		::CloseHandle(hUserToken);
	}
	else
		nOSError = ::GetLastError();

	::SetLastError(nOSError);
	return nRes;
}


static int IsRunningWithElevatedPrivileges(void)
{
	//Determine if the current process is running with elevated privileges
	//RETURN:
	//		0 - if not running elevated
	//		0x80 - if running elevated
	//		-1 - if error determining -- check GetLastError() for info
	int nRes = -1;
	int nOSError = NO_ERROR;

	//See what version of Windows we're running on
	OSVERSIONINFO osi;
	osi.dwOSVersionInfoSize = sizeof(osi);
#pragma warning( push )
#pragma warning( disable : 4996 )
	BOOL bGV = GetVersionEx(&osi);
#pragma warning( pop )
	ASSERT(bGV);

	BOOL bWinVista = bGV && osi.dwMajorVersion > 5;

	//See what verson of windows
	if(bWinVista)
	{
		//Vista and later OK
		struct xxTOKEN_ELEVATION {
			DWORD TokenIsElevated;
		};

		HANDLE hAccessToken;
		if(::OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hAccessToken))
		{
			DWORD dwSz;
			xxTOKEN_ELEVATION te = {0};

			#ifndef TokenElevation
			#define TokenElevation 20
			#endif

			if(::GetTokenInformation(hAccessToken, (TOKEN_INFORMATION_CLASS)TokenElevation, &te, sizeof(te), &dwSz))
			{
				//Make result
				nRes = te.TokenIsElevated ? 0x80 : 0;
			}
			else
				nOSError = ::GetLastError();

			::CloseHandle(hAccessToken);
		}
		else
			nOSError = ::GetLastError();
	}
	else
	{
		//Windows XP
		HANDLE hUserToken;
		if(::OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hUserToken))
		{
			//Duplicate the token
			HANDLE hAccessToken;
			if(::DuplicateToken(hUserToken, SecurityIdentification, &hAccessToken))
			{
				//See how much memory do we need
				DWORD dwSz = 0;
				::GetTokenInformation(hAccessToken, TokenGroups, NULL, 0, &dwSz);
				if((int)dwSz > 0)
				{
					//Reserve mem
					BYTE* pData = new (std::nothrow) BYTE[dwSz];
					if(pData)
					{
						//Get group accounts info
						if(::GetTokenInformation(hAccessToken, TokenGroups, pData, dwSz, &dwSz))
						{
							//Allocate SID
							PSID psidAdministrators;
							SID_IDENTIFIER_AUTHORITY siaNtAuthority = SECURITY_NT_AUTHORITY;
							if(::AllocateAndInitializeSid(&siaNtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
								DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &psidAdministrators))
							{
								//Go thru all groups
								nRes = 0;
								PTOKEN_GROUPS ptgGroups = (PTOKEN_GROUPS)pData;
								for(DWORD x = 0; x < ptgGroups->GroupCount; x++)
								{
									if(::EqualSid(psidAdministrators, ptgGroups->Groups[x].Sid))
									{
										//This is an admin
										nRes = 0x80;
										break;
									}
								}

								//Free mem
								::FreeSid(psidAdministrators);
							}
							else
								nOSError = ::GetLastError();
						}
						else
							nOSError = ::GetLastError();

						//Free mem
						delete[] pData;
					}
					else
						nOSError = ERROR_OUTOFMEMORY;
				}
				else
					nOSError = ::GetLastError();

				//Close token
				::CloseHandle(hAccessToken);
			}
			else
				nOSError = ::GetLastError();

			//Close token
			::CloseHandle(hUserToken);
		}
		else
			nOSError = ::GetLastError();
	}

	::SetLastError(nOSError);
	return nRes;
}

static int IsRunningWithRemoteDesktopConnection()
{
	//Checks if this process is running under a Remote Desktop Connection
	//RETURN:
	//		= 1 if yes
	//		= 0 if no
	//		= -1 if error (check GetLastError() for more details)
	int nRes = -1;
	int nOSError = NO_ERROR;

	DWORD dwProcID = ::GetCurrentProcessId();

	//Get session Id
	DWORD nSessID = -1;
	if(::ProcessIdToSessionId(dwProcID, &nSessID))
	{
		//Query protocol type
		DWORD dwSz;
		LPTSTR ppBuffer = NULL;
		if(::WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, nSessID, WTSClientProtocolType, &ppBuffer, &dwSz))
		{
			//Make sure that it's not an RDP session (such session is a listening "dud")
			if(ppBuffer &&
				dwSz >= sizeof(USHORT))
			{
				//Check the result
				USHORT uR = *(USHORT*)ppBuffer;

				nRes = uR == 2 ? 1 : 0;
			}
			else
			{
				//Error
				nOSError = ERROR_INVALID_BLOCK;
			}
		}
		else
		{
			//Error
			nOSError = ::GetLastError();
		}
		
		//Free mem
		if(ppBuffer)
			::WTSFreeMemory(ppBuffer);
	}
	else
	{
		//Error
		nOSError = ::GetLastError();
	}

	//Set last error
	::SetLastError(nOSError);
	return nRes;
}







static inline BOOL GetWindowsNameAndVersion(std::wstring& ver)
{
	//Get current Windows OS name, version and bitness
	//'ver' = receives string version
	//RETURN:
	//		= TRUE if no error
	return _get_win_ver(ver);
}




private:

static BOOL _get_win_ver(std::wstring& ver)
{
	//RETURN: = TRUE and string representing the current Windows version in 'ver'

	//RETURN: Type of OS as string
	//(Get periodic updates to this code from the MSDN page for description of GetVersionEx() API)
	std::wstring& res = ver;
	#define BUFSIZE 1024

	typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);
	typedef BOOL (WINAPI *PGPI)(DWORD, DWORD, DWORD, DWORD, PDWORD);

	#define MY_STRING_CCH_COPY(pszDest, pszSrc) ::StringCchCopy(pszDest, SIZEOF(pszDest), pszSrc)
	#define MY_STRING_CCH_CAT(pszDest, pszSrc) ::StringCchCat(pszDest, SIZEOF(pszDest), pszSrc)
	#define MY_SPRINTF(pszDest, pszFormat, ...) ::StringCchPrintf(pszDest, SIZEOF(pszDest), pszFormat, __VA_ARGS__)

	RTL_OSVERSIONINFOEXW osvi = {};
	SYSTEM_INFO si = {};
	PGNSI pGNSI;
	PGPI pGPI;
	BOOL bOsVersionInfoEx;
	DWORD dwType;

	osvi.dwOSVersionInfoSize = sizeof(osvi);

	if( !(bOsVersionInfoEx = AUX_FUNCS::CheckWindowsVersion(&osvi)) )
	{
		res = _T("?");
		return FALSE;
	}

	// Call GetNativeSystemInfo if supported or GetSystemInfo otherwise.
	TCHAR pszOS[BUFSIZE];

	pGNSI = (PGNSI) GetProcAddress(
		GetModuleHandle(TEXT("kernel32.dll")), 
		"GetNativeSystemInfo");
	if(NULL != pGNSI)
		pGNSI(&si);
	else GetSystemInfo(&si);

	if ( VER_PLATFORM_WIN32_NT==osvi.dwPlatformId && 
		osvi.dwMajorVersion > 4 )
	{
		MY_STRING_CCH_COPY(pszOS, TEXT("Microsoft "));

		// Test for the specific product.

		if ( osvi.dwMajorVersion == 10 )
		{
			if( osvi.dwMinorVersion == 0)
			{
				if( osvi.wProductType == VER_NT_WORKSTATION )
					MY_STRING_CCH_CAT(pszOS, TEXT("Windows 10 "));		//Windows 10
				else
					MY_STRING_CCH_CAT(pszOS, TEXT("Windows Server 10 "));		//Windows Server 10
			}

			goto lbl_get_product_info;
		}

		if ( osvi.dwMajorVersion == 6 )
		{
			if( osvi.dwMinorVersion == 0 )
			{
			if( osvi.wProductType == VER_NT_WORKSTATION )
				MY_STRING_CCH_CAT(pszOS, TEXT("Windows Vista "));
			else MY_STRING_CCH_CAT(pszOS, TEXT("Windows Server 2008 " ));
			}

			if ( osvi.dwMinorVersion == 1 )
			{
			if( osvi.wProductType == VER_NT_WORKSTATION )
				MY_STRING_CCH_CAT(pszOS, TEXT("Windows 7 "));
			else MY_STRING_CCH_CAT(pszOS, TEXT("Windows Server 2008 R2 " ));
			}

			if( osvi.dwMinorVersion == 2)
			{
				if( osvi.wProductType == VER_NT_WORKSTATION )
					MY_STRING_CCH_CAT(pszOS, TEXT("Windows 8 "));		//Windows 8
				else
					MY_STRING_CCH_CAT(pszOS, TEXT("Windows Server 2012 "));		//Windows Server 2012
			}

			if( osvi.dwMinorVersion == 3)
			{
				if( osvi.wProductType == VER_NT_WORKSTATION )
					MY_STRING_CCH_CAT(pszOS, TEXT("Windows 8.1 "));		//Windows 8.1
				else
					MY_STRING_CCH_CAT(pszOS, TEXT("Windows Server 2012 R2 "));		//Windows Server 2012 R2
			}

			if( osvi.dwMinorVersion == 4)
			{
				if( osvi.wProductType == VER_NT_WORKSTATION )
					MY_STRING_CCH_CAT(pszOS, TEXT("Windows 10 Preview "));		//Windows 10
				else
					MY_STRING_CCH_CAT(pszOS, TEXT("Windows Server 10 Preview "));		//Windows Server 10
			}

lbl_get_product_info:

			pGPI = (PGPI) GetProcAddress(
			GetModuleHandle(TEXT("kernel32.dll")), 
			"GetProductInfo");

			pGPI( osvi.dwMajorVersion, osvi.dwMinorVersion, 0, 0, &dwType);

#ifndef PRODUCT_PROFESSIONAL
#define PRODUCT_PROFESSIONAL                        0x00000030
#endif

			switch( dwType )
			{
			case PRODUCT_ULTIMATE:
				MY_STRING_CCH_CAT(pszOS, TEXT("Ultimate Edition" ));
				break;
			case PRODUCT_PROFESSIONAL:
				MY_STRING_CCH_CAT(pszOS, TEXT("Professional" ));
				break;
			case PRODUCT_HOME_PREMIUM:
				MY_STRING_CCH_CAT(pszOS, TEXT("Home Premium Edition" ));
				break;
			case PRODUCT_HOME_BASIC:
				MY_STRING_CCH_CAT(pszOS, TEXT("Home Basic Edition" ));
				break;
			case PRODUCT_ENTERPRISE:
				MY_STRING_CCH_CAT(pszOS, TEXT("Enterprise Edition" ));
				break;
			case PRODUCT_BUSINESS:
				MY_STRING_CCH_CAT(pszOS, TEXT("Business Edition" ));
				break;
			case PRODUCT_STARTER:
				MY_STRING_CCH_CAT(pszOS, TEXT("Starter Edition" ));
				break;
			case PRODUCT_CLUSTER_SERVER:
				MY_STRING_CCH_CAT(pszOS, TEXT("Cluster Server Edition" ));
				break;
			case PRODUCT_DATACENTER_SERVER:
				MY_STRING_CCH_CAT(pszOS, TEXT("Datacenter Edition" ));
				break;
			case PRODUCT_DATACENTER_SERVER_CORE:
				MY_STRING_CCH_CAT(pszOS, TEXT("Datacenter Edition (core installation)" ));
				break;
			case PRODUCT_ENTERPRISE_SERVER:
				MY_STRING_CCH_CAT(pszOS, TEXT("Enterprise Edition" ));
				break;
			case PRODUCT_ENTERPRISE_SERVER_CORE:
				MY_STRING_CCH_CAT(pszOS, TEXT("Enterprise Edition (core installation)" ));
				break;
			case PRODUCT_ENTERPRISE_SERVER_IA64:
				MY_STRING_CCH_CAT(pszOS, TEXT("Enterprise Edition for Itanium-based Systems" ));
				break;
			case PRODUCT_SMALLBUSINESS_SERVER:
				MY_STRING_CCH_CAT(pszOS, TEXT("Small Business Server" ));
				break;
			case PRODUCT_SMALLBUSINESS_SERVER_PREMIUM:
				MY_STRING_CCH_CAT(pszOS, TEXT("Small Business Server Premium Edition" ));
				break;
			case PRODUCT_STANDARD_SERVER:
				MY_STRING_CCH_CAT(pszOS, TEXT("Standard Edition" ));
				break;
			case PRODUCT_STANDARD_SERVER_CORE:
				MY_STRING_CCH_CAT(pszOS, TEXT("Standard Edition (core installation)" ));
				break;
			case PRODUCT_WEB_SERVER:
				MY_STRING_CCH_CAT(pszOS, TEXT("Web Server Edition" ));
				break;

			case 0x00000065:	//PRODUCT_CORE:
				MY_STRING_CCH_CAT(pszOS, TEXT("Core"));
				break;

			case 0x4A:		
				MY_STRING_CCH_CAT(pszOS, TEXT("Consumer Preview" ));
				break;

			default:
				{
					std::wstring strBuff;
					__Format(strBuff, _T("(0x%X)"), dwType);
					MY_STRING_CCH_CAT(pszOS, strBuff.c_str());
				}
				break;
			}
		}

		if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2 )
		{
#ifndef SM_SERVERR2
			#define SM_SERVERR2 89
#endif
#ifndef VER_SUITE_WH_SERVER
			#define VER_SUITE_WH_SERVER                 0x00008000
#endif
			if( GetSystemMetrics(SM_SERVERR2) )
			MY_STRING_CCH_CAT(pszOS, TEXT( "Windows Server 2003 R2, "));
			else if ( osvi.wSuiteMask & VER_SUITE_STORAGE_SERVER )
			MY_STRING_CCH_CAT(pszOS, TEXT( "Windows Storage Server 2003"));
			else if ( osvi.wSuiteMask & VER_SUITE_WH_SERVER )
			MY_STRING_CCH_CAT(pszOS, TEXT( "Windows Home Server"));
			else if( osvi.wProductType == VER_NT_WORKSTATION &&
					si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64)
			{
			MY_STRING_CCH_CAT(pszOS, TEXT( "Windows XP Professional x64 Edition"));
			}
			else MY_STRING_CCH_CAT(pszOS, TEXT("Windows Server 2003, "));

			// Test for the server type.
			if ( osvi.wProductType != VER_NT_WORKSTATION )
			{
			if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_IA64 )
			{
				if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
					MY_STRING_CCH_CAT(pszOS, TEXT( "Datacenter Edition for Itanium-based Systems" ));
				else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
					MY_STRING_CCH_CAT(pszOS, TEXT( "Enterprise Edition for Itanium-based Systems" ));
			}

			else if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 )
			{
				if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
					MY_STRING_CCH_CAT(pszOS, TEXT( "Datacenter x64 Edition" ));
				else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
					MY_STRING_CCH_CAT(pszOS, TEXT( "Enterprise x64 Edition" ));
				else MY_STRING_CCH_CAT(pszOS, TEXT( "Standard x64 Edition" ));
			}

			else
			{
				if ( osvi.wSuiteMask & VER_SUITE_COMPUTE_SERVER )
					MY_STRING_CCH_CAT(pszOS, TEXT( "Compute Cluster Edition" ));
				else if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
					MY_STRING_CCH_CAT(pszOS, TEXT( "Datacenter Edition" ));
				else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
					MY_STRING_CCH_CAT(pszOS, TEXT( "Enterprise Edition" ));
				else if ( osvi.wSuiteMask & VER_SUITE_BLADE )
					MY_STRING_CCH_CAT(pszOS, TEXT( "Web Edition" ));
				else MY_STRING_CCH_CAT(pszOS, TEXT( "Standard Edition" ));
			}
			}
		}

		if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 )
		{
			MY_STRING_CCH_CAT(pszOS, TEXT("Windows XP "));
			if( osvi.wSuiteMask & VER_SUITE_PERSONAL )
			MY_STRING_CCH_CAT(pszOS, TEXT( "Home Edition" ));
			else MY_STRING_CCH_CAT(pszOS, TEXT( "Professional" ));
		}

		if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0 )
		{
			MY_STRING_CCH_CAT(pszOS, TEXT("Windows 2000 "));

			if ( osvi.wProductType == VER_NT_WORKSTATION )
			{
			MY_STRING_CCH_CAT(pszOS, TEXT( "Professional" ));
			}
			else 
			{
			if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
				MY_STRING_CCH_CAT(pszOS, TEXT( "Datacenter Server" ));
			else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
				MY_STRING_CCH_CAT(pszOS, TEXT( "Advanced Server" ));
			else MY_STRING_CCH_CAT(pszOS, TEXT( "Server" ));
			}
		}

		// Include service pack (if any) and build number.

		if( _tcslen(osvi.szCSDVersion) > 0 )
		{
			MY_STRING_CCH_CAT(pszOS, TEXT(" ") );
			MY_STRING_CCH_CAT(pszOS, osvi.szCSDVersion);
		}

		TCHAR buf[80];

		MY_SPRINTF( buf, TEXT(" (build %d)"), osvi.dwBuildNumber);
		MY_STRING_CCH_CAT(pszOS, buf);

		if ( osvi.dwMajorVersion >= 6 )
		{
			if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 )
			MY_STRING_CCH_CAT(pszOS, TEXT( ", 64-bit" ));
			else if (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL )
			MY_STRING_CCH_CAT(pszOS, TEXT(", 32-bit"));
		}

		res = pszOS;
	}
	else
	{  
		res = _T( "Unknown version of Windows");
	}

	return TRUE;
}


static void __getBriefSystemInfo(std::wstring& str, COLLECT_SYS_INFO typeMask)
{
	//DO NOT CALL directly

	if(typeMask & CSI_DATE_TIME)
	{
		//Get current time
		SYSTEMTIME stUtc = {0};
		SYSTEMTIME stLoc = {0};

		::GetSystemTime(&stUtc);
		::GetLocalTime(&stLoc);

		FILETIME ftUtc = {0};
		FILETIME ftLoc = {0};
		::SystemTimeToFileTime(&stUtc, &ftUtc);
		::SystemTimeToFileTime(&stLoc, &ftLoc);

		//See difference between now & UTC
		LONG64 iinsDiff = FILETIME_TO_NS(ftLoc) - FILETIME_TO_NS(ftUtc);
		double fUtcDiffSecs = (double)(iinsDiff / (10000000LL * 60LL));
		double fDiffHrs = fabs(fUtcDiffSecs) / 60.0;

		std::wstring strUtcPlus;
		__Format(strUtcPlus,
			L"%s%.2fh", 
			fUtcDiffSecs >= 0.0 ? L"+" : L"-",
			fDiffHrs
			);

		//Format it
		__AppendFormat(str,
			L"DATE: %04d-%02d-%02d %02d:%02d:%02d (%s)\n"
			,

			//Date/time
			stLoc.wYear,
			stLoc.wMonth,
			stLoc.wDay,
			stLoc.wHour,
			stLoc.wMinute,
			stLoc.wSecond,

			strUtcPlus.c_str()		//UTC +- value
			);
	}


	if(typeMask & CSI_OS_NAME)
	{
		//Get OS name
		std::wstring strWin;
		_get_win_ver(strWin);

		//Format it
		__AppendFormat(str,
			L"OS: %s\n"
			,
			strWin.c_str());
	}


	if(typeMask & CSI_LOCALE)
	{
		//Locale info

		//Format it
		__AppendFormat(str,
			L"LOCALE: (0x%X) %s\n"
			,
			::GetThreadLocale(),
			GetLocaleName().c_str()
			);
	}


	int nErr;

	if(typeMask & CSI_RAM)
	{
		//Get RAM info
		std::wstring strMemTotal, strMemFree;
		MEMORYSTATUSEX msx = {0};
		msx.dwLength = sizeof(msx);
		if(GlobalMemoryStatusEx(&msx))
		{
			strMemTotal = FormatKiloMegaGigaTera(msx.ullTotalPhys);
			strMemFree = FormatKiloMegaGigaTera(msx.ullAvailPhys);
		}
		else
		{
			//Failed
			nErr = ::GetLastError();
			__Format(strMemTotal, _T("Err:%d"), nErr);
			__Format(strMemFree, _T("Err:%d"), nErr);
		}

		//Format it
		__AppendFormat(str,
			_T("RAM: %s, Free: %s\n")
			,
			strMemTotal.c_str(),
			strMemFree.c_str()
			);
	}



	if(typeMask & CSI_DISK_OS)
	{
		//Get HDD info
		TCHAR buffWndDir_User[MAX_PATH * 4];
		buffWndDir_User[0] = 0;
		::GetWindowsDirectory(buffWndDir_User, SIZEOF(buffWndDir_User));
		buffWndDir_User[SIZEOF(buffWndDir_User) - 1] = 0;

		__formatHddStats(buffWndDir_User, L"DISK OS: ", str);
	}


	if(typeMask & CSI_DISK_APP)
	{
		//App disk info
		TCHAR buffApp[MAX_PATH * 4];
		buffApp[0] = 0;
		::GetModuleFileName(NULL, buffApp, SIZEOF(buffApp));
		buffApp[SIZEOF(buffApp) - 1] = 0;

		__formatHddStats(GetFolderOnly(buffApp, TRUE).c_str(), L"DISK APP: ", str);
	}


	if(typeMask & CSI_PROC_ELEV_GUEST_RDC)
	{
		//Process info
		std::wstring strElev, strGuest, strRDC;

		//Elevated
		//		0 - if not running elevated
		//		0x80 - if running elevated
		//		-1 - if error determining -- check GetLastError() for info
		int nElev = IsRunningWithElevatedPrivileges();
		switch(nElev)
		{
		case 0:
			strElev = L"Not elevated";
			break;
		case 0x80:
			strElev = L"Elevated";
			break;
		default:
			__Format(strElev, L"ElevErr:%d", ::GetLastError());
			break;
		}

		//Guest
		//		= 0 if running under a Guest account
		//		= 1 if not running as Guest
		//		= -1 if error determining -- check GetLastError() for info
		int nGst = IsRunningUnderGuestAccount();
		switch(nGst)
		{
		case 0:
			strGuest = L"Guest";
			break;
		case 1:
			//strGuest = L"";		//Don't add anything
			break;
		default:
			__Format(strGuest, L"GstErr:%d", ::GetLastError());
			break;
		}

		//Remote desktop connection
		//		= 1 if yes
		//		= 0 if no
		//		= -1 if error (check GetLastError() for more details)
		int nRDC = IsRunningWithRemoteDesktopConnection();
		switch(nRDC)
		{
		case 0:
			//strRDC = L"";		//Don't add anything
			break;
		case 1:
			strRDC = L"RDC";
			break;
		default:
			__Format(strRDC, L"RdcErr:%d", ::GetLastError());
			break;
		}


		//Format
		str += L"PROC: ";
		str += strElev;

		if(!strGuest.empty())
		{
			str += L", ";
			str += strGuest;
		}

		if(!strRDC.empty())
		{
			str += L", ";
			str += strRDC;
		}

		str += L"\n";
	}


	//Trim result
	__Trim(str);
}



static BOOL __formatHddStats(LPCTSTR pStrDirPath, LPCTSTR pStrHeading, std::wstring& str)
{
	//Get HDD stats for a folder
	//'pStrDirPath' = folder path, may or may not end with a slash
	//'pStrHeading' = heading for the message
	//'str' = string to add info to
	//RETURN:
	//		= TRUE if success

	TCHAR chDrvLtr[2] = L"?";

	if(!pStrDirPath ||
		!pStrDirPath[0])
	{
		//Error
		::SetLastError(ERROR_OUT_OF_PAPER);

		goto lbl_failed;
	}

	//Get drive letter
	chDrvLtr[0] = pStrDirPath[0];

	//Make it upper
	::CharUpper(chDrvLtr);

	ULARGE_INTEGER uiFreeBytesAvailable;
	uiFreeBytesAvailable.QuadPart = -1;
	ULARGE_INTEGER uiTotalNumberOfBytes;
	uiTotalNumberOfBytes.QuadPart = -1;
	ULARGE_INTEGER uiTotalNumberOfFreeBytes;
	uiTotalNumberOfFreeBytes.QuadPart = -1;

	//Get drive sizes
	if(!::GetDiskFreeSpaceEx(MakeFolderPathEndWithSlash(pStrDirPath, 0).c_str(), &uiFreeBytesAvailable, &uiTotalNumberOfBytes, &uiTotalNumberOfFreeBytes))
	{
lbl_failed:
		//Failed
		__AppendFormat(str, L"%s(%s:) Err:%d\n",
			pStrHeading ? pStrHeading : L"",
			chDrvLtr,
			::GetLastError());

		return FALSE;
	}

	std::wstring strHddUser;

	if(uiTotalNumberOfFreeBytes.QuadPart != uiFreeBytesAvailable.QuadPart)
	{
		__Format(strHddUser, L" (For User: %s)", FormatKiloMegaGigaTera(uiFreeBytesAvailable.QuadPart).c_str());
	}

	//Format it
	__AppendFormat(str,
		L"%s(%s:) %s, Free: %s%s\n"
		,
		pStrHeading ? pStrHeading : L"",
		chDrvLtr,
		FormatKiloMegaGigaTera(uiTotalNumberOfBytes.QuadPart).c_str(),
		FormatKiloMegaGigaTera(uiTotalNumberOfFreeBytes.QuadPart).c_str(),
		strHddUser.c_str()
		);

	return TRUE;
}


};



};
