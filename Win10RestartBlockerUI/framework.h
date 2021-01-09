// header.h : include file for standard system include files,
// or project specific include files
//

#pragma once

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>



#include "..\ShellChromeAPI\event_log_reporter.h"		//Event log functions
#include "..\ShellChromeAPI\Auxiliary.h"				//Commonly used functions

#include <strsafe.h>
#include "resource.h"

#include "commctrl.h"
#pragma comment(lib, "Comctl32.lib")

#include <wingdi.h>

#include <string>

#include <tlhelp32.h>
#include <atlbase.h>


#include "Types.h"			//Custom types


