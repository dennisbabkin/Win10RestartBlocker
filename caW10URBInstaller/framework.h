#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>

#include <string>
#include <vector>
#include <assert.h>



#include "..\ShellChromeAPI\SharedDefs.h"				//Share definitions
#include "..\ShellChromeAPI\event_log_reporter.h"

#include <Msiquery.h>
#pragma comment(lib, "Msi.lib")

#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#include <winver.h>
#pragma comment(lib, "Version.lib")


