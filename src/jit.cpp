#include "debugger.h"

BOOL SetJITDebugger(LPCSTR lpDebuggerPath, BOOL bAuto)
{
	CHAR data[BUFSIZ] = "";

    char curPath[MAX_PATH] = "";
    if (lpDebuggerPath == NULL)
    {
        GetModuleFileName(NULL, curPath, MAX_PATH);
        lpDebuggerPath = curPath;
    }

	sprintf(data, "\"%s\" -AEDEBUG ", lpDebuggerPath);
	strcat(data, "%ld %ld");

	HKEY hKey;

	// open reg (work for windows 7 x64)
	if (RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Aedebug", &hKey) != ERROR_SUCCESS)
	{
		dprintf(DEBUG_ERROR, "error: open key\n");
		return FALSE;
	}

	// set debugger path
	if (RegSetKeyValue(hKey, NULL, "Debugger", REG_SZ, data, strlen(data)) != ERROR_SUCCESS)
	{
		dprintf(DEBUG_ERROR, "error: set value (Debugger)\n");
		RegCloseKey(hKey);
		return FALSE;
	}

	// set auto start debugging after fault
	LPCSTR lpMode = bAuto ? "1" : "0";
	if (RegSetKeyValue(hKey, NULL, "Auto", REG_SZ, lpMode, strlen(lpMode)) != ERROR_SUCCESS)
	{
		dprintf(DEBUG_ERROR, "error: set value (Auto)\n");
		RegCloseKey(hKey);
		return FALSE;
	}

	RegCloseKey(hKey);
	return TRUE;
}