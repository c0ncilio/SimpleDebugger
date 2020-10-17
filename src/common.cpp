#include "debugger.h"

BOOL GetThreadContextByThreadId(DWORD dwThreadId, LPCONTEXT lpContext)
{
    BOOL bRet = FALSE;
    HANDLE hThread = INVALID_HANDLE_VALUE;

    hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, dwThreadId);
    if (hThread)
    {
        if (SuspendThread(hThread ) != -1)
        {
            lpContext->ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(hThread, lpContext) == TRUE)
                bRet = TRUE;
            ResumeThread(hThread);
        }
        CloseHandle(hThread);
    }
    return bRet;
}

DWORD GetProcessIdByName(LPCSTR lpProcessName)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (stricmp(entry.szExeFile, lpProcessName) == 0)
            {  
               return entry.th32ProcessID;
            }
        }
    }
    CloseHandle(snapshot);
    return 0;
}

BOOL GetFileNameFromHandle(HANDLE hFile, LPSTR lpFileName, DWORD dwSize) 
{
    BOOL bRet = FALSE;

    char fullPath[MAX_PATH];
    char path[MAX_PATH];

    size_t size = sizeof(FILE_NAME_INFO) + sizeof(WCHAR) * MAX_PATH;
    FILE_NAME_INFO *info = reinterpret_cast<FILE_NAME_INFO *>( malloc (size));
    info->FileNameLength = MAX_PATH;
    if (GetFileInformationByHandleEx(hFile, FileNameInfo, info, size))
    {
        DWORD dwSizeNeeded = WideCharToMultiByte(CP_ACP, 0, info->FileName, info->FileNameLength, NULL, NULL, NULL, NULL);
        if (dwSizeNeeded <= MAX_PATH)
        {
            WideCharToMultiByte(CP_ACP, 0, info->FileName, info->FileNameLength, path, dwSizeNeeded, NULL, NULL);
            path[info->FileNameLength / 2] = '\0';
            bRet = TRUE;
        }
    }    
    free(info);

    DWORD drives = GetLogicalDrives(); // bug if two dll with same name, but diference drive
    for (int i = 0; i < 26; i++)
    {
        if (drives & (1 << i))
        {
            sprintf(fullPath, "%c:\\%s", 'A' + i, path);
            DWORD attr = GetFileAttributes(fullPath);
            if (attr != INVALID_FILE_ATTRIBUTES && strlen(fullPath) < dwSize)
            {
                strcpy(lpFileName, fullPath);
                bRet = TRUE;
            }
        }
    }

    return bRet;
}

BOOL IsProcess32Bit(DWORD dwProcessId, PBOOL pbIs32Bit)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
    BOOL bResult = FALSE;

    if (hProcess)
    {
        BOOL Wow64Process = FALSE;
        if (IsWow64Process(hProcess, &Wow64Process))
        {
            *pbIs32Bit = Wow64Process;
            bResult = TRUE;
        }
        else
        {
            dprintf(DEBUG_ERROR, "error: get process bits (%d)", GetLastError());
        }
        CloseHandle(hProcess);
    }
    else
    {
        dprintf(DEBUG_ERROR, "error: open process (%d)", GetLastError());
    }
    return bResult;
}