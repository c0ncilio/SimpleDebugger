#include <Windows.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <capstone.h>

#include "debug.h"

typedef WOW64_CONTEXT WIN_CONTEXT;

BOOL CreateDebugProcess(LPCSTR target);
BOOL AttachDebugProcess(LPCSTR target);
BOOL AttachDebugProcess(DWORD dwProcessId);

void HandleDebugEvents();

void HandleCreateProcessDebugEvent(LPDEBUG_EVENT lpDebugEvent);
void HandleExitProcessDebugEvent(LPDEBUG_EVENT lpDebugEvent);
void HandleCreateThreadDebugEvent(LPDEBUG_EVENT lpDebugEvent);
void HandleExitThreadDebugEvent(LPDEBUG_EVENT lpDebugEvent);
void HandleLoadDllDebugEvent(LPDEBUG_EVENT lpDebugEvent);
void HandleUnloadDllDebugEvent(LPDEBUG_EVENT lpDebugEvent);
void HandleExceptionDebugEvent(LPDEBUG_EVENT lpDebugEvent);
void HandleOutputDebugStringEvent(LPDEBUG_EVENT lpDebugEvent);
void HandleRipEvent(LPDEBUG_EVENT lpDebugEvent);

BOOL GetThreadContextByThreadId(DWORD dwThreadId, LPCONTEXT lpContext);
DWORD GetProcessIdByName(LPCSTR lpProcessName);
BOOL GetFileNameFromHandle(HANDLE hFile, LPSTR lpFileName, DWORD dwSize);

BOOL SetJITDebugger(LPCSTR lpDebuggerPath, BOOL bAuto);

void PrintDebugInfo(LPDEBUG_EVENT lpDebugEvent);
void PrintRegisters(WIN_CONTEXT * lpContext);
void PrintStack(LPCVOID lpAddress, LPCVOID lpBuffer, DWORD dwBufferSize);
void PrintCode(LPCVOID lpAddress, LPCVOID lpBuffer, DWORD dwBufferSize);
void PrintHexDump(LPCVOID lpAddress, LPCVOID lpBuffer, DWORD dwSize);