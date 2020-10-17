#include <Windows.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <stdio.h>

typedef unsigned __int8   u8;
typedef unsigned __int16  u16;
typedef unsigned __int32  u32;
typedef unsigned __int64  u64;
typedef signed __int8     s8;
typedef signed __int16    s16;
typedef signed __int32    s32;
typedef signed __int64    s64;


#ifdef _WIN64
#define X86_64
#else
#define X86_32
#endif

#ifdef X86_32
typedef WOW64_CONTEXT   WIN_CONTEXT_32;
#else
typedef WOW64_CONTEXT   WIN_CONTEXT_32;
typedef CONTEXT         WIN_CONTEXT_64;
#endif // X86_32


#define DEBUG_TRACE        0x1
#define DEBUG_INFO         0x2
#define DEBUG_ERROR        0x4

#define DEBUG_CONSOLE
#define DEBUG_FILTER     ( DEBUG_INFO | DEBUG_ERROR )

void dprintf(unsigned int debug_type, const char* format, ...);
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
BOOL IsProcess32Bit(DWORD dwProcessId, PBOOL pbIs32Bit);


BOOL SetJITDebugger(LPCSTR lpDebuggerPath, BOOL bAuto);


BOOL PrintExceptionReport(LPDEBUG_EVENT lpDebugEvent);

BOOL PrintExceptionReport32(LPDEBUG_EVENT lpDebugEvent);
BOOL PrintRegisters32(WIN_CONTEXT_32 * lpContext);
BOOL PrintStack32(u32 address, LPCVOID lpBuffer, DWORD dwBufferSize);
BOOL PrintAssemblyCode32(u32 address, LPCVOID lpBuffer, DWORD dwBufferSize);

#ifdef X86_64
BOOL PrintExceptionReport64(LPDEBUG_EVENT lpDebugEvent);
BOOL PrintRegisters64(WIN_CONTEXT_64 * lpContext);
BOOL PrintStack64(u64 address, LPCVOID lpBuffer, DWORD dwBufferSize);
BOOL PrintAssemblyCode64(u64 address, LPCVOID lpBuffer, DWORD dwBufferSize);
#endif

void PrintHexDump(LPCVOID lpAddress, LPCVOID lpBuffer, DWORD dwSize);