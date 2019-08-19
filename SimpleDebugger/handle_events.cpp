#include "debugger.h"

void HandleDebugEvents()
{    
    BOOL bContinueDebugging = TRUE;
    DEBUG_EVENT debugEvent = {0};
    while (bContinueDebugging)
    {
        DWORD dwContinueStatus = DBG_CONTINUE;

        if (!WaitForDebugEvent(&debugEvent, INFINITE))
            return;
        

        switch (debugEvent.dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
            HandleCreateProcessDebugEvent(&debugEvent);
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            HandleExitProcessDebugEvent(&debugEvent);
            bContinueDebugging = FALSE;
            break;

        case CREATE_THREAD_DEBUG_EVENT:
            HandleCreateThreadDebugEvent(&debugEvent);
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            HandleExitProcessDebugEvent(&debugEvent);
            break;

        case LOAD_DLL_DEBUG_EVENT:
            HandleLoadDllDebugEvent(&debugEvent);
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            HandleUnloadDllDebugEvent(&debugEvent);
            break;

        case EXCEPTION_DEBUG_EVENT:
            HandleExceptionDebugEvent(&debugEvent);
            if (debugEvent.u.Exception.dwFirstChance == FALSE)
            {
                PrintDebugInfo(&debugEvent);
                //bContinueDebugging = FALSE;

                HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, debugEvent.dwProcessId);
                TerminateProcess(hProc, debugEvent.u.Exception.ExceptionRecord.ExceptionCode);
                //FatalExit(debugEvent.u.Exception.ExceptionRecord.ExceptionCode);
            }
            dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            HandleOutputDebugStringEvent(&debugEvent);
            break;

        case RIP_EVENT:
            HandleRipEvent(&debugEvent);
            break;

        default:
            break;
        }
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, dwContinueStatus);
    }
}

void HandleCreateProcessDebugEvent(LPDEBUG_EVENT lpDebugEvent)
{
    LPCREATE_PROCESS_DEBUG_INFO lpDebugInfo = &lpDebugEvent->u.CreateProcessInfo;
    DWORD dwProcessId = lpDebugEvent->dwProcessId;
    DWORD dwThreadId = lpDebugEvent->dwThreadId;


    dprintf(DEBUG_EVENTS, "CREATE_PROCESS_DEBUG_EVENT\n");

    char fileName[MAX_PATH] = "";
    if (GetFileNameFromHandle(lpDebugInfo->hFile, fileName, MAX_PATH))
    {
        dprintf(DEBUG_INFO, "Create Process: (0x%08x) %s\n", lpDebugInfo->lpBaseOfImage, fileName);
    }
}

void HandleExitProcessDebugEvent(LPDEBUG_EVENT lpDebugEvent)
{
    LPEXIT_PROCESS_DEBUG_INFO lpDebugInfo = &lpDebugEvent->u.ExitProcess;
    DWORD dwProcessId = lpDebugEvent->dwProcessId;
    DWORD dwThreadId = lpDebugEvent->dwThreadId;
    
    dprintf(DEBUG_EVENTS, "EXIT_PROCESS_DEBUG_EVENT\n");
}

void HandleCreateThreadDebugEvent(LPDEBUG_EVENT lpDebugEvent)
{
    LPCREATE_THREAD_DEBUG_INFO lpDebugInfo = &lpDebugEvent->u.CreateThread;
    DWORD dwProcessId = lpDebugEvent->dwProcessId;
    DWORD dwThreadId = lpDebugEvent->dwThreadId;
    dprintf(DEBUG_EVENTS, "CREATE_THREAD_DEBUG_EVENT\n");
}

void HandleExitThreadDebugEvent(LPDEBUG_EVENT lpDebugEvent)
{
    LPEXIT_THREAD_DEBUG_INFO lpDebugInfo = &lpDebugEvent->u.ExitThread;
    DWORD dwProcessId = lpDebugEvent->dwProcessId;
    DWORD dwThreadId = lpDebugEvent->dwThreadId;

    dprintf(DEBUG_EVENTS, "EXIT_THREAD_DEBUG_EVENT\n");
}

void HandleLoadDllDebugEvent(LPDEBUG_EVENT lpDebugEvent)
{
    LPLOAD_DLL_DEBUG_INFO lpDebugInfo = &lpDebugEvent->u.LoadDll;
    DWORD dwProcessId = lpDebugEvent->dwProcessId;
    DWORD dwThreadId = lpDebugEvent->dwThreadId;

    dprintf(DEBUG_EVENTS, "LOAD_DLL_DEBUG_EVENT\n");
    //dprintf(DEBUG_INFO, "Image Base: %08x\n", lpDebugInfo->lpBaseOfDll);
    //dprintf(DEBUG_INFO, "hFile: %x\n", lpDebugInfo->hFile);

    char fileName[MAX_PATH] = "";
    if (GetFileNameFromHandle(lpDebugInfo->hFile, fileName, MAX_PATH))
    {
        dprintf(DEBUG_INFO, "Loaded DLL: (0x%08x) %s\n", lpDebugInfo->lpBaseOfDll, fileName);
    }
}

void HandleUnloadDllDebugEvent(LPDEBUG_EVENT lpDebugEvent)
{
    LPUNLOAD_DLL_DEBUG_INFO lpDebugInfo = &lpDebugEvent->u.UnloadDll;
    DWORD dwProcessId = lpDebugEvent->dwProcessId;
    DWORD dwThreadId = lpDebugEvent->dwThreadId;

    dprintf(DEBUG_EVENTS, "UNLOAD_DLL_DEBUG_EVENT\n");
}

void HandleExceptionDebugEvent(LPDEBUG_EVENT lpDebugEvent)
{
    LPEXCEPTION_DEBUG_INFO lpDebugInfo = &lpDebugEvent->u.Exception;
    DWORD dwProcessId = lpDebugEvent->dwProcessId;
    DWORD dwThreadId = lpDebugEvent->dwThreadId;

    dprintf(DEBUG_EVENTS, "EXCEPTION_DEBUG_EVENT\n");

    switch (lpDebugInfo->ExceptionRecord.ExceptionCode)
    {
    case EXCEPTION_ACCESS_VIOLATION:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_ACCESS_VIOLATION\n");
        break;

    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED\n");
        break;

    case EXCEPTION_BREAKPOINT:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_BREAKPOINT\n");
        break;

    case EXCEPTION_DATATYPE_MISALIGNMENT:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_DATATYPE_MISALIGNMENT\n");
        break;

    case EXCEPTION_FLT_DENORMAL_OPERAND:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_FLT_DENORMAL_OPERAND\n");
        break;

    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_FLT_DIVIDE_BY_ZERO\n");
        break;

    case EXCEPTION_FLT_INEXACT_RESULT:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_FLT_INEXACT_RESULT\n");
        break;

    case EXCEPTION_FLT_INVALID_OPERATION:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_FLT_INVALID_OPERATION\n");
        break;

    case EXCEPTION_FLT_OVERFLOW:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_FLT_OVERFLOW\n");
        break;

    case EXCEPTION_FLT_STACK_CHECK:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_FLT_STACK_CHECK\n");
        break;

    case EXCEPTION_FLT_UNDERFLOW:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_FLT_UNDERFLOW\n");
        break;

    case EXCEPTION_ILLEGAL_INSTRUCTION:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_ILLEGAL_INSTRUCTION\n");
        break;

    case EXCEPTION_IN_PAGE_ERROR:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_IN_PAGE_ERROR\n");
        break;

    case EXCEPTION_INT_DIVIDE_BY_ZERO:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_INT_DIVIDE_BY_ZERO\n");
        break;

    case EXCEPTION_INT_OVERFLOW:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_INT_OVERFLOW\n");
        break;

    case EXCEPTION_INVALID_DISPOSITION:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_INVALID_DISPOSITION\n");
        break;

    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_NONCONTINUABLE_EXCEPTION\n");
        break;

    case EXCEPTION_PRIV_INSTRUCTION:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_PRIV_INSTRUCTION\n");
        break;

    case EXCEPTION_SINGLE_STEP:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_SINGLE_STEP\n");
        break;

    case EXCEPTION_STACK_OVERFLOW:
        dprintf(DEBUG_EXCEPTIONS, "EXCEPTION_STACK_OVERFLOW\n");
        break;

    default:
        dprintf(DEBUG_EXCEPTIONS, "UNKNOWN_EXCEPTION (0x%08x)\n", lpDebugInfo->ExceptionRecord.ExceptionCode);
        break;
    }
}

void HandleOutputDebugStringEvent(LPDEBUG_EVENT lpDebugEvent)
{
    LPOUTPUT_DEBUG_STRING_INFO lpDebugInfo = &lpDebugEvent->u.DebugString;
    DWORD dwProcessId = lpDebugEvent->dwProcessId;
    DWORD dwThreadId = lpDebugEvent->dwThreadId;

    dprintf(DEBUG_EVENTS, "OUTPUT_DEBUG_STRING_EVENT\n");
}

void HandleRipEvent(LPDEBUG_EVENT lpDebugEvent)
{
    LPRIP_INFO lpDebugInfo = &lpDebugEvent->u.RipInfo;
    DWORD dwProcessId = lpDebugEvent->dwProcessId;
    DWORD dwThreadId = lpDebugEvent->dwThreadId;

    dprintf(DEBUG_EVENTS, "RIP_EVENT\n");
}