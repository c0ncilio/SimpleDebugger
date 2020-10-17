#include "debugger.h"

void help()
{
    dprintf(DEBUG_INFO, "Usage:\n");
    dprintf(DEBUG_INFO, "--create - create new process\n");
    dprintf(DEBUG_INFO, "--attach - attach to process\n");
    dprintf(DEBUG_INFO, "--jit    - set as JIT debugger\n");
}

int main(int argc, char * argv[])
{
    if (argc == 3)
    {
        if (strcmp(argv[1], "--attach") == 0)
        {
            AttachDebugProcess(argv[2]);
        }
        else if (strcmp(argv[1], "--create") == 0)
        {
            CreateDebugProcess(argv[2]);
        }
    }
    else if (argc == 4 && strcmp(argv[1], "-AEDEBUG") == 0) // 
    {
        DWORD dwProcessId = atoi(argv[2]);
        AttachDebugProcess(dwProcessId);
        system("pause");
    }
    else if (argc == 2 && strcmp(argv[1], "-jit") == 0) // set SimpleDebugger as Just-In-Time Debugger 
    {
        char curPath[MAX_PATH] = "";
        GetModuleFileName(NULL, curPath, MAX_PATH);
        SetJITDebugger(curPath, TRUE);
    }
    else
    {
        help();
    }
    return 0;
}

BOOL CreateDebugProcess(LPCSTR target)
{
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi))
    {
        dprintf(DEBUG_ERROR, "error: create debug process (%d)\n", GetLastError());
        return FALSE;
    }
    HandleDebugEvents();
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    dprintf(DEBUG_INFO, "Exit code: %lx\n", exitCode);
    return TRUE;
}

BOOL AttachDebugProcess(LPCSTR target)
{
    DWORD dwProcessId = GetProcessIdByName(target);
    if (!dwProcessId)
    {
        dprintf(DEBUG_ERROR, "error: get process id by name\n");
        return FALSE;
    }
    return AttachDebugProcess(dwProcessId);
}

BOOL AttachDebugProcess(DWORD dwProcessId)
{
    if (!DebugActiveProcess(dwProcessId))
    {
        dprintf(DEBUG_ERROR, "error: attach to process (%d)\n", GetLastError());
        return FALSE;
    }
    HandleDebugEvents();
    return TRUE;
}