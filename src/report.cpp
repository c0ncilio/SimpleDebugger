#include "debugger.h"
#include <udis86.h>

BOOL PrintExceptionReport(LPDEBUG_EVENT lpDebugEvent)
{
    BOOL bIsTargetProcess32Bit = TRUE;
    if (!IsProcess32Bit(lpDebugEvent->dwProcessId, &bIsTargetProcess32Bit))
    {
        return FALSE;
    }

    if (bIsTargetProcess32Bit)
    {
        PrintExceptionReport32(lpDebugEvent);
    }
    else
    {
#ifdef X86_64
        PrintExceptionReport64(lpDebugEvent);
#endif
    }
    return TRUE;
}

BOOL PrintExceptionReport32(LPDEBUG_EVENT lpDebugEvent)
{
    const DWORD dwStackBufferSize = 0x18, dwCodeBufferSize = 0x10;
    LPVOID lpStackBuffer[dwStackBufferSize] = { 0 }, lpCodeBuffer[dwCodeBufferSize] = { 0 };
    SIZE_T nBytes = 0;

    dprintf(DEBUG_INFO, "Process is 32-bit\n");
    dprintf(DEBUG_INFO, "Exception code: %08x\n", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode);
    dprintf(DEBUG_INFO, "Exception address: 0x%08x\n", (u32)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
    
    WIN_CONTEXT_32 context = { 0 };
    context.ContextFlags = CONTEXT_FULL;
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, lpDebugEvent->dwThreadId);
    if (!hThread)
    {
        dprintf(DEBUG_ERROR, "error: open thread (%d)\n", GetLastError());
        return FALSE;
    }

    if (!Wow64GetThreadContext(hThread, &context))
    {
        dprintf(DEBUG_ERROR, "error: get thread context (%d)\n", GetLastError());
        return FALSE;
    }

    PrintRegisters32(&context);
    
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, lpDebugEvent->dwProcessId);
    if (!hProcess)
    {
        dprintf(DEBUG_ERROR, "error: open process handle (%d)\n", GetLastError());
        return FALSE;
    }

    if (ReadProcessMemory(hProcess, (LPCVOID)context.Esp, lpStackBuffer, dwStackBufferSize, &nBytes))
    {
        PrintStack32(context.Esp, lpStackBuffer, dwStackBufferSize);
    }
    else
    {
        dprintf(DEBUG_ERROR, "error: read address (%x)\n", context.Esp);
    }
    
    if (ReadProcessMemory(hProcess, (LPCVOID)context.Eip, lpCodeBuffer, dwCodeBufferSize, &nBytes))
    {
        PrintAssemblyCode32(context.Eip, lpCodeBuffer, dwCodeBufferSize);
    }
    else
    {
        dprintf(DEBUG_ERROR, "error: read address (%x)\n", context.Eip);
    }
    
    CloseHandle(hProcess);
    
    return TRUE;
}

BOOL PrintRegisters32(WIN_CONTEXT_32* lpContext)
{
    dprintf(DEBUG_INFO, "Registrers:\n");
    dprintf(DEBUG_INFO, "EAX: 0x%08x  EBX: 0x%08x\n", lpContext->Eax, lpContext->Ebx);
    dprintf(DEBUG_INFO, "ECX: 0x%08x  EDX: 0x%08x\n", lpContext->Ecx, lpContext->Edx);
    dprintf(DEBUG_INFO, "ESI: 0x%08x  EDI: 0x%08x\n", lpContext->Esi, lpContext->Edi);
    dprintf(DEBUG_INFO, "EBP: 0x%08x  ESP: 0x%08x\n", lpContext->Ebp, lpContext->Esp);
    dprintf(DEBUG_INFO, "EIP: 0x%08x\n", lpContext->Eip);
    dprintf(DEBUG_INFO, "CS: 0x%02x  DS: 0x%02x  ES: 0x%02x  FS: 0x%02x  GS: 0x%02x  SS: 0x%02x\n",
        lpContext->SegCs, lpContext->SegDs, lpContext->SegEs, lpContext->SegFs, lpContext->SegGs, lpContext->SegSs);
    return TRUE;
}

BOOL PrintStack32(u32 address, LPCVOID lpBuffer, DWORD dwBufferSize)
{
    const DWORD dwAddressSize = 0x4;
    dwBufferSize -= (dwBufferSize % dwAddressSize);
    dprintf(DEBUG_INFO, "Stack:\n");
    for (DWORD dwIndex = 0; dwIndex < dwBufferSize; dwIndex += dwAddressSize)
        dprintf(DEBUG_INFO, "0x%08x: 0x%08x\n", (u32)(address + dwIndex), *(u32 *)((u8 *)lpBuffer + dwIndex));
    return TRUE;
}

BOOL PrintAssemblyCode32(u32 address, LPCVOID lpBuffer, DWORD dwBufferSize)
{
    ud state;
    u32 offset = 0;
    ud_init(&state);
    ud_set_syntax(&state, UD_SYN_INTEL);
    ud_set_mode(&state, 32);
    ud_set_input_buffer(&state, (const uint8_t *)lpBuffer, dwBufferSize);
    dprintf(DEBUG_INFO, "Code:\n");
    while (offset < dwBufferSize)
    {
        const u32 MAX_INSTRUCTION_LENGTH = 15;
        u32 len = ud_disassemble(&state);
        if (len == 0 || state.mnemonic == UD_Iinvalid)
            break;
        char hex[MAX_INSTRUCTION_LENGTH * 3 + 1] = { 0 };
        for (u32 i = 0; i < len; ++i)
        {
            sprintf(hex + i * 3, "%02x ", *((u8 *)lpBuffer + offset + i));
        }
        dprintf(DEBUG_INFO, "0x%x: %-30s %s\n", address + offset, state.asm_buf, hex);
        offset += len;
    }
    return TRUE;
}

#ifdef X86_64

BOOL PrintExceptionReport64(LPDEBUG_EVENT lpDebugEvent)
{
    const DWORD dwStackBufferSize = 0x30, dwCodeBufferSize = 0x10;
    LPVOID lpStackBuffer[dwStackBufferSize] = { 0 }, lpCodeBuffer[dwCodeBufferSize] = { 0 };
    SIZE_T nBytes = 0;

    dprintf(DEBUG_INFO, "Process is 64-bit\n");
    dprintf(DEBUG_INFO, "Exception code: %08x\n", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode);
    dprintf(DEBUG_INFO, "Exception address: 0x%016lx\n", (u64)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);

    WIN_CONTEXT_64 context = { 0 };
    context.ContextFlags = CONTEXT_FULL;

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, lpDebugEvent->dwThreadId);
    if (!hThread)
    {
        dprintf(DEBUG_ERROR, "error: open thread (%d)\n", GetLastError());
        return FALSE;
    }

    if (!GetThreadContext(hThread, &context))
    {
        dprintf(DEBUG_ERROR, "error: get thread context (%d)\n", GetLastError());
        return FALSE;
    }

    PrintRegisters64(&context);

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, lpDebugEvent->dwProcessId);
    if (!hProcess)
    {
        dprintf(DEBUG_ERROR, "error: open process handle (%d)\n", GetLastError());
        return FALSE;
    }

    if (ReadProcessMemory(hProcess, (LPCVOID)context.Rsp, lpStackBuffer, dwStackBufferSize, &nBytes))
    {
        PrintStack64(context.Rsp, lpStackBuffer, dwStackBufferSize);
    }
    else
    {
        dprintf(DEBUG_ERROR, "error: read address (%08x)\n", context.Rsp);
    }

    if (ReadProcessMemory(hProcess, (LPCVOID)context.Rip, lpCodeBuffer, dwCodeBufferSize, &nBytes))
    {
        PrintAssemblyCode64(context.Rip, lpCodeBuffer, dwCodeBufferSize);
    }
    else
    {
        dprintf(DEBUG_ERROR, "error: read address (%x)\n", context.Rip);
    }

    CloseHandle(hProcess);
    return TRUE;

}

BOOL PrintRegisters64(WIN_CONTEXT_64 * lpContext)
{
    dprintf(DEBUG_INFO, "Registrers:\n");
    dprintf(DEBUG_INFO, "RAX: 0x%016llx  RBX: 0x%016llx\n", lpContext->Rax, lpContext->Rbx);
    dprintf(DEBUG_INFO, "RCX: 0x%016llx  RDX: 0x%016llx\n", lpContext->Rcx, lpContext->Rdx);
    dprintf(DEBUG_INFO, "RSI: 0x%016llx  RDI: 0x%016llx\n", lpContext->Rsi, lpContext->Rdi);
    dprintf(DEBUG_INFO, "RBP: 0x%016llx  RSP: 0x%016llx\n", lpContext->Rsp, lpContext->Rip);
    dprintf(DEBUG_INFO, "RIP: 0x%016llx\n", lpContext->Rbp);
    dprintf(DEBUG_INFO, "CS: 0x%02x  DS: 0x%02x  ES: 0x%02x  FS: 0x%02x  GS: 0x%02x  SS: 0x%02x\n", 
        lpContext->SegCs, lpContext->SegDs, lpContext->SegEs, lpContext->SegFs, lpContext->SegGs, lpContext->SegSs);
    return TRUE;
}

BOOL PrintStack64(u64 address, LPCVOID lpBuffer, DWORD dwBufferSize)
{
    const DWORD dwAddressSize = 0x8;
    dwBufferSize -= (dwBufferSize % dwAddressSize);
    dprintf(DEBUG_INFO, "Stack:\n");
    for (DWORD dwIndex = 0; dwIndex < dwBufferSize; dwIndex += dwAddressSize)
        dprintf(DEBUG_INFO, "0x%016llx: 0x%016llx\n", (u64)(address + dwIndex), *(u64 *)((u8 *)lpBuffer + dwIndex));
    return TRUE;
}

BOOL PrintAssemblyCode64(u64 address, LPCVOID lpBuffer, DWORD dwBufferSize)
{
    ud state;
    u32 offset = 0;
    ud_init(&state);
    ud_set_syntax(&state, UD_SYN_INTEL);
    ud_set_mode(&state, 64);
    ud_set_input_buffer(&state, (const uint8_t*)lpBuffer, dwBufferSize);
    dprintf(DEBUG_INFO, "Code:\n");
    while (offset < dwBufferSize)
    {
        const u32 MAX_INSTRUCTION_LENGTH = 15;
        u32 len = ud_disassemble(&state);
        if (len == 0 || state.mnemonic == UD_Iinvalid)
            break;
        char hex[MAX_INSTRUCTION_LENGTH * 3 + 1] = { 0 };
        for (u32 i = 0; i < len; ++i)
        {
            sprintf(hex + i * 3, "%02x ", *((u8*)lpBuffer + offset + i));
        }
        dprintf(DEBUG_INFO, "0x%08llx: %-30s %s\n", address + offset, state.asm_buf, hex);
        offset += len;
    }
    return TRUE;
}

#endif

void PrintHexDump(LPCVOID lpAddress, LPCVOID lpBuffer, DWORD dwSize)
{
    const DWORD dwAllign = 0x10;
    dprintf(DEBUG_INFO, "Hex Dump:\n");
    for (DWORD dwIndex = 0; dwIndex < dwSize; dwIndex += dwAllign)
    {
        char hex_line[dwAllign * 3 + 1] = "", ascii_line[dwAllign + 1] = "";
 
        for (DWORD i = 0; i < dwAllign; i++)
        {
            if (i + dwIndex < dwSize)
                sprintf(hex_line + strlen(hex_line), "%02x ", *((LPBYTE)lpBuffer + dwIndex + i));
            else
                strcat(hex_line, "   ");
        }
 
        for (DWORD i = 0; i < dwAllign; i++)
        {
            if (i + dwIndex < dwSize)
            {
                BYTE symb = *((LPBYTE)lpBuffer + dwIndex + i);
                if (symb > 0x20 && symb < 0x7f)
                    sprintf(ascii_line + strlen(ascii_line), "%c", symb);
                else
                    sprintf(ascii_line + strlen(ascii_line), ".");
            }
            else
                strcat(ascii_line, " ");
        }
        
        dprintf(DEBUG_INFO, "%08x: %s  | %s\n", (DWORD)lpAddress + dwIndex, hex_line, ascii_line);
    }
}

void dprintf(unsigned int debug_type, const char * format, ...)
{
    if (!(debug_type & DEBUG_FILTER))
        return;

    va_list args;
    va_start(args, format);
#ifdef DEBUG_CONSOLE
    vprintf(format, args);
#endif

#ifdef DEBUG_FILE
    const char * filename = "";
    FILE * fp = fopen(filename, "a");
    if (fp)
    {
        vfprintf(fp, format, args);
        fclose(fp);
    }
#endif
    va_end(args); 
}