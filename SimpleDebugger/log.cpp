#include "debugger.h"

void PrintDebugInfo(LPDEBUG_EVENT lpDebugEvent)
{
    const DWORD dwStackBufferSize = 0x30, dwCodeBufferSize = 0x10;
    LPVOID lpStackBuffer[dwStackBufferSize] = { 0 }, lpCodeBuffer[dwCodeBufferSize] = { 0 };
    WIN_CONTEXT context;
    DWORD dwBytes = 0;

    dprintf(DEBUG_INFO, "Exception code: %08x\n", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode);
    dprintf(DEBUG_INFO, "Exception address: 0x%08x\n", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);

    if (!GetThreadContextByThreadId(lpDebugEvent->dwThreadId, &context))
    {
        dprintf(DEBUG_ERROR, "error: get thread context\n");
        return;
    }
    PrintRegisters(&context);

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, lpDebugEvent->dwProcessId);
    if (!hProcess)
        return;

    if (ReadProcessMemory(hProcess, (LPCVOID)context.Esp, lpStackBuffer, dwStackBufferSize, &dwBytes))
        PrintStack((LPCVOID)context.Esp, lpStackBuffer, dwStackBufferSize);
    else
        dprintf(DEBUG_ERROR, "error: read address (%x)\n", context.Esp);

    if (ReadProcessMemory(hProcess, (LPCVOID)context.Eip, lpCodeBuffer, dwCodeBufferSize, &dwBytes))
        PrintCode((LPCVOID)context.Eip, lpCodeBuffer, dwCodeBufferSize);
    else
        dprintf(DEBUG_ERROR, "error: read address (%x)\n", context.Eip);

    CloseHandle(hProcess);
}

void PrintRegisters(PWOW64_CONTEXT lpContext)
{
    dprintf(DEBUG_INFO, "Registrers:\n");
    dprintf(DEBUG_INFO, "EAX: 0x%08x  EBX: 0x%08x  ECX: 0x%08x  EDX: 0x%08x\n", lpContext->Eax, lpContext->Ebx, lpContext->Ecx, lpContext->Edx);
    dprintf(DEBUG_INFO, "ESI: 0x%08x  EDI: 0x%08x\n", lpContext->Esi, lpContext->Edi);
    dprintf(DEBUG_INFO, "EBP: 0x%08x  ESP: 0x%08x  EIP: 0x%08x\n", lpContext->Ebp, lpContext->Esp, lpContext->Eip);
    dprintf(DEBUG_INFO, "CS: 0x%02x  DS: 0x%02x  ES: 0x%02x  FS: 0x%02x  GS: 0x%02x  SS: 0x%02x\n", 
        lpContext->SegCs, lpContext->SegDs, lpContext->SegEs, lpContext->SegFs, lpContext->SegGs, lpContext->SegSs);
}

void PrintRegisters64(LPCONTEXT lpContext)
{
    dprintf(DEBUG_INFO, "Registrers:\n");
    dprintf(DEBUG_INFO, "EAX: 0x%16x  EBX: 0x%16x  ECX: 0x%16x  EDX: 0x%16x\n", lpContext->Rax, lpContext->Rbx, lpContext->Rcx, lpContext->Rdx);
    dprintf(DEBUG_INFO, "ESI: 0x%16x  EDI: 0x%16x\n", lpContext->Rsi, lpContext->Rdi);
    dprintf(DEBUG_INFO, "EBP: 0x%16x  ESP: 0x%16x  EIP: 0x%16x\n", lpContext->Rbp, lpContext->Rsp, lpContext->Rip);
    dprintf(DEBUG_INFO, "CS: 0x%02x  DS: 0x%02x  ES: 0x%02x  FS: 0x%02x  GS: 0x%02x  SS: 0x%02x\n", 
        lpContext->SegCs, lpContext->SegDs, lpContext->SegEs, lpContext->SegFs, lpContext->SegGs, lpContext->SegSs);
}

void PrintStack(LPCVOID lpAddress, LPCVOID lpBuffer, DWORD dwBufferSize)
{
    dwBufferSize -= (dwBufferSize % sizeof(LPCVOID)); // allign

    dprintf(DEBUG_INFO, "Stack:\n");
    for (DWORD dwIndex = 0; dwIndex < dwBufferSize; dwIndex += sizeof(LPCVOID))
        dprintf(DEBUG_INFO, "0x%08x: 0x%08x\n", (DWORD)lpAddress + dwIndex, *(LPDWORD)((LPBYTE)lpBuffer + dwIndex));
}

void PrintStack64(LPCVOID lpAddress, LPCVOID lpBuffer, DWORD dwBufferSize)
{
    dwBufferSize -= (dwBufferSize % sizeof(LPCVOID)); // allign

    dprintf(DEBUG_INFO, "Stack:\n");
    for (DWORD dwIndex = 0; dwIndex < dwBufferSize; dwIndex += sizeof(LPCVOID))
        dprintf(DEBUG_INFO, "0x%16x: 0x%16x\n", (DWORD)lpAddress + dwIndex, *(LPDWORD)((LPBYTE)lpBuffer + dwIndex));
}

void PrintCode(LPCVOID lpAddress, LPCVOID lpBuffer, DWORD dwBufferSize)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
        dprintf(DEBUG_ERROR, "error: cs_open\n");
        return;
    }
    count = cs_disasm(handle, (const uint8_t *)lpBuffer, dwBufferSize, (uint64_t)lpAddress, 0, &insn);
    if (count == 0)
    {
        dprintf(DEBUG_ERROR, "error: cs_disasm\n");
        return;
    }
    
    dprintf(DEBUG_INFO, "Code:\n");
    for (size_t i = 0; i < count; i++)
    {
        dprintf(DEBUG_INFO, "0x%08x: %s %s\n", (uint32_t)insn[i].address, insn[i].mnemonic, insn[i].op_str);
    }

    cs_free(insn,count);
    cs_close(&handle);
}

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