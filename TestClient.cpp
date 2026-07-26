/*
 * TestClient_timeout.cpp - NullkD test client with timeout for each command.
 * Uses a separate thread to call the hooked function; if it hangs (>3s),
 * we assume a BSOD and exit cleanly.
 */

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#pragma pack(push, 1)

#define REQUEST_MAGIC 0x44524B4E

typedef enum _DRIVER_COMMAND {
    CMD_NONE = 0, CMD_READ = 1, CMD_WRITE = 2,
    CMD_MODULE_BASE = 3, CMD_ALLOC = 4, CMD_FREE = 5,
    CMD_PROTECT = 6, CMD_READ64 = 7, CMD_WRITE64 = 8,
    CMD_READ_BATCH = 9, CMD_PING = 99,
    CMD_VERIFY_PTE = 100, CMD_VERIFY_SPOOF = 101,
} DRIVER_COMMAND;

#define BATCH_MAX_ENTRIES 32

typedef struct _BATCH_READ_ENTRY {
    unsigned __int64 address;
    unsigned int     size;
    unsigned int     outOffset;
} BATCH_READ_ENTRY;

typedef struct _BATCH_READ_REQUEST {
    unsigned int       count;
    unsigned __int64   outBuffer;
    BATCH_READ_ENTRY   entries[BATCH_MAX_ENTRIES];
} BATCH_READ_REQUEST;

typedef struct _REQUEST_DATA {
    unsigned int    magic;
    unsigned int    command;
    unsigned __int64 pid;
    unsigned __int64 address;
    unsigned __int64 buffer;
    unsigned __int64 size;
    unsigned __int64 result;
    unsigned int    protect;
    wchar_t         module_name[64];
} REQUEST_DATA;

#pragma pack(pop)

typedef NTSTATUS (WINAPI *pNtQueryCompositionSurfaceStatistics)(
    HANDLE  hCompositionSurface,
    PVOID   pQueryInput,
    PVOID   pQueryOutput
);

pNtQueryCompositionSurfaceStatistics NtQueryCompSurf = nullptr;

bool InitDriverCommunication()
{
    HMODULE hWin32u = LoadLibraryA("win32u.dll");
    if (!hWin32u) { printf("[-] win32u.dll not found\n"); return false; }
    NtQueryCompSurf = (pNtQueryCompositionSurfaceStatistics)
        GetProcAddress(hWin32u, "NtQueryCompositionSurfaceStatistics");
    if (!NtQueryCompSurf) { printf("[-] export not found\n"); return false; }
    printf("[+] Resolved at %p\n", NtQueryCompSurf);
    return true;
}

// Structure passed to thread
struct CallParams {
    pNtQueryCompositionSurfaceStatistics func;
    HANDLE arg;
    NTSTATUS result;
    bool completed;
};

DWORD WINAPI CallThreadProc(LPVOID lpParam)
{
    CallParams* p = (CallParams*)lpParam;
    __try {
        p->result = p->func((HANDLE)p->arg, NULL, NULL);
        p->completed = true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        p->result = STATUS_UNSUCCESSFUL;
        p->completed = true;
    }
    return 0;
}

bool SendRequestTimeout(REQUEST_DATA& req, DWORD timeoutMs = 3000)
{
    req.magic = REQUEST_MAGIC;
    req.result = 0;

    CallParams cp = {};
    cp.func = NtQueryCompSurf;
    cp.arg = (HANDLE)&req;
    cp.completed = false;

    HANDLE hThread = CreateThread(NULL, 0, CallThreadProc, &cp, 0, NULL);
    if (!hThread) {
        printf("[-] Cannot create thread\n");
        return false;
    }

    DWORD wait = WaitForSingleObject(hThread, timeoutMs);
    if (wait == WAIT_TIMEOUT) {
        printf("[-] TIMEOUT: driver call hung -> likely BSOD.\n");
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
        return false;
    }
    CloseHandle(hThread);

    if (!cp.completed) {
        printf("[-] Thread didn't complete\n");
        return false;
    }

    if (cp.result != 0) {
        printf("[-] NTSTATUS 0x%08X\n", cp.result);
        return false;
    }
    return true;
}

// --- Tests (abbreviated, same as before but using SendRequestTimeout) ---
bool TestPing()
{
    printf("\n--- Ping ---\n");
    REQUEST_DATA req = {};
    req.command = CMD_PING;
    if (!SendRequestTimeout(req)) return false;
    printf("    Response: 0x%016llX\n", req.result);
    return (req.result == 0x50544548 || req.result == 0x4B524E4C);
}

bool TestMemoryReadWrite()
{
    printf("\n--- R/W ---\n");
    DWORD pid = GetCurrentProcessId();
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    BYTE buf[16] = {};
    REQUEST_DATA req = {};
    req.command = CMD_READ;
    req.pid = pid;
    req.address = (ULONG64)hK32;
    req.buffer = (ULONG64)buf;
    req.size = sizeof(buf);
    if (!SendRequestTimeout(req) || req.result != 1) return false;
    if (memcmp(buf, hK32, 16)) { printf("    Mismatch\n"); return false; }

    PVOID p = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    const char* txt = "Test";
    req = {}; req.command = CMD_WRITE; req.pid = pid;
    req.address = (ULONG64)p; req.buffer = (ULONG64)txt; req.size = 5;
    if (!SendRequestTimeout(req) || req.result != 1) { VirtualFree(p,0,MEM_RELEASE); return false; }
    if (memcmp(p, txt, 5)) { VirtualFree(p,0,MEM_RELEASE); return false; }
    VirtualFree(p, 0, MEM_RELEASE);
    printf("    OK\n");
    return true;
}

int main()
{
    printf("NullkD Test (timeout)\n=====================\n");
    if (!InitDriverCommunication()) return 1;

    if (!TestPing()) {
        printf("Ping failed or hang detected. Aborting.\n");
        return 1;
    }

    if (!TestMemoryReadWrite()) {
        printf("R/W test failed.\n");
        return 1;
    }

    printf("\nAll critical tests passed.\n");
    return 0;
}
