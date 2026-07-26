/*
 * TestClient.cpp - Usermode test client for NullkD (packing fix + debug)
 *
 * Tests all driver commands via the hooked NtQueryCompositionSurfaceStatistics.
 * Requires NullkD.sys loaded with kdmapper.
 */

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

// ---------- Packed structures (must match kernel driver) ----------
#pragma pack(push, 1)

#define REQUEST_MAGIC 0x44524B4E

typedef enum _DRIVER_COMMAND {
    CMD_NONE = 0,
    CMD_READ = 1,
    CMD_WRITE = 2,
    CMD_MODULE_BASE = 3,
    CMD_ALLOC = 4,
    CMD_FREE = 5,
    CMD_PROTECT = 6,
    CMD_READ64 = 7,
    CMD_WRITE64 = 8,
    CMD_READ_BATCH = 9,
    CMD_PING = 99,
    CMD_VERIFY_PTE = 100,
    CMD_VERIFY_SPOOF = 101,
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
    if (!hWin32u) {
        printf("[-] win32u.dll not found\n");
        return false;
    }
    NtQueryCompSurf = (pNtQueryCompositionSurfaceStatistics)
        GetProcAddress(hWin32u, "NtQueryCompositionSurfaceStatistics");
    if (!NtQueryCompSurf) {
        printf("[-] Function not found in win32u\n");
        return false;
    }
    printf("[+] win32u function resolved at %p\n", NtQueryCompSurf);
    return true;
}

bool SendRequest(REQUEST_DATA& req, const char* desc = "")
{
    req.magic = REQUEST_MAGIC;
    req.result = 0;

    if (desc[0]) printf("[>] Sending %s...\n", desc);

    __try {
        NTSTATUS status = NtQueryCompSurf((HANDLE)&req, NULL, NULL);
        if (status != 0) {
            printf("[-] NTSTATUS error 0x%08X for %s\n", status, desc);
            return false;
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception during %s! Driver may not be loaded.\n", desc);
        return false;
    }
}

bool TestPing()
{
    printf("\n--- TestPing ---\n");
    REQUEST_DATA req = {};
    req.command = CMD_PING;

    if (!SendRequest(req, "PING")) return false;

    printf("[*] PING response: 0x%016llX\n", req.result);
    if (req.result == 0x50544548)
        printf("[+] PTE hook active\n");
    else if (req.result == 0x4B524E4C)
        printf("[!] Direct patch fallback (0x4B524E4C)\n");
    else
        printf("[-] Unknown ping response. Packing mismatch?\n");
    return true;
}

bool TestMemoryReadWrite()
{
    printf("\n--- TestMemoryReadWrite ---\n");
    DWORD pid = GetCurrentProcessId();
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    BYTE localBuf[16], readBuf[16] = {};

    REQUEST_DATA req = {};
    req.command = CMD_READ;
    req.pid = pid;
    req.address = (ULONG64)hKernel32;
    req.buffer = (ULONG64)readBuf;
    req.size = sizeof(readBuf);
    if (!SendRequest(req, "READ")) return false;

    memcpy(localBuf, hKernel32, sizeof(localBuf));
    if (memcmp(localBuf, readBuf, sizeof(localBuf)) != 0) {
        printf("[-] Read data mismatch\n");
        return false;
    }
    printf("[+] Read 16 bytes OK\n");

    PVOID testMem = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    if (!testMem) return false;
    const char testStr[] = "NullkD test";
    req = {};
    req.command = CMD_WRITE;
    req.pid = pid;
    req.address = (ULONG64)testMem;
    req.buffer = (ULONG64)testStr;
    req.size = sizeof(testStr);
    if (!SendRequest(req, "WRITE")) { VirtualFree(testMem, 0, MEM_RELEASE); return false; }

    if (memcmp(testMem, testStr, sizeof(testStr)) != 0) {
        printf("[-] Write data mismatch\n");
        VirtualFree(testMem, 0, MEM_RELEASE);
        return false;
    }
    printf("[+] Write/verify OK\n");
    VirtualFree(testMem, 0, MEM_RELEASE);
    return true;
}

bool TestModuleBase()
{
    printf("\n--- TestModuleBase ---\n");
    REQUEST_DATA req = {};
    req.command = CMD_MODULE_BASE;
    req.pid = GetCurrentProcessId();
    wcscpy_s(req.module_name, L"kernel32.dll");
    if (!SendRequest(req, "MODULE_BASE")) return false;

    ULONG64 base = req.result;
    if (!base) { printf("[-] Base not found\n"); return false; }
    HMODULE real = GetModuleHandleA("kernel32.dll");
    if ((ULONG64)real != base) { printf("[-] Mismatch\n"); return false; }
    printf("[+] Module base correct: 0x%llX\n", base);
    return true;
}

bool TestAllocFreeProtect()
{
    printf("\n--- TestAllocFreeProtect ---\n");
    DWORD pid = GetCurrentProcessId();
    REQUEST_DATA req = {};
    req.command = CMD_ALLOC;
    req.pid = pid;
    req.size = 0x1000;
    req.protect = PAGE_READWRITE;
    if (!SendRequest(req, "ALLOC")) return false;
    ULONG64 alloc = req.result;
    printf("[+] Allocated at 0x%llX\n", alloc);

    __try { *(int*)alloc = 0x12345678; }
    __except(1) { printf("[-] Write failed\n"); return false; }
    printf("[+] Write to alloc OK\n");

    req = {}; req.command = CMD_PROTECT; req.pid = pid;
    req.address = alloc; req.size = 0x1000; req.protect = PAGE_READONLY;
    if (!SendRequest(req, "PROTECT")) return false;

    bool exc = false;
    __try { *(int*)alloc = 0xDEAD; }
    __except(1) { exc = true; }
    if (!exc) { printf("[-] Protection unchanged\n"); return false; }
    printf("[+] Protection OK\n");

    req = {}; req.command = CMD_FREE; req.pid = pid; req.result = alloc;
    if (!SendRequest(req, "FREE")) return false;
    __try { volatile int x = *(int*)alloc; (void)x; printf("[-] Still accessible\n"); return false; }
    __except(1) { printf("[+] Free OK\n"); }
    return true;
}

bool TestBatchRead()
{
    printf("\n--- TestBatchRead ---\n");
    DWORD pid = GetCurrentProcessId();
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    const int n = 3;
    BYTE local[n][16], out[n*16] = {};
    BATCH_READ_REQUEST batch = {};
    batch.count = n;
    batch.outBuffer = (ULONG64)out;
    for (int i = 0; i < n; i++) {
        batch.entries[i].address = (ULONG64)hK32 + i*16;
        batch.entries[i].size = 16;
        batch.entries[i].outOffset = i*16;
        memcpy(local[i], (PBYTE)hK32 + i*16, 16);
    }
    REQUEST_DATA req = {};
    req.command = CMD_READ_BATCH;
    req.pid = pid;
    req.buffer = (ULONG64)&batch;
    req.size = sizeof(out);
    if (!SendRequest(req, "BATCH_READ") || req.result != 1) { printf("[-] Failed\n"); return false; }
    if (memcmp(local, out, sizeof(out)) != 0) { printf("[-] Mismatch\n"); return false; }
    printf("[+] Batch read OK\n");
    return true;
}

bool TestVerifyPte()
{
    printf("\n--- TestVerifyPte ---\n");
    BYTE buf[64] = {};
    REQUEST_DATA req = {};
    req.command = CMD_VERIFY_PTE;
    req.buffer = (ULONG64)buf;
    if (!SendRequest(req, "VERIFY_PTE")) return false;
    printf(" Active: %llu, OrigPFN: 0x%llX, NewPFN: 0x%llX\n",
        *(ULONG64*)buf, *(ULONG64*)(buf+8), *(ULONG64*)(buf+16));
    return true;
}

bool TestVerifySpoof()
{
    printf("\n--- TestVerifySpoof ---\n");
    BYTE buf[16] = {};
    REQUEST_DATA req = {};
    req.command = CMD_VERIFY_SPOOF;
    req.buffer = (ULONG64)buf;
    if (!SendRequest(req, "VERIFY_SPOOF")) return false;
    printf(" Gadget: 0x%llX, Stub: 0x%llX\n", *(ULONG64*)buf, *(ULONG64*)(buf+8));
    return true;
}

int main()
{
    printf("NullkD Test Client v1.1 (packed structs)\n========================\n");
    if (!InitDriverCommunication()) return 1;

    if (!TestPing())
        printf("FATAL: Driver not responding. Check packing / hook target.\n");
    else
        printf("[PASS] Ping\n");

    bool allPass = true;
    #define RUN(t) if (!(t)()) { printf("!!! " #t " FAILED !!!\n"); allPass = false; } else printf("[PASS] " #t "\n");

    RUN(TestMemoryReadWrite);
    RUN(TestModuleBase);
    RUN(TestAllocFreeProtect);
    RUN(TestBatchRead);
    RUN(TestVerifyPte);
    RUN(TestVerifySpoof);

    printf("\n========================\n");
    if (allPass) printf("ALL TESTS PASSED\n");
    else printf("SOME TESTS FAILED\n");
    return allPass ? 0 : 1;
}
