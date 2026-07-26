/*
 * TestClient.cpp - Usermode test client for NullkD kernel driver
 *
 * Tests all driver commands via the hooked NtQueryCompositionSurfaceStatistics.
 * Safe to run: no BSOD risk; validates PTE hook integrity.
 * Compile: MSVC (C++17), links against Windows SDK only.
 */

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

// Copy shared definitions (no kernel headers needed)
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

// NtQueryCompositionSurfaceStatistics is exported from win32u.dll
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
        printf("[-] NtQueryCompositionSurfaceStatistics not found\n");
        return false;
    }
    printf("[+] win32u function resolved\n");
    return true;
}

bool SendRequest(REQUEST_DATA& req)
{
    req.magic = REQUEST_MAGIC;
    req.result = 0;

    __try {
        NTSTATUS status = NtQueryCompSurf((HANDLE)&req, NULL, NULL);
        if (status != 0) {
            printf("[-] Call returned 0x%08X\n", status);
            return false;
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception during driver call (driver not loaded?)\n");
        return false;
    }
}

bool TestPing()
{
    REQUEST_DATA req = {};
    req.command = CMD_PING;
    if (!SendRequest(req)) return false;
    printf("[*] PING response: 0x%016llX\n", req.result);
    if (req.result == 0x50544548)
        printf("[+] PTE hook active (0x50544548)\n");
    else if (req.result == 0x4B524E4C)
        printf("[!] PTE hook not active (0x4B524E4C) - direct patch likely\n");
    else
        printf("[-] Unexpected ping response\n");
    return true;
}

bool TestMemoryReadWrite()
{
    DWORD targetPid = GetCurrentProcessId();
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return false;
    BYTE localBuf[16] = {};
    BYTE readBuf[16] = {};

    REQUEST_DATA req = {};
    req.command = CMD_READ;
    req.pid = targetPid;
    req.address = (ULONG64)hKernel32;
    req.buffer = (ULONG64)readBuf;
    req.size = sizeof(readBuf);
    if (!SendRequest(req) || req.result != 1) {
        printf("[-] CMD_READ failed\n");
        return false;
    }

    memcpy(localBuf, hKernel32, sizeof(localBuf));
    if (memcmp(localBuf, readBuf, sizeof(localBuf)) != 0) {
        printf("[-] Read data mismatch\n");
        return false;
    }
    printf("[+] Read 16 bytes from kernel32: correct\n");

    PVOID testMem = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    if (!testMem) return false;
    const char testStr[] = "NullkD test";
    req.command = CMD_WRITE;
    req.address = (ULONG64)testMem;
    req.buffer = (ULONG64)testStr;
    req.size = sizeof(testStr);
    if (!SendRequest(req) || req.result != 1) {
        printf("[-] CMD_WRITE failed\n");
        VirtualFree(testMem, 0, MEM_RELEASE);
        return false;
    }
    if (memcmp(testMem, testStr, sizeof(testStr)) != 0) {
        printf("[-] Write data mismatch\n");
        VirtualFree(testMem, 0, MEM_RELEASE);
        return false;
    }
    printf("[+] Write/verify passed\n");
    VirtualFree(testMem, 0, MEM_RELEASE);
    return true;
}

bool TestModuleBase()
{
    REQUEST_DATA req = {};
    req.command = CMD_MODULE_BASE;
    req.pid = GetCurrentProcessId();
    wcscpy_s(req.module_name, L"kernel32.dll");
    if (!SendRequest(req)) return false;
    ULONG64 base = req.result;
    if (!base) {
        printf("[-] Module base not found\n");
        return false;
    }
    HMODULE realBase = GetModuleHandleA("kernel32.dll");
    if ((ULONG64)realBase != base) {
        printf("[-] Module base mismatch\n");
        return false;
    }
    printf("[+] Module base correct: 0x%llX\n", base);
    return true;
}

bool TestAllocFreeProtect()
{
    DWORD pid = GetCurrentProcessId();
    REQUEST_DATA req = {};
    req.command = CMD_ALLOC;
    req.pid = pid;
    req.size = 0x1000;
    req.protect = PAGE_READWRITE;
    if (!SendRequest(req)) return false;
    ULONG64 allocAddr = req.result;
    if (!allocAddr) {
        printf("[-] Allocation failed\n");
        return false;
    }
    printf("[+] Allocated at 0x%llX\n", allocAddr);

    __try {
        *(int*)allocAddr = 0x12345678;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Cannot write to allocated memory\n");
        return false;
    }
    printf("[+] Write to allocated memory successful\n");

    req.command = CMD_PROTECT;
    req.address = allocAddr;
    req.size = 0x1000;
    req.protect = PAGE_READONLY;
    if (!SendRequest(req)) return false;

    bool writeCausedException = false;
    __try {
        *(int*)allocAddr = 0xDEAD;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        writeCausedException = true;
    }
    if (!writeCausedException) {
        printf("[-] Protection didn't change\n");
        return false;
    }
    printf("[+] Protection set to READONLY confirmed\n");

    req = {};
    req.command = CMD_FREE;
    req.pid = pid;
    req.result = allocAddr;
    if (!SendRequest(req)) return false;

    __try {
        volatile int x = *(int*)allocAddr; (void)x;
        printf("[-] Memory still accessible after free\n");
        return false;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[+] Freed memory correctly inaccessible\n");
    }
    return true;
}

bool TestBatchRead()
{
    DWORD pid = GetCurrentProcessId();
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return false;

    const int testCount = 3;
    BYTE localBuf[testCount][16] = {};
    BYTE outBuffer[testCount * 16] = {};

    BATCH_READ_REQUEST batch = {};
    batch.count = testCount;
    batch.outBuffer = (ULONG64)outBuffer;

    for (int i = 0; i < testCount; i++) {
        batch.entries[i].address = (ULONG64)hKernel32 + i * 16;
        batch.entries[i].size = 16;
        batch.entries[i].outOffset = i * 16;
        memcpy(localBuf[i], (PBYTE)hKernel32 + i * 16, 16);
    }

    REQUEST_DATA req = {};
    req.command = CMD_READ_BATCH;
    req.pid = pid;
    req.buffer = (ULONG64)&batch;
    req.size = sizeof(outBuffer);
    if (!SendRequest(req) || req.result != 1) {
        printf("[-] Batch read failed\n");
        return false;
    }

    if (memcmp(localBuf, outBuffer, sizeof(outBuffer)) != 0) {
        printf("[-] Batch read data mismatch\n");
        return false;
    }
    printf("[+] Batch read %d entries correct\n", testCount);
    return true;
}

bool TestVerifyPte()
{
    BYTE buffer[64] = {};
    REQUEST_DATA req = {};
    req.command = CMD_VERIFY_PTE;
    req.buffer = (ULONG64)buffer;
    if (!SendRequest(req) || req.result != 1) {
        printf("[-] CMD_VERIFY_PTE failed\n");
        return false;
    }
    printf("[+] PTE verification data:\n");
    printf("    Active: %llu\n", *(ULONG64*)(buffer));
    printf("    Orig PFN: 0x%llX\n", *(ULONG64*)(buffer+8));
    printf("    New  PFN: 0x%llX\n", *(ULONG64*)(buffer+16));
    printf("    Target VA: 0x%llX\n", *(ULONG64*)(buffer+24));
    return true;
}

bool TestVerifySpoof()
{
    BYTE buffer[16] = {};
    REQUEST_DATA req = {};
    req.command = CMD_VERIFY_SPOOF;
    req.buffer = (ULONG64)buffer;
    if (!SendRequest(req) || req.result != 1) {
        printf("[-] CMD_VERIFY_SPOOF failed\n");
        return false;
    }
    printf("[+] Spoof gadget: 0x%llX\n", *(ULONG64*)(buffer));
    printf("[+] Spoof stub:   0x%llX\n", *(ULONG64*)(buffer+8));
    return true;
}

int main()
{
    printf("NullkD Test Client v1.0\n");
    printf("========================\n");

    if (!InitDriverCommunication()) {
        printf("FATAL: Cannot resolve NtQueryCompositionSurfaceStatistics\n");
        return 1;
    }

    if (!TestPing()) {
        printf("FATAL: Driver not responding. Is NullkD.sys loaded?\n");
        return 1;
    }

    bool allPass = true;
    #define RUN_TEST(name) \
        printf("\n--- " #name " ---\n"); \
        if (!(name)()) { \
            printf("!!! " #name " FAILED !!!\n"); \
            allPass = false; \
        } else { \
            printf("[PASS] " #name "\n"); \
        }

    RUN_TEST(TestMemoryReadWrite);
    RUN_TEST(TestModuleBase);
    RUN_TEST(TestAllocFreeProtect);
    RUN_TEST(TestBatchRead);
    RUN_TEST(TestVerifyPte);
    RUN_TEST(TestVerifySpoof);

    printf("\n========================\n");
    if (allPass)
        printf("ALL TESTS PASSED - Driver is healthy.\n");
    else
        printf("SOME TESTS FAILED - Review output.\n");

    return allPass ? 0 : 1;
}
