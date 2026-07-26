/*
 * test_driver.cpp - Robust verification of NullKD kernel driver
 */

#include <windows.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <Psapi.h>
#include <vector>

#pragma comment(lib, "psapi.lib")

#define REQUEST_MAGIC 0x44524B4E

enum DRIVER_COMMAND {
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
};

typedef struct _REQUEST_DATA {
    unsigned int    magic;
    unsigned int    command;
    unsigned int    protect;
    unsigned __int64 pid;
    unsigned __int64 address;
    unsigned __int64 buffer;
    unsigned __int64 size;
    unsigned __int64 result;
    wchar_t         module_name[64];
} REQUEST_DATA, *PREQUEST_DATA;

typedef NTSTATUS (NTAPI *NtQCSS_t)(void*, void*, void*);
static NtQCSS_t g_NtQuery = nullptr;

#define LOG(msg) do { std::cout << msg << std::endl; } while(0)

bool init_driver() {
    LOG("[*] Resolving win32u!NtQueryCompositionSurfaceStatistics...");
    HMODULE hWin32u = GetModuleHandleA("win32u.dll");
    if (!hWin32u) {
        hWin32u = LoadLibraryA("win32u.dll");
    }
    if (!hWin32u) {
        LOG("[FATAL] win32u.dll not found.");
        return false;
    }
    g_NtQuery = (NtQCSS_t)GetProcAddress(hWin32u, "NtQueryCompositionSurfaceStatistics");
    if (!g_NtQuery) {
        LOG("[FATAL] Export not found.");
        return false;
    }
    return true;
}

bool call_driver(REQUEST_DATA& req) {
    if (!g_NtQuery) return false;
    req.magic = REQUEST_MAGIC;
    __try {
        NTSTATUS st = g_NtQuery(&req, nullptr, nullptr);
        return (st == 0 || st == 1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG("[!] Exception during driver call.");
        return false;
    }
}

int main() {
    LOG("=== NullKD Driver Test ===");

    if (!init_driver()) {
        std::cin.get();
        return 1;
    }

    // 1. PING
    {
        REQUEST_DATA req = {};
        req.command = CMD_PING;
        LOG("[*] Sending PING...");
        if (!call_driver(req) || req.result == 0) {
            LOG("[FAIL] PING (result=0x" << std::hex << req.result << std::dec << ")");
            LOG("[HINT] Make sure NullKD.sys is loaded.");
            std::cin.get();
            return 1;
        }
        LOG("[PASS] PING");
    }

    // 2. MODULE_BASE
    {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        MODULEINFO mi;
        if (hNtdll && GetModuleInformation(GetCurrentProcess(), hNtdll, &mi, sizeof(mi))) {
            uintptr_t expected = (uintptr_t)mi.lpBaseOfDll;
            REQUEST_DATA req = {};
            req.command = CMD_MODULE_BASE;
            req.pid = GetCurrentProcessId();
            wcsncpy_s(req.module_name, L"ntdll.dll", 63);
            if (!call_driver(req) || req.result != expected)
                LOG("[FAIL] MODULE_BASE");
            else
                LOG("[PASS] MODULE_BASE");
        }
    }

    // 3. READ / WRITE
    {
        int original = 0x12345678, readback = 0;
        REQUEST_DATA req = {};
        req.command = CMD_READ;
        req.pid = GetCurrentProcessId();
        req.address = (uintptr_t)&original;
        req.buffer = (uintptr_t)&readback;
        req.size = 4;
        if (!call_driver(req) || readback != original)
            LOG("[FAIL] READ");
        else {
            LOG("[PASS] READ");
            int target = 0;
            req = {}; req.command = CMD_WRITE; req.pid = GetCurrentProcessId();
            req.address = (uintptr_t)&target; req.buffer = (uintptr_t)&original; req.size = 4;
            if (!call_driver(req) || target != original)
                LOG("[FAIL] WRITE");
            else
                LOG("[PASS] WRITE");
        }
    }

    // 4. ALLOC + FREE
    {
        REQUEST_DATA req = {};
        req.command = CMD_ALLOC; req.pid = GetCurrentProcessId(); req.size = 0x1000; req.protect = PAGE_READWRITE;
        if (!call_driver(req) || req.result == 0)
            LOG("[FAIL] ALLOC");
        else {
            LOG("[PASS] ALLOC");
            req = {}; req.command = CMD_FREE; req.pid = GetCurrentProcessId(); req.result = req.result; // use previous value? Actually need to store it.
            // Let's simplify:
            uintptr_t addr = req.result;
            req = {}; req.command = CMD_FREE; req.pid = GetCurrentProcessId(); req.result = addr;
            if (call_driver(req)) LOG("[PASS] FREE");
            else LOG("[WARN] FREE");
        }
    }

    // 5. PROTECT
    {
        REQUEST_DATA req = {};
        req.command = CMD_ALLOC; req.pid = GetCurrentProcessId(); req.size = 0x1000; req.protect = PAGE_READWRITE;
        if (call_driver(req) && req.result) {
            uintptr_t addr = req.result;
            req = {}; req.command = CMD_PROTECT; req.pid = GetCurrentProcessId(); req.address = addr;
            req.size = 0x1000; req.protect = PAGE_READONLY;
            if (call_driver(req)) LOG("[PASS] PROTECT");
            else LOG("[FAIL] PROTECT");
            req = {}; req.command = CMD_FREE; req.pid = GetCurrentProcessId(); req.result = addr;
            call_driver(req);
        }
    }

    // 6. VERIFY_PTE
    {
        unsigned char buf[64] = {};
        REQUEST_DATA req = {};
        req.command = CMD_VERIFY_PTE; req.buffer = (uintptr_t)buf;
        if (call_driver(req))
            LOG("[PASS] VERIFY_PTE");
        else
            LOG("[FAIL] VERIFY_PTE");
    }

    // 7. VERIFY_SPOOF
    {
        unsigned char buf[16] = {};
        REQUEST_DATA req = {};
        req.command = CMD_VERIFY_SPOOF; req.buffer = (uintptr_t)buf;
        if (call_driver(req))
            LOG("[PASS] VERIFY_SPOOF");
        else
            LOG("[FAIL] VERIFY_SPOOF");
    }

    LOG("\n=== All tests completed ===");
    LOG("Press Enter to exit...");
    std::cin.get();
    return 0;
}
