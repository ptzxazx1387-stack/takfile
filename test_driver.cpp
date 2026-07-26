/*
 * test_driver.cpp - Robust verification of NullKD kernel driver
 */

#include <windows.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <Psapi.h>
#include <vector>
#include <chrono>
#include <thread>

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

// Force flush after every line
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
    LOG("[*] Function resolved at 0x" << std::hex << (uintptr_t)g_NtQuery << std::dec);
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
        LOG("[!] Exception during driver call (caught).");
        return false;
    }
}

int main() {
    LOG("=== NullKD Driver Test ===");

    // 1. Initialize
    __try {
        if (!init_driver()) {
            LOG("[FATAL] Initialization failed. Is the driver loaded?");
            std::cin.get();
            return 1;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG("[FATAL] Exception during init_driver.");
        std::cin.get();
        return 1;
    }

    // 2. Quick safety check: call with zeroed request to see if the function is reachable
    {
        REQUEST_DATA zero = {};
        LOG("[*] Testing raw call to driver (expecting no crash)...");
        __try {
            g_NtQuery(&zero, nullptr, nullptr);
            LOG("[*] Raw call returned safely (driver may not be hooked yet).");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LOG("[FATAL] Raw call caused exception. Driver hook may be unstable.");
            std::cin.get();
            return 1;
        }
    }

    // 3. PING
    {
        REQUEST_DATA req = {};
        req.command = CMD_PING;
        LOG("[*] Sending PING...");
        if (!call_driver(req) || req.result == 0) {
            LOG("[FAIL] PING – driver not responding. (result=0x" << std::hex << req.result << std::dec << ")");
            LOG("[HINT] Make sure NullKD.sys is loaded with kdmapper.");
            std::cin.get();
            return 1;
        }
        LOG("[PASS] PING (0x" << std::hex << req.result << std::dec << ")");
    }

    // 4. MODULE_BASE
    {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) {
            LOG("[SKIP] MODULE_BASE (ntdll not found)");
        } else {
            MODULEINFO mi;
            if (GetModuleInformation(GetCurrentProcess(), hNtdll, &mi, sizeof(mi))) {
                uintptr_t expected = (uintptr_t)mi.lpBaseOfDll;
                REQUEST_DATA req = {};
                req.command = CMD_MODULE_BASE;
                req.pid = GetCurrentProcessId();
                wcsncpy_s(req.module_name, L"ntdll.dll", 63);
                LOG("[*] Sending MODULE_BASE for ntdll.dll...");
                if (!call_driver(req) || req.result != expected) {
                    LOG("[FAIL] MODULE_BASE expected 0x" << std::hex << expected << " got 0x" << req.result << std::dec);
                } else {
                    LOG("[PASS] MODULE_BASE");
                }
            } else {
                LOG("[SKIP] MODULE_BASE (GetModuleInformation failed)");
            }
        }
    }

    // 5. READ
    {
        int original = 0x12345678;
        int readback = 0;
        REQUEST_DATA req = {};
        req.command = CMD_READ;
        req.pid = GetCurrentProcessId();
        req.address = (uintptr_t)&original;
        req.buffer = (uintptr_t)&readback;
        req.size = sizeof(original);
        LOG("[*] Sending READ...");
        if (!call_driver(req) || readback != original) {
            LOG("[FAIL] READ (got 0x" << std::hex << readback << std::dec << ")");
        } else {
            LOG("[PASS] READ");
        }
    }

    // 6. WRITE
    {
        int target = 0;
        int value = 0xDEADBEEF;
        REQUEST_DATA req = {};
        req.command = CMD_WRITE;
        req.pid = GetCurrentProcessId();
        req.address = (uintptr_t)&target;
        req.buffer = (uintptr_t)&value;
        req.size = sizeof(value);
        LOG("[*] Sending WRITE...");
        if (!call_driver(req) || target != value) {
            LOG("[FAIL] WRITE");
        } else {
            LOG("[PASS] WRITE");
        }
    }

    // 7. ALLOC + FREE
    {
        REQUEST_DATA req = {};
        req.command = CMD_ALLOC;
        req.pid = GetCurrentProcessId();
        req.size = 0x1000;
        req.protect = PAGE_READWRITE;
        LOG("[*] Sending ALLOC...");
        if (!call_driver(req) || req.result == 0) {
            LOG("[FAIL] ALLOC");
        } else {
            uintptr_t addr = req.result;
            LOG("[PASS] ALLOC (0x" << std::hex << addr << std::dec << ")");
            // Test usability
            int testVal = 0x1234;
            req = {};
            req.command = CMD_WRITE;
            req.pid = GetCurrentProcessId();
            req.address = addr;
            req.buffer = (uintptr_t)&testVal;
            req.size = sizeof(testVal);
            if (call_driver(req)) {
                int readVal = 0;
                req = {};
                req.command = CMD_READ;
                req.pid = GetCurrentProcessId();
                req.address = addr;
                req.buffer = (uintptr_t)&readVal;
                req.size = sizeof(readVal);
                if (call_driver(req) && readVal == testVal) {
                    LOG("[PASS] Allocated memory usable");
                } else {
                    LOG("[FAIL] Allocated memory not usable");
                }
            }
            // Free
            req = {};
            req.command = CMD_FREE;
            req.pid = GetCurrentProcessId();
            req.result = addr;
            if (call_driver(req)) {
                LOG("[PASS] FREE");
            } else {
                LOG("[WARN] FREE failed");
            }
        }
    }

    // 8. PROTECT
    {
        REQUEST_DATA req = {};
        req.command = CMD_ALLOC;
        req.pid = GetCurrentProcessId();
        req.size = 0x1000;
        req.protect = PAGE_READWRITE;
        if (call_driver(req) && req.result != 0) {
            uintptr_t addr = req.result;
            req = {};
            req.command = CMD_PROTECT;
            req.pid = GetCurrentProcessId();
            req.address = addr;
            req.size = 0x1000;
            req.protect = PAGE_READONLY;
            LOG("[*] Sending PROTECT...");
            if (call_driver(req)) {
                LOG("[PASS] PROTECT");
            } else {
                LOG("[FAIL] PROTECT");
            }
            // Cleanup
            req = {};
            req.command = CMD_FREE;
            req.pid = GetCurrentProcessId();
            req.result = addr;
            call_driver(req);
        } else {
            LOG("[SKIP] PROTECT (ALLOC failed)");
        }
    }

    // 9. VERIFY_PTE
    {
        unsigned char buf[64] = {};
        REQUEST_DATA req = {};
        req.command = CMD_VERIFY_PTE;
        req.buffer = (uintptr_t)buf;
        LOG("[*] Sending VERIFY_PTE...");
        if (!call_driver(req)) {
            LOG("[FAIL] VERIFY_PTE call failed");
        } else {
            bool active = (*(uint64_t*)(buf + 0) != 0);
            LOG("[PASS] VERIFY_PTE: " << (active ? "PTE hook active" : "fallback (direct patch)"));
        }
    }

    // 10. VERIFY_SPOOF
    {
        unsigned char buf[16] = {};
        REQUEST_DATA req = {};
        req.command = CMD_VERIFY_SPOOF;
        req.buffer = (uintptr_t)buf;
        LOG("[*] Sending VERIFY_SPOOF...");
        if (!call_driver(req)) {
            LOG("[FAIL] VERIFY_SPOOF");
        } else {
            bool active = (req.result != 0);
            LOG("[PASS] VERIFY_SPOOF: " << (active ? "spoof active" : "spoof inactive"));
        }
    }

    LOG("\n=== All tests completed ===");
    LOG("Press Enter to exit...");
    std::cin.get();
    return 0;
}
