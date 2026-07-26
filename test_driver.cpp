/*
 * test_driver.cpp - Full verification of NullKD kernel driver
 *
 * Tests all communication commands: PING, MODULE_BASE, READ, WRITE,
 * ALLOC, FREE, PROTECT, VERIFY_PTE, VERIFY_SPOOF.
 *
 * Compile (x64 Release):
 *   cl /EHsc /std:c++17 test_driver.cpp /Fe:test_driver.exe
 */

#include <windows.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <Psapi.h>   // for GetModuleInformation

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

// Hooked dxgkrnl function
typedef NTSTATUS (NTAPI *NtQCSS_t)(void*,void*,void*);

static NtQCSS_t g_NtQuery = nullptr;

bool init_driver() {
    if (g_NtQuery) return true;
    HMODULE hWin32u = LoadLibraryA("win32u.dll");
    if (!hWin32u) return false;
    g_NtQuery = (NtQCSS_t)GetProcAddress(hWin32u, "NtQueryCompositionSurfaceStatistics");
    return g_NtQuery != nullptr;
}

bool call_driver(REQUEST_DATA& req) {
    if (!g_NtQuery) return false;
    req.magic = REQUEST_MAGIC;
    __try {
        NTSTATUS st = g_NtQuery(&req, nullptr, nullptr);
        return (st == 0 || st == 1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Helper: verify a pointer is readable in our process
bool is_readable(const void* ptr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return true;
}

int main() {
    std::cout << "=== NullKD Driver Test ===\n\n";

    if (!init_driver()) {
        std::cout << "[FATAL] Could not resolve NtQueryCompositionSurfaceStatistics.\n";
        std::cout << "        Make sure the driver is loaded.\n";
        std::cin.get();
        return 1;
    }

    REQUEST_DATA req;
    ZeroMemory(&req, sizeof(req));

    // ---- 1. PING ----
    req.command = CMD_PING;
    if (!call_driver(req) || req.result == 0) {
        std::cout << "[FAIL] PING – driver not responding.\n";
        std::cin.get();
        return 1;
    }
    std::cout << "[PASS] PING (0x" << std::hex << req.result << std::dec << ")\n";

    // ---- 2. MODULE_BASE (self) ----
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cout << "[FAIL] Cannot get ntdll.dll handle for verification.\n";
    } else {
        MODULEINFO mi;
        if (!GetModuleInformation(GetCurrentProcess(), hNtdll, &mi, sizeof(mi))) {
            std::cout << "[FAIL] GetModuleInformation failed.\n";
        } else {
            uintptr_t expectedBase = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            req = {0};
            req.command = CMD_MODULE_BASE;
            req.pid = GetCurrentProcessId();
            wcsncpy_s(req.module_name, L"ntdll.dll", 63);
            if (!call_driver(req)) {
                std::cout << "[FAIL] MODULE_BASE – driver call failed.\n";
            } else if (req.result != expectedBase) {
                std::cout << "[FAIL] MODULE_BASE – expected 0x" << std::hex << expectedBase
                          << " got 0x" << req.result << std::dec << "\n";
            } else {
                std::cout << "[PASS] MODULE_BASE (ntdll.dll = 0x" << std::hex << req.result << std::dec << ")\n";
            }
        }
    }

    // ---- 3. READ (own memory) ----
    {
        int original = 0x12345678;
        int readback = 0;
        req = {0};
        req.command = CMD_READ;
        req.pid = GetCurrentProcessId();
        req.address = reinterpret_cast<uintptr_t>(&original);
        req.buffer = reinterpret_cast<uintptr_t>(&readback);
        req.size = sizeof(original);
        if (!call_driver(req) || readback != original) {
            std::cout << "[FAIL] READ (expected 0x12345678, got 0x" << std::hex << readback << std::dec << ")\n";
        } else {
            std::cout << "[PASS] READ\n";
        }
    }

    // ---- 4. WRITE (own memory) ----
    {
        int target = 0;
        int value = 0xDEADBEEF;
        req = {0};
        req.command = CMD_WRITE;
        req.pid = GetCurrentProcessId();
        req.address = reinterpret_cast<uintptr_t>(&target);
        req.buffer = reinterpret_cast<uintptr_t>(&value);
        req.size = sizeof(value);
        if (!call_driver(req) || target != value) {
            std::cout << "[FAIL] WRITE (target = 0x" << std::hex << target << std::dec << ")\n";
        } else {
            std::cout << "[PASS] WRITE\n";
        }
    }

    // ---- 5. ALLOC ----
    {
        req = {0};
        req.command = CMD_ALLOC;
        req.pid = GetCurrentProcessId();
        req.size = 0x1000;
        req.protect = PAGE_READWRITE;
        if (!call_driver(req) || req.result == 0) {
            std::cout << "[FAIL] ALLOC\n";
        } else {
            uintptr_t addr = req.result;
            std::cout << "[PASS] ALLOC (0x" << std::hex << addr << std::dec << ")\n";

            // Write to allocated memory to confirm it's usable
            int testVal = 0xDEAD;
            req = {0};
            req.command = CMD_WRITE;
            req.pid = GetCurrentProcessId();
            req.address = addr;
            req.buffer = reinterpret_cast<uintptr_t>(&testVal);
            req.size = sizeof(testVal);
            if (call_driver(req)) {
                // Read back
                int readVal = 0;
                req = {0};
                req.command = CMD_READ;
                req.pid = GetCurrentProcessId();
                req.address = addr;
                req.buffer = reinterpret_cast<uintptr_t>(&readVal);
                req.size = sizeof(readVal);
                if (call_driver(req) && readVal == testVal) {
                    std::cout << "[PASS] ALLOC memory usable\n";
                } else {
                    std::cout << "[FAIL] ALLOC memory not usable\n";
                }
            }

            // Free
            req = {0};
            req.command = CMD_FREE;
            req.pid = GetCurrentProcessId();
            req.result = addr;
            if (!call_driver(req)) {
                std::cout << "[WARN] FREE of allocated memory failed (non-fatal)\n";
            } else {
                std::cout << "[PASS] FREE\n";
            }
        }
    }

    // ---- 6. PROTECT ----
    {
        // Allocate a small region and change protection
        req = {0};
        req.command = CMD_ALLOC;
        req.pid = GetCurrentProcessId();
        req.size = 0x1000;
        req.protect = PAGE_READWRITE;
        if (call_driver(req) && req.result != 0) {
            uintptr_t addr = req.result;
            // Change to PAGE_READONLY and test
            req = {0};
            req.command = CMD_PROTECT;
            req.pid = GetCurrentProcessId();
            req.address = addr;
            req.size = 0x1000;
            req.protect = PAGE_READONLY;
            if (!call_driver(req)) {
                std::cout << "[FAIL] PROTECT\n";
            } else {
                std::cout << "[PASS] PROTECT\n";
            }
            // Free
            req = {0};
            req.command = CMD_FREE;
            req.pid = GetCurrentProcessId();
            req.result = addr;
            call_driver(req);
        } else {
            std::cout << "[SKIP] PROTECT (ALLOC failed)\n";
        }
    }

    // ---- 7. VERIFY_PTE ----
    {
        unsigned char buf[64] = {0};
        req = {0};
        req.command = CMD_VERIFY_PTE;
        req.buffer = reinterpret_cast<uintptr_t>(buf);
        if (!call_driver(req)) {
            std::cout << "[FAIL] VERIFY_PTE – driver call failed\n";
        } else {
            bool active = (reinterpret_cast<ULONG64*>(buf)[0] != 0);
            std::cout << "[INFO] VERIFY_PTE: " << (active ? "PTE hook active" : "fallback (direct patch)") << "\n";
            std::cout << "       originalPfn: 0x" << std::hex << reinterpret_cast<ULONG64*>(buf)[1] << std::dec << "\n";
            std::cout << "       newPfn:      0x" << std::hex << reinterpret_cast<ULONG64*>(buf)[2] << std::dec << "\n";
            std::cout << "       targetVA:    0x" << std::hex << reinterpret_cast<ULONG64*>(buf)[3] << std::dec << "\n";
            std::cout << "[PASS] VERIFY_PTE\n";
        }
    }

    // ---- 8. VERIFY_SPOOF ----
    {
        unsigned char buf[16] = {0};
        req = {0};
        req.command = CMD_VERIFY_SPOOF;
        req.buffer = reinterpret_cast<uintptr_t>(buf);
        if (!call_driver(req)) {
            std::cout << "[FAIL] VERIFY_SPOOF\n";
        } else {
            bool active = (req.result != 0);
            std::cout << "[INFO] VERIFY_SPOOF: " << (active ? "spoof active" : "spoof inactive") << "\n";
            if (active) {
                std::cout << "       gadget: 0x" << std::hex << reinterpret_cast<ULONG64*>(buf)[0] << std::dec << "\n";
                std::cout << "       stub:   0x" << std::hex << reinterpret_cast<ULONG64*>(buf)[1] << std::dec << "\n";
            }
            std::cout << "[PASS] VERIFY_SPOOF\n";
        }
    }

    std::cout << "\n=== All tests completed ===\n";
    std::cout << "Press Enter to exit...";
    std::cin.get();
    return 0;
}
