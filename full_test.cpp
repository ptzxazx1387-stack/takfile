#include <iostream>
#include <Windows.h>
#include <string>

// ============ copy from shared.h ============
#define REQUEST_MAGIC 0x44524B4E

enum {
    CMD_READ = 1,
    CMD_WRITE = 2,
    CMD_MODULE_BASE = 3,
    CMD_ALLOC = 4,
    CMD_FREE = 5,
    CMD_PROTECT = 6,
    CMD_PING = 99,
    CMD_VERIFY_PTE = 100,
    CMD_VERIFY_SPOOF = 101,
};

typedef struct _REQ {
    unsigned int magic;
    unsigned int command;
    unsigned __int64 pid;
    unsigned __int64 address;
    unsigned __int64 buffer;
    unsigned __int64 size;
    unsigned __int64 result;
    unsigned int protect;
    wchar_t module_name[64];
} REQ;

typedef NTSTATUS(NTAPI* NtQCSS_t)(void*, void*, void*);
// ============================================

NtQCSS_t NtQCSS = 0;

void init() {
    HMODULE h = LoadLibraryA("win32u.dll");
    if (h) NtQCSS = (NtQCSS_t)GetProcAddress(h, "NtQueryCompositionSurfaceStatistics");
}

bool call(REQ& r) {
    if (!NtQCSS) return false;
    r.magic = REQUEST_MAGIC;
    NTSTATUS s = NtQCSS(&r, nullptr, nullptr);
    return (s == 0);
}

int main() {
    std::cout << "NullKD Driver Test Suite" << std::endl;
    std::cout << "========================" << std::endl;
    
    init();
    if (!NtQCSS) {
        std::cout << "FATAL: Cannot find NtQueryCompositionSurfaceStatistics" << std::endl;
        std::cout << "Make sure driver is loaded first!" << std::endl;
        return 1;
    }
    
    // [1] PING
    std::cout << "\n[1/6] PING... ";
    {
        REQ r = { 0 };
        r.command = CMD_PING;
        if (call(r)) {
            if (r.result == 0x50544548)
                std::cout << "OK (PTE Hook Active)" << std::endl;
            else if (r.result == 0x4B524E4C)
                std::cout << "OK (Fallback Hook)" << std::endl;
            else
                std::cout << "UNKNOWN: 0x" << std::hex << r.result << std::dec << std::endl;
        } else {
            std::cout << "FAIL - Driver not responding!" << std::endl;
        }
    }
    
    // [2] READ
    std::cout << "[2/6] Physical Read... ";
    {
        int orig = 0x12345678;
        int read = 0;
        REQ r = { 0 };
        r.command = CMD_READ;
        r.pid = GetCurrentProcessId();
        r.address = (uintptr_t)&orig;
        r.buffer = (uintptr_t)&read;
        r.size = 4;
        if (call(r) && read == orig)
            std::cout << "OK" << std::endl;
        else
            std::cout << "FAIL" << std::endl;
    }
    
    // [3] WRITE
    std::cout << "[3/6] Physical Write... ";
    {
        int val = 0;
        int newVal = 0xDEAD;
        REQ r = { 0 };
        r.command = CMD_WRITE;
        r.pid = GetCurrentProcessId();
        r.address = (uintptr_t)&val;
        r.buffer = (uintptr_t)&newVal;
        r.size = 4;
        if (call(r) && val == 0xDEAD)
            std::cout << "OK" << std::endl;
        else
            std::cout << "FAIL" << std::endl;
    }
    
    // [4] ALLOC
    std::cout << "[4/6] Alloc in self... ";
    {
        REQ r = { 0 };
        r.command = CMD_ALLOC;
        r.pid = GetCurrentProcessId();
        r.size = 0x1000;
        r.protect = 0x40;
        if (call(r) && r.result > 0) {
            std::cout << "OK (0x" << std::hex << r.result << std::dec << ")" << std::endl;
            REQ f = { 0 };
            f.command = CMD_FREE;
            f.pid = GetCurrentProcessId();
            f.result = r.result;
            call(f);
        } else {
            std::cout << "FAIL" << std::endl;
        }
    }
    
    // [5] MODULE BASE
    std::cout << "[5/6] Module base... ";
    {
        REQ r = { 0 };
        r.command = CMD_MODULE_BASE;
        r.pid = GetCurrentProcessId();
        wcscpy_s(r.module_name, L"ntdll.dll");
        if (call(r) && r.result > 0)
            std::cout << "OK (ntdll: 0x" << std::hex << r.result << std::dec << ")" << std::endl;
        else
            std::cout << "FAIL" << std::endl;
    }
    
    // [6] VERIFY PTE
    std::cout << "[6/6] PTE Hook Info... " << std::endl;
    {
        unsigned char buf[64] = { 0 };
        REQ r = { 0 };
        r.command = CMD_VERIFY_PTE;
        r.buffer = (uintptr_t)buf;
        if (call(r)) {
            uint64_t active = *(uint64_t*)(buf + 0);
            uint64_t origPfn = *(uint64_t*)(buf + 8);
            uint64_t newPfn = *(uint64_t*)(buf + 16);
            uint64_t targetVA = *(uint64_t*)(buf + 24);
            unsigned char* origBytes = buf + 32;
            unsigned char* virtBytes = buf + 48;
            
            std::cout << "    Active:    " << active << std::endl;
            std::cout << "    Orig PFN:  0x" << std::hex << origPfn << std::dec << std::endl;
            std::cout << "    New PFN:   0x" << std::hex << newPfn << std::dec << std::endl;
            std::cout << "    Target VA: 0x" << std::hex << targetVA << std::dec << std::endl;
            
            std::cout << "    Orig page: ";
            for (int i = 0; i < 12; i++) printf("%02X ", origBytes[i]);
            std::cout << std::endl;
            std::cout << "    Virt page: ";
            for (int i = 0; i < 12; i++) printf("%02X ", virtBytes[i]);
            std::cout << std::endl;
            
            if (memcmp(origBytes, virtBytes, 12) != 0)
                std::cout << "    [OK] Trampoline detected (pages differ)" << std::endl;
            else
                std::cout << "    [!] Pages identical - fallback hook?" << std::endl;
        } else {
            std::cout << "    FAIL" << std::endl;
        }
    }
    
    std::cout << "\n========================" << std::endl;
    std::cout << "Tests complete." << std::endl;
    std::cout << "If all OK: ready for real system." << std::endl;
    std::cout << "Press any key to exit...";
    std::cin.get();
    return 0;
}
