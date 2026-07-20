#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <iomanip>
#include <string>

DWORD GetProcessId(const wchar_t* procName) {
    PROCESSENTRY32W pe{ sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, procName) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

uintptr_t GetModuleBase(DWORD pid, const wchar_t* modName) {
    MODULEENTRY32W me{ sizeof(me) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, modName) == 0) {
                CloseHandle(snap);
                return reinterpret_cast<uintptr_t>(me.modBaseAddr);
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return 0;
}

template<typename T>
T Read(HANDLE hProc, uintptr_t addr) {
    T val{};
    ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(addr), &val, sizeof(T), nullptr);
    return val;
**باشه، کامل کامل.** 

### `main.cpp` نهایی (همه توابع پر شده + تست جامع)

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <iomanip>
#include <string>

DWORD GetProcessId(const wchar_t* procName) {
    PROCESSENTRY32W pe{ sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, procName) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

uintptr_t GetModuleBase(DWORD pid, const wchar_t* modName) {
    MODULEENTRY32W me{ sizeof(me) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, modName) == 0) {
                CloseHandle(snap);
                return reinterpret_cast<uintptr_t>(me.modBaseAddr);
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return 0;
}

template<typename T>
T Read(HANDLE hProc, uintptr_t addr) {
    T val{};
    ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(addr), &val, sizeof(T), nullptr);
    return val;
}

// ====================== Decryption (از SDK) ======================
namespace decryption {
    inline uintptr_t base_networkable_0(uintptr_t hv) {
        uintptr_t rax = hv;
        uint32_t* rdx = reinterpret_cast<uint32_t*>(&rax);
        for (uint32_t i = 0; i < 2; ++i) {
            uint32_t v = *rdx;
            v = (v << 16) | (v >> 16);
            v ^= 0xFE89EFE3u;
            v -= 0x7C71A258u;
            *rdx = v;
            ++rdx;
        }
        return rax;
    }

    inline uintptr_t base_networkable_1(uintptr_t hv) {
        uintptr_t rax = hv;
        uint32_t* rdx = reinterpret_cast<uint32_t*>(&rax);
        for (uint32_t i = 0; i < 2; ++i) {
            uint32_t v = *rdx;
            v += 0xEBB43A5Au;
            v = (v << 23) | (v >> 9);
            v += 0x4A9A11E7u;
            v = (v << 28) | (v >> 4);
            *rdx = v;
            ++rdx;
        }
        return rax;
    }
}

int main() {
    std::cout << "=== Rust Comprehensive Tester (Full) ===\n\n";

    DWORD pid = GetProcessId(L"RustClient.exe");
    if (!pid) {
        std::cout << "[-] RustClient.exe پیدا نشد!\n";
        system("pause");
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        std::cout << "[-] OpenProcess شکست خورد!\n";
        system("pause");
        return 1;
    }

    uintptr_t ga = GetModuleBase(pid, L"GameAssembly.dll");
    std::cout << "[+] GameAssembly: 0x" << std::hex << ga << "\n\n";

    // تست 1: BaseNetworkable (SDK)
    std::cout << "--- Test 1: BaseNetworkable (SDK) ---\n";
    uintptr_t bn = ga + 0xFB99108;
    std::cout << "BaseNetworkable: 0x" << bn << "\n";

    uintptr_t static_fields = Read<uintptr_t>(hProc, bn + 0xB8);
    std::cout << "Static Fields: 0x" << static_fields << "\n";

    uintptr_t wrapper = Read<uintptr_t>(hProc, static_fields + 0x8);
    std::cout << "Wrapper: 0x" << wrapper << "\n";

    uintptr_t hv1 = Read<uintptr_t>(hProc, wrapper + 0x18);
    std::cout << "HV1 raw: 0x" << hv1 << "\n";

    uintptr_t dec1 = decryption::base_networkable_0(hv1);
    std::cout << "Dec1: 0x" << dec1 << "\n";

    uintptr_t parent = Read<uintptr_t>(hProc, dec1 + 0x10);
    std::cout << "Parent: 0x" << parent << "\n";

    if (parent == 0) {
        std::cout << "[!] Parent صفر شد - decryption مشکل داره\n";
    } else {
        uintptr_t hv2 = Read<uintptr_t>(hProc, parent + 0x18);
        uintptr_t entity_dict = decryption::base_networkable_1(hv2);
        std::cout << "Entity Dict: 0x" << entity_dict << "\n";

        uintptr_t buffer = Read<uintptr_t>(hProc, entity_dict + 0x10);
        int count = Read<int>(hProc, entity_dict + 0x18);

        std::cout << "Buffer List: 0x" << buffer << "\n";
        std::cout << "Entity Count: " << std::dec << count << "\n";
    }

    // تست 2: Direct RVA (از دامپ اولیه)
    std::cout << "\n--- Test 2: Direct Ent List ---\n";
    uintptr_t direct = ga + 0x3c830a0;
    int direct_count = Read<int>(hProc, direct + 0x18);
    std::cout << "Direct Entity Count: " << direct_count << "\n";

    CloseHandle(hProc);
    system("pause");
    return 0;
}
