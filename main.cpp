#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <iomanip>
#include <string>

DWORD GetProcessId(const wchar_t* procName) {
    PROCESSENTRY32W pe = { sizeof(pe) };
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
    MODULEENTRY32W me = { sizeof(me) };
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
    T val = {};
    ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(addr), &val, sizeof(T), nullptr);
    return val;
}

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
    std::cout << "=== Rust Final Tester (Wrapper Test) ===\n\n";

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

    uintptr_t bn = ga + 0xFB99108;
    std::cout << "BaseNetworkable: 0x" << bn << "\n";

    uintptr_t sf = Read<uintptr_t>(hProc, bn + 0xB8);
    std::cout << "Static Fields: 0x" << sf << "\n";

    // تست offsetهای مختلف wrapper
    std::vector<uint32_t> offsets = {0x0, 0x8, 0x10, 0x20, 0x28, 0x30};
    for (auto off : offsets) {
        uintptr_t w = Read<uintptr_t>(hProc, sf + off);
        std::cout << "Wrapper (+" << std::hex << off << "): 0x" << w << "\n";

        if (w > 0x10000) {
            uintptr_t hv = Read<uintptr_t>(hProc, w + 0x18);
            std::cout << "  HV (+0x18): 0x" << hv << "\n";
            if (hv) {
                uintptr_t dec = decryption::base_networkable_0(hv);
                std::cout << "  Dec: 0x" << dec << "\n";
            }
        }
    }

    std::cout << "\nDirect Count: " << std::dec << Read<int>(hProc, ga + 0x3c830a0 + 0x18) << "\n";

    CloseHandle(hProc);
    system("pause");
    return 0;
}
