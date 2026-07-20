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

// ====================== Decryption از SDK ======================
namespace decryption {
    inline uintptr_t base_networkable_0(uintptr_t hv_value) {
        uintptr_t rax = hv_value;
        uint32_t* rdx = reinterpret_cast<uint32_t*>(&rax);
        for (uint32_t _i = 0; _i < 2; ++_i) {
            uint32_t v = *rdx;
            v = (v << 16) | (v >> 16);
            v ^= 0xFE89EFE3u;
            v -= 0x7C71A258u;
            *rdx = v;
            ++rdx;
        }
        return rax;
    }

    inline uintptr_t base_networkable_1(uintptr_t hv_value) {
        uintptr_t rax = hv_value;
        uint32_t* rdx = reinterpret_cast<uint32_t*>(&rax);
        for (uint32_t _i = 0; _i < 2; ++_i) {
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

// ====================== Offsets ======================
namespace offsets {
    uintptr_t GameAssembly = 0;

    namespace base_networkable {
        constexpr uintptr_t typeinfo = 0xFB99108;   // از SDK
    }
}

int main() {
    std::cout << "=== Rust SDK Tester ===\n\n";

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

    offsets::GameAssembly = GetModuleBase(pid, L"GameAssembly.dll");
    std::cout << "[+] GameAssembly: 0x" << std::hex << offsets::GameAssembly << "\n";

    // تست زنجیره BaseNetworkable
    uintptr_t bn = offsets::GameAssembly + offsets::base_networkable::typeinfo;
    std::cout << "[+] BaseNetworkable: 0x" << bn << "\n";

    uintptr_t static_fields = Read<uintptr_t>(hProc, bn + 0xB8);
    std::cout << "[+] Static Fields: 0x" << static_fields << "\n";

    // wrapper + parent + entity list (از SDK)
    uintptr_t wrapper = Read<uintptr_t>(hProc, static_fields + 0x8);
    uintptr_t hv = Read<uintptr_t>(hProc, wrapper + 0x18);
    uintptr_t decrypted = decryption::base_networkable_0(hv);

    uintptr_t parent = Read<uintptr_t>(hProc, decrypted + 0x10);
    uintptr_t hv2 = Read<uintptr_t>(hProc, parent + 0x18);
    uintptr_t entity_list_base = decryption::base_networkable_1(hv2);

    uintptr_t buffer = Read<uintptr_t>(hProc, entity_list_base + 0x10);
    int count = Read<int>(hProc, entity_list_base + 0x18);

    std::cout << "[+] Entity Buffer: 0x" << buffer << "\n";
    std::cout << "[+] Entity Count : " << std::dec << count << "\n";

    CloseHandle(hProc);
    system("pause");
    return 0;
}
