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

// Decryption Placeholders
uintptr_t decryptIl2cppHandle(uintptr_t handle) {
    if (handle <= 0 || handle > 0xFFFFFFFFULL) return 0;
    return handle;
}

uintptr_t client_entities(uintptr_t a1, HANDLE hProc) {
    if (!a1) return 0;
    uint64_t rax = Read<uint64_t>(hProc, a1 + 0x18);
    uint32_t* rdx = reinterpret_cast<uint32_t*>(&rax);
    for (uint32_t i = 0; i < 2; ++i) {
        uint32_t eax = *rdx;
        uint32_t ecx = eax;
        // TODO: decryption واقعی اینجا (از IDA)
        // مثال (ممکنه اشتباه باشه - باید از IDA بگیری):
        eax = (eax ^ 0x1E7771E);
        ecx = ecx >> 0x1A;
        eax = (eax << 0x6) | ecx;
        eax = eax - 0x1118D90C;
        *rdx++ = eax;
    }
    return decryptIl2cppHandle(rax);
}

uintptr_t entity_list(uintptr_t a1, HANDLE hProc) {
    if (!a1) return 0;
    uint64_t rax = Read<uint64_t>(hProc, a1 + 0x18);
    uint32_t* rdx = reinterpret_cast<uint32_t*>(&rax);
    for (uint32_t i = 0; i < 2; ++i) {
        uint32_t eax = *rdx;
        uint32_t ecx = eax;
        // TODO: decryption واقعی
        *rdx++ = eax;
    }
    return decryptIl2cppHandle(rax);
}

namespace offsets {
    uintptr_t GameAssembly = 0;

    namespace base_networkable {
        constexpr uintptr_t typeinfo = 0xfd36298;
    }

    namespace main_camera {
        constexpr uintptr_t typeinfo = 0xfd0a5c0;
        constexpr uint32_t static_fields = 0xb8;
        constexpr uint32_t instance = 0x28;
    }
}

int main() {
    std::cout << "=== Rust External Offset Tester ===\n\n";

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

    uintptr_t bn = offsets::GameAssembly + offsets::base_networkable::typeinfo;
    std::cout << "[+] BaseNetworkable: 0x" << bn << "\n";

    uintptr_t static_fields = Read<uintptr_t>(hProc, bn + 0xB8);
    std::cout << "[+] Static Fields: 0x" << static_fields << "\n";

    uintptr_t direct_ent = offsets::GameAssembly + 0x3c830a0;
    int count = Read<int>(hProc, direct_ent + 0x18);
    std::cout << "[+] Entity Count: " << std::dec << count << "\n";

    CloseHandle(hProc);
    std::cout << "\nتست تمام شد.\n";
    system("pause");
    return 0;
}
