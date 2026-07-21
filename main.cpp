// ========================================================================
// Simple External ESP for Rust
// Build with CMake (Windows, C++17)
// GitHub Workflow included
// ========================================================================

#include <windows.h>
#include <dwmapi.h>
#include <gdiplus.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <memory>
#include <thread>
#include <chrono>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "psapi.lib")

using namespace Gdiplus;

// ----------------------------------------------------------------
// Offsets (combined from your dump and User 4)
// ----------------------------------------------------------------
namespace offsets {
    namespace il2cpp {
        inline constexpr std::uintptr_t gc_handles = 0x100C22A0;
    }
    namespace base_networkable {
        inline constexpr std::uintptr_t typeinfo = 0xFB99108;
        inline constexpr std::uint32_t static_fields = 0xB8;
        inline constexpr std::uint32_t wrapper_class_ptr = 0x8;
        inline constexpr std::uint32_t parent_static_fields = 0x10;
        inline constexpr std::uint32_t hv_offset = 0x18;
        inline constexpr std::uint32_t buffer_list_array = 0x10;
        inline constexpr std::uint32_t count_in_buffer_list = 0x18;
    }
    namespace main_camera {
        inline constexpr std::uintptr_t typeinfo = 0xFC25F88;
        inline constexpr std::uint32_t static_fields = 0xB8;
        inline constexpr std::uint32_t instance = 0x38;
        inline constexpr std::uint32_t viewMatrix = 0x2FC;
        inline constexpr std::uint32_t position = 0x444;
    }
    namespace base_player {
        inline constexpr std::uintptr_t username = 0x7B8;
        inline constexpr std::uintptr_t playerFlags = 0x6B8;
        inline constexpr std::uintptr_t playerModel = 0x520;
        inline constexpr std::uintptr_t playerInventory = 0x728;
        inline constexpr std::uintptr_t playerEyes = 0x3D8;
        inline constexpr std::uintptr_t clActiveItem = 0x568;
        inline constexpr std::uintptr_t team = 0x538;
        inline constexpr std::uint32_t player_eyes_off = 0x3D8; // alias
    }
    namespace base_entity {
        inline constexpr std::uintptr_t model = 0x1A8;
        inline constexpr std::uintptr_t flags = 0x1B0;
    }
    namespace base_combat_entity {
        inline constexpr std::uintptr_t lifeState = 0x298;
        inline constexpr std::uintptr_t health = 0x2A4;
        inline constexpr std::uintptr_t maxHealth = 0x2A8;
    }
    namespace player_model {
        inline constexpr std::uintptr_t position = 0x2F8;
    }
    namespace model {
        inline constexpr std::uintptr_t boneTransforms = 0x50;
    }
    namespace local_player {
        inline constexpr std::uintptr_t slot_klass_rva = 0xFBD6028;
        inline constexpr std::uintptr_t entity_field_off = 0x20;
        inline constexpr std::uint32_t self_static_off = 0x20;
    }
}

// ----------------------------------------------------------------
// Decryption (identical from both)
// ----------------------------------------------------------------
namespace decrypt {
    inline std::uintptr_t base_networkable_0(std::uintptr_t encrypted) {
        std::uintptr_t rax = encrypted;
        std::uint32_t* rdx = reinterpret_cast<std::uint32_t*>(&rax);
        for (int i = 0; i < 2; ++i) {
            std::uint32_t v = *rdx;
            v = (v << 16) | (v >> 16);
            v ^= 0xFE89EFE3u;
            v -= 0x7C71A258u;
            *rdx = v;
            ++rdx;
        }
        return rax;
    }
    inline std::uintptr_t base_networkable_1(std::uintptr_t encrypted) {
        std::uintptr_t rax = encrypted;
        std::uint32_t* rdx = reinterpret_cast<std::uint32_t*>(&rax);
        for (int i = 0; i < 2; ++i) {
            std::uint32_t v = *rdx;
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

// ----------------------------------------------------------------
// Vec2, Vec3, Vec4
// ----------------------------------------------------------------
struct Vec2 { float x, y; };
struct Vec3 { float x, y, z; };
struct Vec4 { float x, y, z, w; };

// ----------------------------------------------------------------
// Memory utilities
// ----------------------------------------------------------------
class Memory {
public:
    HANDLE process = nullptr;
    uintptr_t base = 0;

    bool attach(const wchar_t* procName) {
        DWORD pid = 0;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, procName) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        if (!pid) return false;
        process = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if (!process) return false;
        // get base address
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(process, hMods, sizeof(hMods), &cbNeeded)) {
            base = (uintptr_t)hMods[0];
        }
        return base != 0;
    }

    template<typename T>
    bool read(uintptr_t addr, T& out) const {
        return ReadProcessMemory(process, (LPCVOID)addr, &out, sizeof(T), nullptr);
    }

    // overload for reading into buffer
    bool read(uintptr_t addr, void* buffer, size_t size) const {
        return ReadProcessMemory(process, (LPCVOID)addr, buffer, size, nullptr);
    }

    uintptr_t readPtr(uintptr_t addr) const {
        uintptr_t val = 0;
        read(addr, val);
        return val;
    }
};

// ----------------------------------------------------------------
// GCHandle helper
// ----------------------------------------------------------------
uintptr_t get_gchandle_target(uintptr_t handle, const Memory& mem) {
    uintptr_t handleTable = mem.base + offsets::il2cpp::gc_handles;
    uintptr_t target = 0;
    if (mem.read(handleTable + handle * 8, target))
        return target;
    return 0;
}

// ----------------------------------------------------------------
// World to Screen
// ----------------------------------------------------------------
bool world_to_screen(const Vec3& world, Vec2& screen, const float* viewMatrix, int width, int height) {
    Vec4 clip;
    clip.x = world.x * viewMatrix[0] + world.y * viewMatrix[4] + world.z * viewMatrix[8] + viewMatrix[12];
    clip.y = world.x * viewMatrix[1] + world.y * viewMatrix[5] + world.z * viewMatrix[9] + viewMatrix[13];
    clip.z = world.x * viewMatrix[2] + world.y * viewMatrix[6] + world.z * viewMatrix[10] + viewMatrix[14];
    clip.w = world.x * viewMatrix[3] + world.y * viewMatrix[7] + world.z * viewMatrix[11] + viewMatrix[15];

    if (clip.w < 0.001f) return false;
    Vec3 ndc;
    ndc.x = clip.x / clip.w;
    ndc.y = clip.y / clip.w;
    ndc.z = clip.z / clip.w;
    screen.x = (width / 2.0f) * (ndc.x + 1.0f);
    screen.y = (height / 2.0f) * (1.0f - ndc.y);
    return true;
}

// ----------------------------------------------------------------
// Entity iteration
// ----------------------------------------------------------------
struct Entity {
    uintptr_t obj;
    Vec3 position;
    float health;
    float maxHealth;
    bool isAlive;
    bool isLocal;
    std::wstring name;
};

std::vector<Entity> get_entities(const Memory& mem, uintptr_t localPlayerPtr) {
    std::vector<Entity> entities;
    // get BaseNetworkable static
    uintptr_t bnKlass = mem.base + offsets::base_networkable::typeinfo;
    uintptr_t staticFields;
    if (!mem.read(bnKlass + offsets::base_networkable::static_fields, staticFields)) return {};
    if (!staticFields) return {};

    uintptr_t wrapper;
    if (!mem.read(staticFields + offsets::base_networkable::wrapper_class_ptr, wrapper)) return {};
    if (!wrapper) return {};

    // decrypt client_entities
    uintptr_t encrypted0 = mem.readPtr(wrapper + offsets::base_networkable::hv_offset);
    uintptr_t clientEntities = decrypt::base_networkable_0(encrypted0);
    clientEntities = get_gchandle_target(clientEntities, mem);
    if (!clientEntities) return {};

    // parent static fields
    uintptr_t parentFields;
    if (!mem.read(clientEntities + offsets::base_networkable::parent_static_fields, parentFields)) return {};
    if (!parentFields) return {};

    uintptr_t encrypted1 = mem.readPtr(parentFields + offsets::base_networkable::hv_offset);
    uintptr_t dict = decrypt::base_networkable_1(encrypted1);
    dict = get_gchandle_target(dict, mem);
    if (!dict) return {};

    // buffer list (values)
    uintptr_t bufferList;
    if (!mem.read(dict + offsets::base_networkable::buffer_list_array, bufferList)) return {};
    if (!bufferList) return {};

    uintptr_t array;
    if (!mem.read(bufferList + 0x10, array)) return {};
    array = get_gchandle_target(array, mem);
    if (!array) return {};

    int count;
    if (!mem.read(bufferList + 0x18, count)) return {};
    if (count <= 0) return {};

    // iterate entities
    for (int i = 0; i < count; ++i) {
        uintptr_t ent;
        if (!mem.read(array + 0x20 + i * 8, ent)) continue;
        if (!ent) continue;

        // check if it's a BasePlayer (type check omitted for simplicity, assume all are players)
        // get health
        uintptr_t combat = ent; // BaseCombatEntity is base
        float health, maxHealth;
        mem.read(combat + offsets::base_combat_entity::health, health);
        mem.read(combat + offsets::base_combat_entity::maxHealth, maxHealth);
        if (maxHealth <= 0) continue;
        uint8_t lifeState;
        mem.read(combat + offsets::base_combat_entity::lifeState, lifeState);
        if (lifeState != 0) continue; // 0 = alive

        // get position from PlayerModel
        uintptr_t model = mem.readPtr(ent + offsets::base_player::playerModel);
        if (!model) continue;
        Vec3 pos;
        mem.read(model + offsets::player_model::position, pos);

        // get name
        std::wstring name = L"Unknown";
        uintptr_t namePtr = mem.readPtr(ent + offsets::base_player::username);
        if (namePtr) {
            int len;
            mem.read(namePtr + 0x10, len);
            if (len > 0 && len < 64) {
                wchar_t* buf = new wchar_t[len + 1];
                if (mem.read(namePtr + 0x14, buf, len * 2)) {
                    buf[len] = 0;
                    name = buf;
                }
                delete[] buf;
            }
        }

        entities.push_back({ ent, pos, health, maxHealth, true, false, name });
    }

    // identify local player
    uintptr_t slotKlass = mem.base + offsets::local_player::slot_klass_rva;
    uintptr_t slotStatic;
    mem.read(slotKlass + offsets::base_networkable::static_fields, slotStatic);
    if (slotStatic) {
        uintptr_t localObj = mem.readPtr(slotStatic + offsets::local_player::self_static_off);
        if (localObj) {
            for (auto& e : entities) {
                if (e.obj == localObj) {
                    e.isLocal = true;
                    break;
                }
            }
        }
    }

    return entities;
}

// ----------------------------------------------------------------
// Overlay drawing with GDI+
// ----------------------------------------------------------------
class Overlay {
public:
    HWND hwnd = nullptr;
    int width, height;
    HDC hdc = nullptr;
    Graphics* graphics = nullptr;

    bool create(const wchar_t* title, int w, int h) {
        width = w; height = h;
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = DefWindowProcW;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)CreateSolidBrush(RGB(0,0,0));
        wc.lpszClassName = L"ESPOverlay";
        RegisterClassExW(&wc);

        hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED,
            L"ESPOverlay", title,
            WS_POPUP,
            0, 0, width, height,
            nullptr, nullptr, wc.hInstance, nullptr
        );
        if (!hwnd) return false;

        SetLayeredWindowAttributes(hwnd, RGB(0,0,0), 0, LWA_COLORKEY);
        SetWindowLong(hwnd, GWL_EXSTYLE, GetWindowLong(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);

        // Enable transparency for mouse clicks
        MARGINS margin = { -1, -1, -1, -1 };
        DwmExtendFrameIntoClientArea(hwnd, &margin);

        ShowWindow(hwnd, SW_SHOW);

        hdc = GetDC(hwnd);
        graphics = new Graphics(hdc);
        return true;
    }

    ~Overlay() {
        if (graphics) delete graphics;
        if (hdc) ReleaseDC(hwnd, hdc);
        if (hwnd) DestroyWindow(hwnd);
    }

    void beginDraw() {
        // clear to transparent
        RECT rect;
        GetClientRect(hwnd, &rect);
        HBRUSH brush = CreateSolidBrush(RGB(0,0,0));
        FillRect(hdc, &rect, brush);
        DeleteObject(brush);
        graphics->Clear(Color(0,0,0,0));
    }

    void endDraw() {
        // no swap needed for GDI
    }

    void drawBox(float x, float y, float w, float h, Color color, float thickness = 1.0f) {
        Pen pen(color, thickness);
        graphics->DrawRectangle(&pen, x, y, w, h);
    }

    void drawHealthBar(float x, float y, float w, float h, float healthPercent) {
        // background
        SolidBrush bgBrush(Color(128, 0, 0, 0));
        graphics->FillRectangle(&bgBrush, x, y, w, h);
        // health
        Color healthColor = healthPercent > 0.5f ? Color(0, 255, 0) : 
                            healthPercent > 0.25f ? Color(255, 255, 0) : Color(255, 0, 0);
        SolidBrush healthBrush(healthColor);
        graphics->FillRectangle(&healthBrush, x+1, y+1, (w-2) * healthPercent, h-2);
    }

    void drawText(const std::wstring& text, float x, float y, Color color, float size = 10) {
        Font font(L"Arial", size, FontStyleRegular, UnitPixel);
        SolidBrush brush(color);
        PointF pt(x, y);
        graphics->DrawString(text.c_str(), -1, &font, pt, &brush);
    }
};

// ----------------------------------------------------------------
// Main entry point
// ----------------------------------------------------------------
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    // Initialize GDI+
    ULONG_PTR gdiToken;
    GdiplusStartupInput gdiInput;
    GdiplusStartup(&gdiToken, &gdiInput, nullptr);

    // Attach to Rust
    Memory mem;
    if (!mem.attach(L"RustClient.exe")) {
        MessageBoxW(nullptr, L"RustClient.exe not found", L"Error", MB_OK);
        GdiplusShutdown(gdiToken);
        return 1;
    }

    // Get screen size
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    // Create overlay
    Overlay overlay;
    if (!overlay.create(L"ESP", screenW, screenH)) {
        MessageBoxW(nullptr, L"Failed to create overlay", L"Error", MB_OK);
        GdiplusShutdown(gdiToken);
        return 1;
    }

    // Main loop
    MSG msg;
    while (true) {
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                GdiplusShutdown(gdiToken);
                return 0;
            }
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        // Get camera matrix
        uintptr_t camKlass = mem.base + offsets::main_camera::typeinfo;
        uintptr_t camStatic;
        mem.read(camKlass + offsets::main_camera::static_fields, camStatic);
        uintptr_t camObj = mem.readPtr(camStatic + offsets::main_camera::instance);
        if (!camObj) { Sleep(10); continue; }
        float viewMatrix[16];
        mem.read(camObj + offsets::main_camera::viewMatrix, viewMatrix);

        // Get entities
        auto entities = get_entities(mem, 0);

        // Draw
        overlay.beginDraw();

        for (const auto& ent : entities) {
            if (!ent.isAlive) continue;
            if (ent.isLocal) continue;

            Vec2 screenPos;
            if (!world_to_screen(ent.position, screenPos, viewMatrix, screenW, screenH))
                continue;

            // approximate box height (1.8m) and width (0.6m) - scale with distance
            Vec3 top = { ent.position.x, ent.position.y + 1.8f, ent.position.z };
            Vec2 topScreen;
            if (!world_to_screen(top, topScreen, viewMatrix, screenW, screenH))
                continue;
            float height = std::abs(screenPos.y - topScreen.y);
            float width = height * 0.45f;

            // Draw box
            Color boxColor = ent.isLocal ? Color(0, 255, 255) : Color(255, 0, 0);
            overlay.drawBox(screenPos.x - width/2, topScreen.y, width, height, boxColor);

            // Health bar
            float healthPercent = ent.health / ent.maxHealth;
            overlay.drawHealthBar(screenPos.x - width/2, topScreen.y - 6, width, 4, healthPercent);

            // Name
            overlay.drawText(ent.name, screenPos.x - width/2, topScreen.y - 20, Color(255,255,255), 10);
        }

        overlay.endDraw();

        Sleep(15);
    }

    GdiplusShutdown(gdiToken);
    return 0;
}
