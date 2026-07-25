#include <iostream>
#include <Windows.h>

#define REQUEST_MAGIC 0x44524B4E

enum { CMD_READ=1, CMD_WRITE=2, CMD_MODULE_BASE=3, CMD_ALLOC=4, CMD_FREE=5, CMD_PING=99, CMD_VERIFY_PTE=100 };

typedef struct _REQ {
    unsigned int magic, command, protect;
    unsigned __int64 pid, address, buffer, size, result;
    wchar_t module_name[64];
} REQ;

typedef NTSTATUS(NTAPI* NtQCSS_t)(void*,void*,void*);
NtQCSS_t NtQCSS=0;

void init(){ HMODULE h=LoadLibraryA("win32u.dll"); if(h) NtQCSS=(NtQCSS_t)GetProcAddress(h,"NtQueryCompositionSurfaceStatistics"); }
bool call(REQ& r){ if(!NtQCSS) return false; r.magic=REQUEST_MAGIC; return NtQCSS(&r,0,0)==0; }

int main(){
    init();
    if(!NtQCSS){ std::cout<<"Driver not loaded\n"; return 1; }

    // PING
    REQ r={0}; r.command=CMD_PING;
    std::cout<<"[1] PING: "<<(call(r)?"OK":"FAIL")<<" (0x"<<std::hex<<r.result<<std::dec<<")\n";

    // READ
    int orig=0x12345678, read=0;
    r={0}; r.command=CMD_READ; r.pid=GetCurrentProcessId(); r.address=(uintptr_t)&orig; r.buffer=(uintptr_t)&read; r.size=4;
    std::cout<<"[2] READ: "<<(call(r)&&read==orig?"OK":"FAIL")<<"\n";

    // WRITE
    int val=0;
    r={0}; r.command=CMD_WRITE; r.pid=GetCurrentProcessId(); r.address=(uintptr_t)&val; r.buffer=(uintptr_t)&orig; r.size=4;
    call(r);
    std::cout<<"[3] WRITE: "<<(val==0x12345678?"OK":"FAIL")<<"\n";

    // ALLOC
    r={0}; r.command=CMD_ALLOC; r.pid=GetCurrentProcessId(); r.size=0x1000; r.protect=0x40;
    bool ok=call(r)&&r.result>0;
    std::cout<<"[4] ALLOC: "<<(ok?"OK":"FAIL")<<"\n";
    if(ok){ REQ f={0}; f.command=CMD_FREE; f.pid=GetCurrentProcessId(); f.result=r.result; call(f); }

    // MODULE
    r={0}; r.command=CMD_MODULE_BASE; r.pid=GetCurrentProcessId(); wcscpy_s(r.module_name,L"ntdll.dll");
    std::cout<<"[5] MODULE: "<<(call(r)&&r.result>0?"OK":"FAIL")<<"\n";

    // PTE
    unsigned char buf[64]={0};
    r={0}; r.command=CMD_VERIFY_PTE; r.buffer=(uintptr_t)buf;
    if(call(r)){
        int active=*(uint64_t*)(buf+0);
        std::cout<<"[6] PTE: "<<(active?"OK (active)":"OK (fallback)")<<"\n";
    } else std::cout<<"[6] PTE: FAIL\n";

    std::cout<<"\nDone. Press enter..."; std::cin.get();
    return 0;
}
