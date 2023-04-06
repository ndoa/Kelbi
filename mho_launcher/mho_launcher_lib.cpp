#include "mho_launcher_lib.h"
#include "util.h"
#include "memory_mapper.h"
#include "memory.h"

#include <windows.h>
#include <fstream>
#include <thread>
#include <string>

std::thread *run_thread;
HMODULE crygame_handle;
DWORD crygame_addr;
HMODULE mho_client_handle;
DWORD mho_client_addr;


DWORD rva_hook_svr_call_rva = 0x11A8CAE;
DWORD rva_hook_svr_call_ret_rva = 0x11A8CB3;
DWORD rva_hook_svr_call_fn_rva = 0xEBF60;
DWORD abs_a = 0;
DWORD abs_b = 0;

void svr_addr() {
    fprintf(stdout, "svr_addr\n");

    const char *url = "127.0.0.1:8142";
    DWORD url_addr = mho_client_addr + 0x15780C8; // RVA
    fprintf(stdout, "url_addr: 0x%08X \n", url_addr);
    WriteMemory((LPVOID) url_addr, url, strlen(url));
}
// 15780C8
__declspec(naked) void hook_svr_addr() {
    __asm {
        // hook
            pushfd
            pushad
            call svr_addr
        // add esp, 4
            popad
            popfd
        // end hook
            call[abs_a]
            jmp abs_b
    }
}


void run() {
    fprintf(stdout, "run\n");

    crygame_handle = nullptr;
    crygame_addr = 0;

    if (TRUE == AllocConsole()) {
        FILE *nfp[3];
        freopen_s(nfp + 0, "CONOUT$", "rb", stdin);
        freopen_s(nfp + 1, "CONOUT$", "wb", stdout);
        freopen_s(nfp + 2, "CONOUT$", "wb", stderr);
        std::ios::sync_with_stdio();
    }
    mho_client_handle = GetModuleHandleA("mhoclient.exe");
    mho_client_addr = (DWORD) mho_client_handle;
    fprintf(stdout, "mho_client_handle: %p \n", mho_client_handle);

    while (!crygame_handle) {
        crygame_handle = GetModuleHandleA("crygame");
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    crygame_addr = (DWORD) crygame_handle;
    fprintf(stdout, "crygame_handle: %p \n", crygame_handle);

    // perhaps make dynamic
    // DWORD tmp = 0;
    // ReadMemory((LPVOID)(crygame_addr + rva_hook_svr_call_rva + 1), &tmp, 4);
    // rva_hook_svr_call_fn_rva = (tmp & 0x000000ff) << 24 | (tmp & 0x0000ff00) << 8 | (tmp & 0x00ff0000) >> 8 | (tmp & 0xff000000) >> 24;
    // rva_hook_svr_call_fn_rva = tmp;
    // TODO need to calculate

    fprintf(stdout, "rva_hook_svr_call_fn_rva: 0x%08X\n", rva_hook_svr_call_fn_rva);
    hook_jmp(crygame_addr, rva_hook_svr_call_rva, &hook_svr_addr);

    abs_a = crygame_addr + rva_hook_svr_call_fn_rva;
    abs_b = crygame_addr + rva_hook_svr_call_ret_rva;

}


BOOL WINAPI DllMain(HINSTANCE h_instance, DWORD fdw_reason, LPVOID lpv_reserved) {
    switch (fdw_reason) {
        case DLL_PROCESS_ATTACH:
            run_thread = new std::thread(run);
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}