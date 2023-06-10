#include "mho_launcher_lib.h"
#include "memory.h"
#include "mho_types.h"
#include "util.h"

#include "blockingconcurrentqueue.h"

#include <windows.h>
#include <fstream>
#include <thread>
#include <string>
#include <iostream>
#include <Tchar.h>

DWORD server_url_address = 0;

fn_crygame_13EC290 org_fn_crygame_13EC290 = nullptr;
fn_log_dll org_log_dll = nullptr;
fn_log_format org_log_format = nullptr;

/// Event System - START
// Had some issues with printing console logs on game threads.
// Now only constructing the logs on game thread but not printing.
// Isolating the printing to my own thread via a queue.
struct Event {
    std::string msg;
};

std::atomic<bool> is_running;
moodycamel::BlockingConcurrentQueue<Event> *events = nullptr;

void run_events() {
    Event event{};
    while (is_running) {
        if (!events->wait_dequeue_timed(event, 500 * 1000)) {
            // check every 500ms if we are still running
            continue;
        }
        std::cout << event.msg;
    }
}

void log(const char *fmt, ...) {
    va_list ap;
            va_start (ap, fmt);
    std::string buf = vformat(fmt, ap);
            va_end (ap);
    events->enqueue({buf});
}

/// Event System - END

void __cdecl log_dll(
        int p_unk,
        size_t p_buffer_size,
        wchar_t *p_str,
        void *p_str_fmt_args
) {
    // call original, just in case we find a switch that prints to file or want to observe behaviour related.
    org_log_dll(p_unk, p_buffer_size, p_str, p_str_fmt_args);

    size_t w_str_size = std::wcslen(p_str);
    if (w_str_size <= 0) {
        // TODO I am not interested if there is no string content in the buffer,
        // TODO however it gets called some times without any content.
        //fprintf("protocalhandler::w_str_size:%d (p_unk:%d, p_buffer_size:%d p_str:%p, p_str_fmt_args:%p)\n",
        //        w_str_size, p_unk, p_buffer_size, p_str, p_str_fmt_args
        //);
        return;
    }
    // `p_buffer_size` should be appropriate sized to hold formatted string
    size_t out_buffer_size = p_buffer_size + w_str_size + 1024; // just to be sure
    wchar_t *w_str_fmt = new wchar_t[out_buffer_size];

    // this is a function the game uses to apply formatting, it als adds process and thread id to the string
    org_log_format(w_str_fmt, out_buffer_size, p_str, p_str_fmt_args);
    size_t w_str_fmt_size = std::wcslen(w_str_fmt);
    std::wstring w_log_text(w_str_fmt, w_str_fmt_size);

    // converting wstring to string, to be able to print it to console
    std::string log_text = ws_2_s(w_log_text);
    delete[] w_str_fmt;
    log("protocalhandler::log:%s\n", log_text.c_str());
}

/**
 * This is the first function that was easy to hook around the server connection routine.
 * its only purpose is to alter memory at the time, right before it is used.
 */
void __cdecl crygame_13F3640() {

    log("crygame_13F3640\n");
    const char *url = "127.0.0.1:8142";
    WriteMemory((LPVOID) server_url_address, url, strlen(url));
    org_fn_crygame_13EC290();
}

/**
 * waits until crygame.dll is loaded and performs and applies patches to its memory
 */
void run_crygame() {
    HMODULE crygame_handle = nullptr;
    DWORD crygame_addr = 0;
    log("wait for crygame... \n");
    while (!crygame_handle) {
        crygame_handle = GetModuleHandleA("crygame");
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    crygame_addr = (DWORD) crygame_handle;
    log("got crygame_handle: %p \n", crygame_handle);

    // assign original function calls
    org_fn_crygame_13EC290 = (fn_crygame_13EC290) (crygame_addr + 0x13F3640);

    // hook existing ones
    hook_call(crygame_addr, 0x11AED64, &crygame_13F3640);
}

/**
 * waits until protocalhandler.dll is loaded and performs and applies patches to its memory
 */
void run_protocal_handler() {
    HMODULE protocal_handler_handle = nullptr;

    log("wait for protocalhandler... \n");
    while (!protocal_handler_handle) {
        protocal_handler_handle = GetModuleHandleA("protocalhandler");
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    DWORD protocal_handler_addr = (DWORD) protocal_handler_handle;
    log("got protocal_handler_handle: %p \n", protocal_handler_handle);

    // assign original function calls
    org_log_dll = (fn_log_dll) (protocal_handler_addr + 0x1703);
    org_log_format = (fn_log_format) (protocal_handler_addr + 0x1A96);

    hook_call(protocal_handler_addr, 0x39171, &log_dll);
    hook_call(protocal_handler_addr, 0x39141, &log_dll);
    hook_call(protocal_handler_addr, 0x390B1, &log_dll);
    hook_call(protocal_handler_addr, 0x390E1, &log_dll);
    hook_call(protocal_handler_addr, 0x3910E, &log_dll);
    hook_call(protocal_handler_addr, 0x391A1, &log_dll);
    hook_call(protocal_handler_addr, 0x38F2E, &log_dll);
    hook_call(protocal_handler_addr, 0x38F61, &log_dll);
    hook_call(protocal_handler_addr, 0x38F04, &log_dll);
    hook_call(protocal_handler_addr, 0x123F1, &log_dll);
    hook_call(protocal_handler_addr, 0x12391, &log_dll);
    hook_call(protocal_handler_addr, 0x123C1, &log_dll);
    hook_call(protocal_handler_addr, 0x1CC61, &log_dll);
    hook_call(protocal_handler_addr, 0x38FBE, &log_dll);
    hook_call(protocal_handler_addr, 0x39021, &log_dll);
    hook_call(protocal_handler_addr, 0x38F91, &log_dll);
    hook_call(protocal_handler_addr, 0x3907E, &log_dll);
    hook_call(protocal_handler_addr, 0x208D1, &log_dll);
    hook_call(protocal_handler_addr, 0x39051, &log_dll);
    hook_call(protocal_handler_addr, 0x38FF1, &log_dll);
    hook_call(protocal_handler_addr, 0x1CC91, &log_dll);
    hook_call(protocal_handler_addr, 0xC921, &log_dll);
    hook_call(protocal_handler_addr, 0xC551, &log_dll);
    hook_call(protocal_handler_addr, 0x83F1, &log_dll);
    hook_call(protocal_handler_addr, 0xA831, &log_dll);
    hook_call(protocal_handler_addr, 0x83C1, &log_dll);
}

void CreateConsole() {
    if (!AllocConsole()) {
        return;
    }

    // std::cout, std::clog, std::cerr, std::cin
    FILE *fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    freopen_s(&fDummy, "CONIN$", "r", stdin);
    std::cout.clear();
    std::clog.clear();
    std::cerr.clear();
    std::cin.clear();

    // std::wcout, std::wclog, std::wcerr, std::wcin
    HANDLE hConOut = CreateFile(_T("CONOUT$"),
                                GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL
    );
    HANDLE hConIn = CreateFile(_T("CONIN$"),
                               GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL
    );
    SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
    SetStdHandle(STD_ERROR_HANDLE, hConOut);
    SetStdHandle(STD_INPUT_HANDLE, hConIn);
    std::wcout.clear();
    std::wclog.clear();
    std::wcerr.clear();
    std::wcin.clear();

    std::ios::sync_with_stdio();
}

void client_log(int do_log, char *near_log_ptr) {
    if (do_log == 0) {
        return;
    }
    char *log_ptr = near_log_ptr + 0x20;
    int log_len = 0;
    while (true) {
        if (log_ptr[log_len] == 0) {
            break;
        }
        log_len++;
    }
    if (log_len <= 0) {
        return;
    }
    std::string log_text = std::string(log_ptr, log_len);
    log("client_log: %s \n", log_text.c_str());
}

// @formatter:off
_declspec(naked)
void asm_client_log() {
    _asm
    {
        pushad
        mov eax, esp
        push eax
        push ecx
        call client_log
        add esp, 8
        popad
        // recover stolen bytes
        mov esp, ebp
        pop ebp
        ret 0xC
    }
}
// @formatter:on

// TODO -> https://github.com/ndoa/Kelbi/blob/feature/playing-around/mho_launcher/mho_launcher_lib.cpp

void run() {
    new std::thread(run_events);
    log("run\n");

    std::wstring exe_name_w = get_exe_name();
    std::string exe_name = ws_2_s(exe_name_w);
    log("exe_name: %s \n", exe_name.c_str());

    // get base addr
    HMODULE mho_client_handle = GetModuleHandleW(exe_name_w.c_str());
    DWORD mho_client_addr = (DWORD) mho_client_handle;
    log("mho_client_handle: %p \n", mho_client_handle);

    // assign variables depending on mhoclient base
    server_url_address = mho_client_addr + 0x157AAA0; // RVA
    log("server_url_address: 0x%08X \n", server_url_address);

    // hook logging fn
    patch_jmp(mho_client_addr, 0x3E0F06, &asm_client_log);
    // patch log exit jmp
    patch_nop(mho_client_addr, 0x3E0C82, 6);

    new std::thread(run_crygame);
    new std::thread(run_protocal_handler);
}

BOOL WINAPI DllMain(HINSTANCE h_instance, DWORD fdw_reason, LPVOID lpv_reserved) {
    switch (fdw_reason) {
        case DLL_PROCESS_ATTACH:
            events = new moodycamel::BlockingConcurrentQueue<Event>(100);
            is_running = true;
            CreateConsole();
            new std::thread(run);
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            is_running = false;
            break;
    }
    return TRUE;
}