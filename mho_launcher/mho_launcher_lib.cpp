#include "mho_launcher_lib.h"
#include "memory.h"
#include "mho_types.h"
#include "util.h"

#include <windows.h>
#include <fstream>
#include <thread>
#include <string>

DWORD server_url_address = 0;

fn_perform_tpdu_encryption org_perform_tpdu_encryption = nullptr;
fn_perform_tpdu_decryption org_perform_tpdu_decryption = nullptr;
fn_crygame_13EC290 org_fn_crygame_13EC290 = nullptr;
fn_aes_key_expansion org_aes_key_expansion = nullptr;
fn_log_dll org_log_dll = nullptr;
fn_log_format org_log_format = nullptr;

int __cdecl perform_tpdu_decryption(
        TQQApiHandle *apiHandle,
        char *inputBuffer,
        unsigned int inputBufferLength,
        void **outputBuffer,
        unsigned int *outputBufferLength,
        int is_TPDU_CMD_PLAIN,
        int allow_unencrypted_packets) {
    fprintf(stdout, "DECRYPT - START\n");

    uint8_t *encryption_mode_addr = (uint8_t *) apiHandle + 0x84;
    // *encryption_mode_addr = 0;
    // allow_unencrypted_packets = 1;

    fprintf(stdout, "encryption_mode_addr: %d\n", *encryption_mode_addr);
    show((uint8_t *) inputBuffer, inputBufferLength, false);

    int ret = org_perform_tpdu_decryption(apiHandle,
                                          inputBuffer,
                                          inputBufferLength,
                                          outputBuffer,
                                          outputBufferLength,
                                          is_TPDU_CMD_PLAIN,
                                          allow_unencrypted_packets
    );

    void *out = *outputBuffer;
    signed int outlen = *outputBufferLength;
    show((uint8_t *) out, outlen, false);

    fprintf(stdout, "DECRYPT - END\n");

    return ret;
}

int __cdecl perform_tpdu_encryption(
        TQQApiHandle *apiHandle,
        void *inputBuffer,
        signed int inputBufferLength,
        void **outputBuffer,
        signed int *outputBufferLength,
        int allow_unencrypted
) {
    fprintf(stdout, "ENCRYPT - START\n");

    show((uint8_t *) inputBuffer, inputBufferLength, false);


    uint8_t *encryption_mode_addr = (uint8_t *) apiHandle + 0x84;
    //*encryption_mode_addr = 0;
    //allow_unencrypted = 1;

    fprintf(stdout, "encryption_mode_addr: %d\n", *encryption_mode_addr);


    int ret = org_perform_tpdu_encryption(apiHandle,
                                          inputBuffer,
                                          inputBufferLength,
                                          outputBuffer,
                                          outputBufferLength,
                                          allow_unencrypted
    );

    void *out = *outputBuffer;
    signed int outlen = *outputBufferLength;
    show((uint8_t *) out, outlen, false);

    fprintf(stdout, "ENCRYPT - END\n");

    return ret;
}


int __cdecl aes_key_expansion(
        void *key,
        unsigned int key_len_bits,
        void *expanded_key
) {
    fprintf(stdout, "aes_key_expansion (bits:%d)\n", key_len_bits);

    unsigned int key_len_bytes = key_len_bits / 8;
    show((uint8_t *) key, key_len_bytes, false);

    int ret = org_aes_key_expansion(key, key_len_bits, expanded_key);
    if (key_len_bits == 128) {
        unsigned int expanded_key_len_bytes = 176;
        show((uint8_t *) expanded_key, expanded_key_len_bytes, false);
    }
    return ret;
}

void __cdecl log_dll(
        int p_unk,
        size_t p_buffer_size,
        wchar_t *p_str,
        void *p_str_fmt_args
) {
    size_t w_str_size = std::wcslen(p_str);
    if (w_str_size <= 0) {
        //fprintf(stdout, "protocalhandler::w_str_size:%d (p_unk:%d, p_buffer_size:%d p_str:%p, p_str_fmt_args:%p)\n",
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
    fprintf(stdout, "protocalhandler::log:%s\n", log_text.c_str());
}

/**
 * This is the first function that was easy to hook around the server connection routine.
 * its only purpose is to alter memory at the time, right before it is used.
 */
void __cdecl crygame_13EC290() {

    fprintf(stdout, "crygame_13EC290\n");

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
    fprintf(stdout, "wait for crygame... \n");
    while (!crygame_handle) {
        crygame_handle = GetModuleHandleA("crygame");
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    crygame_addr = (DWORD) crygame_handle;
    fprintf(stdout, "got crygame_handle: %p \n", crygame_handle);

    // assign original function calls
    org_fn_crygame_13EC290 = (fn_crygame_13EC290) (crygame_addr + 0x13EC290);

    // hook existing ones
    hook_call(crygame_addr, 0x11A8BF4, &crygame_13EC290);
}

/**
 * waits until protocalhandler.dll is loaded and performs and applies patches to its memory
 */
void run_protocal_handler() {
    HMODULE protocal_handler_handle = nullptr;

    fprintf(stdout, "wait for protocalhandler... \n");
    while (!protocal_handler_handle) {
        protocal_handler_handle = GetModuleHandleA("protocalhandler");
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    DWORD protocal_handler_addr = (DWORD) protocal_handler_handle;
    fprintf(stdout, "got protocal_handler_handle: %p \n", protocal_handler_handle);

    // assign original function calls
    org_perform_tpdu_decryption = (fn_perform_tpdu_decryption) (protocal_handler_addr + 0x73DC0);
    org_perform_tpdu_encryption = (fn_perform_tpdu_encryption) (protocal_handler_addr + 0x73bb0);
    org_aes_key_expansion = (fn_aes_key_expansion) (protocal_handler_addr + 0x888E0);
    org_log_dll = (fn_log_dll) (protocal_handler_addr + 0x1703);
    org_log_format = (fn_log_format) (protocal_handler_addr + 0x1A96);

    // hook existing ones
    hook_call(protocal_handler_addr, 0x36002, &perform_tpdu_decryption);
    hook_call(protocal_handler_addr, 0x360FE, &perform_tpdu_decryption);
    hook_call(protocal_handler_addr, 0x74AD3, &perform_tpdu_decryption);
    hook_call(protocal_handler_addr, 0x74F7F, &perform_tpdu_decryption);
    hook_call(protocal_handler_addr, 0x75336, &perform_tpdu_decryption);
    hook_call(protocal_handler_addr, 0x75508, &perform_tpdu_decryption);
    hook_call(protocal_handler_addr, 0x75651, &perform_tpdu_decryption);

    hook_call(protocal_handler_addr, 0x36FAB, &perform_tpdu_encryption);
    hook_call(protocal_handler_addr, 0x742A2, &perform_tpdu_encryption);
    hook_call(protocal_handler_addr, 0x74661, &perform_tpdu_encryption);
    hook_call(protocal_handler_addr, 0x75B70, &perform_tpdu_encryption);
    hook_call(protocal_handler_addr, 0x76069, &perform_tpdu_encryption);

    hook_call(protocal_handler_addr, 0x88CB0, &aes_key_expansion);
    hook_call(protocal_handler_addr, 0x8B1E1, &aes_key_expansion);
    hook_call(protocal_handler_addr, 0x8B50B, &aes_key_expansion);

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

void run() {
    fprintf(stdout, "run\n");

    // open console
    if (TRUE == AllocConsole()) {
        FILE *nfp[3];
        freopen_s(nfp + 0, "CONOUT$", "rb", stdin);
        freopen_s(nfp + 1, "CONOUT$", "wb", stdout);
        freopen_s(nfp + 2, "CONOUT$", "wb", stderr);
        std::ios::sync_with_stdio();
    }

    // get base addr
    HMODULE mho_client_handle = GetModuleHandleA("mhoclient.exe");
    DWORD mho_client_addr = (DWORD) mho_client_handle;
    fprintf(stdout, "mho_client_handle: %p \n", mho_client_handle);

    // assign variables depending on mhoclient base
    server_url_address = mho_client_addr + 0x15780C8; // RVA
    fprintf(stdout, "server_url_address: 0x%08X \n", server_url_address);

    // kickoff workers
    std::thread *run_crygame_thread = new std::thread(run_crygame);
    std::thread *run_protocal_thread = new std::thread(run_protocal_handler);
}

BOOL WINAPI DllMain(HINSTANCE h_instance, DWORD fdw_reason, LPVOID lpv_reserved) {
    switch (fdw_reason) {
        case DLL_PROCESS_ATTACH:
            new std::thread(run);
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