#include "util.h"

#include <windows.h>
#include <iostream>
#include <string>


PROCESS_INFORMATION CreateMhoProcess(
        const std::wstring &mho_dir,
        const std::wstring &mho_exe,
        const std::wstring &mho_arg) {
    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));

    std::wstring application_name = mho_dir + mho_exe;
    std::wstring cmd_args = mho_exe + L" " + mho_arg;
    std::wstring current_dir = get_exe_dir();

    fwprintf(stdout, L"Creating process: \"%s%s %s\"\n", mho_dir.c_str(), mho_exe.c_str(), mho_arg.c_str());

    int ret = CreateProcessW(application_name.c_str(),
                             const_cast<wchar_t *>(cmd_args.c_str()),
                             NULL,
                             NULL,
                             FALSE,
                             CREATE_SUSPENDED,
                             NULL,
                             current_dir.c_str(),
                             &si,
                             &pi);
    if (ret == FALSE) {
        DWORD err = GetLastError();
        printf("CreateProcess failed (%lu) Msg:%s\n", err, GetLastErrorAsString(err).c_str());
        memset(&pi, 0, sizeof(pi));
        return pi;
    }
    fprintf(stdout, "Created Process Success\n");
    return pi;
}

void inject_lunch(PROCESS_INFORMATION pi) {
    // Allocate memory in the process
    std::wstring mho_launcher_lib_path = get_exe_dir() + L"mho_launcher_lib.dll";
    const wchar_t *lib_path = mho_launcher_lib_path.c_str();
    SIZE_T lib_path_size = wcslen(lib_path) * sizeof(wchar_t);
    void *lib_base_address = VirtualAllocEx(
            pi.hProcess,
            NULL,
            lib_path_size,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
    );

    // Write path of mho_launcher_lib.dll into process memory
    WriteProcessMemory(
            pi.hProcess,
            lib_base_address,
            (void *) lib_path,
            lib_path_size,
            NULL
    );

    // Retrieve address for LoadLibraryW function
    LPTHREAD_START_ROUTINE load_library_proc_address = (LPTHREAD_START_ROUTINE) GetProcAddress(
            GetModuleHandleA("Kernel32"),
            "LoadLibraryW"
    );

    // Create a new thread in the process that calls LoadLibraryW with allocated memory that contains the path of mho_launcher_lib.dll as parameter
    HANDLE load_library_thread = CreateRemoteThread(
            pi.hProcess,
            NULL,
            0,
            load_library_proc_address,
            lib_base_address,
            0,
            NULL
    );
    if (load_library_thread == NULL) {
        fprintf(stderr, "load_library_thread == NULL\n");
        return;
    }

    do {
        std::cout << '\n' << "Press a key to resume MHOClient.exe...";
    } while (std::cin.get() != '\n');

    ResumeThread(pi.hThread);
}

int main(int argc, char *argv[]) {

    std::cout << "MHO Launcher" << std::endl;

    std::wstring mho_dir;
    std::wstring mho_exe;
    std::wstring mho_arg;

    if (argc >= 4) {
        mho_dir = s_2_ws(argv[1]);
        mho_exe = s_2_ws(argv[2]);
        mho_arg = s_2_ws(argv[3]);
    } else {
        mho_dir = get_exe_dir();
        mho_exe = L"MHOClient.exe";
        mho_arg = L"-qos_id=food -q -loginqq=1234567890123456789 -nosplash";
    }

    if (true) {
        mho_dir = L"C:\\Users\\nxspirit\\Downloads\\MHO_FullDirectory_Final\\TencentGame\\Monster Hunter Online\\Bin\\Client\\Bin32\\";
        mho_exe = L"MHOClient_latest_dump_SCY_.exe";
        //mho_exe = L"MHOClient.exe";
        mho_arg = L"-qos_id=food -q -loginqq=1234567890123456789 -nosplash";
    }

    PROCESS_INFORMATION pi = CreateMhoProcess(mho_dir, mho_exe, mho_arg);
    inject_lunch(pi);
    return 0;
}
