#include "util.h"

#include <windows.h>
#include <iostream>
#include <string>


int main() {
    std::cout << "MHO Launcher" << std::endl;

    std::wstring mho_launcher_lib_path = get_exe_dir() + L"mho_launcher_lib.dll";
    std::string mho_dir = "C:\\Users\\nxspirit\\Downloads\\MHO_FullDirectory_Final\\TencentGame\\Monster Hunter Online\\Bin\\Client\\Bin32\\";
    std::string mho_exe = "MHOClient.exe";
    std::string mho_arg = "-qos_id=food -q -loginqq=1234567890123456789";

    // Create Process
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));

    std::string application_name = mho_dir + mho_exe;
    std::string cmd_args = mho_exe + " " + mho_arg;
    int ret = CreateProcessA(application_name.c_str(),
                             const_cast<char *>(cmd_args.c_str()),
                             NULL,
                             NULL,
                             FALSE,
                             CREATE_SUSPENDED,
                             NULL,
                             NULL,
                             &si,
                             &pi);
    if (ret == FALSE) {
        DWORD err = GetLastError();
        printf("CreateProcess failed (%lu) Msg:%s\n", err, GetLastErrorAsString(err).c_str());
        return 0;
    }

    // Allocate memory in the process
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
        return 0;
    }

    do {
        std::cout << '\n' << "Press a key to resume MHOClient.exe...";
    } while (std::cin.get() != '\n');

    ResumeThread(pi.hThread);

    return 0;
}
