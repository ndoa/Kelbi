#ifndef MHO_LAUNCHER_UTIL_H
#define MHO_LAUNCHER_UTIL_H

#include <windows.h>
#include <string>

std::wstring get_exe_path() {
    WCHAR exePath[MAX_PATH + 1];
    DWORD pathLen = GetModuleFileNameW(NULL, exePath, MAX_PATH);
    if (pathLen <= 0) {
        return NULL;
    }
    std::wstring path = std::wstring(exePath);
    return path;
}

std::wstring get_exe_dir() {
    std::wstring path = get_exe_path();
    size_t idx = path.find_last_of(L"/\\");
    if (idx == std::wstring::npos)
    {
        return NULL;
    }
    idx++;
    size_t len = path.length();
    if (idx >= len) {
        return NULL;
    }
    std::wstring dir = path.substr(0, idx);
    return dir;
}

std::string GetLastErrorAsString(DWORD error) {
    if (error == 0) {
        return std::string(); //No error message has been recorded
    }
    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR) &messageBuffer,
            0,
            NULL
    );
    std::string message(messageBuffer, size);
    LocalFree(messageBuffer);
    return message;
}

#endif //MHO_LAUNCHER_UTIL_H
