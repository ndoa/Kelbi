#ifndef MHO_LAUNCHER_UTIL_H
#define MHO_LAUNCHER_UTIL_H

#include <windows.h>
#include <string>
#include <codecvt>

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
    if (idx == std::wstring::npos) {
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

template<typename I>
std::string to_hex(I *bytes, int size, bool stop_at_null) {
    static const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    std::string str;
    for (int i = 0; i < size; ++i) {
        const char ch = bytes[i];
        if (stop_at_null && ch == 0) {
            break;
        }
        str.append(&hex[(ch & 0xF0) >> 4], 1);
        str.append(&hex[ch & 0xF], 1);
        str.append("-");
    }
    return str;
}

template<typename I>
std::string to_ascii(I *bytes, int size, bool stop_at_null) {
    std::string str;
    for (int i = 0; i < size; ++i) {
        const char ch = bytes[i];
        if (ch >= 32 && ch <= 127) {
            str.append(&ch, 1);
        } else {
            if (stop_at_null && ch == 0) {
                break;
            }
            str.append(".");
        }
    }
    return str;
}

template<typename I>
void show(I *bytes, int size, bool stop_at_null) {
    fprintf(stdout, "\n");
    fprintf(stdout, "---------\n");
    fprintf(stdout, "Size: %d\n", size);
    fprintf(stdout, "%s\n", to_ascii(bytes, size, stop_at_null).c_str());
    fprintf(stdout, "%s\n", to_hex(bytes, size, stop_at_null).c_str());
    fprintf(stdout, "---------\n");
    fprintf(stdout, "\n");
}

std::wstring s_2_ws(const std::string& str)
{
    using convert_typeX = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;

    return converterX.from_bytes(str);
}

std::string ws_2_s(const std::wstring& wstr)
{
    using convert_typeX = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;

    return converterX.to_bytes(wstr);
}

#endif //MHO_LAUNCHER_UTIL_H
