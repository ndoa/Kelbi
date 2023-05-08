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

std::string to_hex(uint8_t *bytes, int size) {
    static const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    std::string str;
    for (int i = 0; i < size; ++i) {
        const char ch = bytes[i];
        str.append(&hex[(ch & 0xF0) >> 4], 1);
        str.append(&hex[ch & 0xF], 1);
        str.append(" ");
    }
    return str;
}

std::string to_ascii(uint8_t *bytes, int size) {
    std::string str;
    for (int i = 0; i < size; ++i) {
        const char ch = bytes[i];
        if (ch >= 32 && ch <= 127) {
            str.append(&ch, 1);
        } else {
            str.append(".");
        }
    }
    return str;
}

void show(uint8_t *bytes, int size) {
    fprintf(stdout, "\n");
    fprintf(stdout, "---------\n");
    fprintf(stdout, "Ptr:%p Size:%d\n", bytes, size);

    int chunk_size = 16;
    int chunks = size / chunk_size;
    int rem = size % chunk_size;

    int offset = 0;
    for (int i = 0; i < chunks; i++) {
        offset = i * chunk_size;
        fprintf(stdout, "0x%08X | %s| %s\n",
                offset,
                to_hex(&bytes[offset], chunk_size).c_str(),
                to_ascii(&bytes[offset], chunk_size).c_str()
        );
    }
    if (rem > 0) {
        offset = chunks * chunk_size;
        fprintf(stdout, "0x%08X | %s| %s\n",
                offset,
                to_hex(&bytes[offset], rem).c_str(),
                to_ascii(&bytes[offset], rem).c_str()
        );
    }

    fprintf(stdout, "---------\n");
    fprintf(stdout, "\n");
}

std::wstring s_2_ws(const std::string &str) {
    using convert_typeX = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;

    return converterX.from_bytes(str);
}

std::string ws_2_s(const std::wstring &wstr) {
    using convert_typeX = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;

    return converterX.to_bytes(wstr);
}

#endif //MHO_LAUNCHER_UTIL_H
