#ifndef MHO_LAUNCHER_MEMORY_MAPPER_H
#define MHO_LAUNCHER_MEMORY_MAPPER_H

#include "util.h"

#include <windows.h>
#include <string>
#include <thread>

void map_tcls_sharedmememory() {
    int pid = _getpid();
    std::string tcls_shared_mem_name = "TCLS_SHAREDMEMEMORY" + std::to_string(pid);
    DWORD tcls_shared_mem_size = 100;
    HANDLE tcls_shared_mem_handle = CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            NULL,
            PAGE_READWRITE,
            0,
            tcls_shared_mem_size,
            tcls_shared_mem_name.c_str()
    );
    if (!tcls_shared_mem_handle) {
        DWORD err = GetLastError();
        printf("CreateFileMappingA failed (%lu) Msg:%s\n", err, GetLastErrorAsString(err).c_str());
        return;
    }

    void *tcls_shared_mem = MapViewOfFile(
            tcls_shared_mem_handle,
            FILE_MAP_WRITE,
            0, 0,
            0
    );
    if (!tcls_shared_mem) {
        DWORD err = GetLastError();
        printf("MapViewOfFile failed (%lu) Msg:%s\n", err, GetLastErrorAsString(err).c_str());
        return;
    }
    printf("MapViewOfFile:%s\n", tcls_shared_mem_name.c_str());

    uint8_t *data = (uint8_t *) tcls_shared_mem;
    data[0] = 0x48;
    data[1] = 0x65;
    data[2] = 0x6C;
    data[3] = 0x6C;
    data[4] = 0x6F;
    data[5] = 0x20;
    data[6] = 0x77;
    data[7] = 0x6F;
    data[8] = 0x72;
    data[9] = 0x6C;
    data[10] = 0x64;
    data[11] = 0x21;
}

#endif //MHO_LAUNCHER_MEMORY_MAPPER_H
