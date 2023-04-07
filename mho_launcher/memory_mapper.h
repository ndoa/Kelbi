#ifndef MHO_LAUNCHER_MEMORY_MAPPER_H
#define MHO_LAUNCHER_MEMORY_MAPPER_H

#include "util.h"

#include <windows.h>
#include <string>
#include <thread>

void map_memory(std::string p_name, uint8_t *p_data, uint32_t p_data_size) {

    HANDLE mem_handle = CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            NULL,
            PAGE_READWRITE,
            0,
            p_data_size,
            p_name.c_str()
    );
    if (!mem_handle) {
        DWORD err = GetLastError();
        printf("CreateFileMappingA failed (%lu) Msg:%s\n", err, GetLastErrorAsString(err).c_str());
        return;
    }

    void *shared_mem = MapViewOfFile(
            mem_handle,
            FILE_MAP_WRITE,
            0,
            0,
            0
    );
    if (!shared_mem) {
        DWORD err = GetLastError();
        printf("MapViewOfFile failed (%lu) Msg:%s\n", err, GetLastErrorAsString(err).c_str());
        return;
    }
    printf("MapViewOfFile:%s\n", p_name.c_str());

    uint8_t *shared_data = (uint8_t *) shared_mem;
    for (int i = 0; i < p_data_size; i++) {
        shared_data[i] = p_data[i];
    }
}

void map_tcls_sharedmememory() {
    int pid = _getpid();
    std::string name = "TCLS_SHAREDMEMEMORY" + std::to_string(pid);
    uint8_t *data = new uint8_t[12];
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
    map_memory(name, data, 12);
}

void map_mhfclient() {
    uint8_t *data = new uint8_t[12];
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
    map_memory("mhfclient", data, 12);
}

#endif //MHO_LAUNCHER_MEMORY_MAPPER_H
