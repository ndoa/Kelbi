#ifndef MHO_LAUNCHER_MHO_TYPES_H
#define MHO_LAUNCHER_MHO_TYPES_H

typedef void *TQQApiHandle;

typedef int (__cdecl *fn_perform_tpdu_encryption)(
        TQQApiHandle *apiHandle,
        void *inputBuffer,
        signed int inputBufferLength,
        void **outputBuffer,
        signed int *outputBufferLength,
        int allow_unencrypted
);

typedef int (__cdecl *fn_perform_tpdu_decryption)(
        TQQApiHandle *apiHandle,
        char *inputBuffer,
        unsigned int inputBufferLength,
        void **outputBuffer,
        unsigned int *outputBufferLength,
        int is_TPDU_CMD_PLAIN,
        int allow_unencrypted_packets
);

typedef void(__cdecl *fn_crygame_13EC290)();

#endif //MHO_LAUNCHER_MHO_TYPES_H