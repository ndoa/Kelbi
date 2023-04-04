from construct import *

TPDU_CMD = Enum(Byte,
                TPDU_CMD_NONE=0,
                TPDU_CMD_CHGSKEY=1,
                TPDU_CMD_QUEINFO=2,
                TPDU_CMD_AUTH=3,
                TPDU_CMD_IDENT=4,
                TPDU_CMD_PLAIN=5,
                TPDU_CMD_RELAY=6,
                TPDU_CMD_STOP=7,
                TPDU_CMD_SYN=8,
                TPDU_CMD_SYNACK=9,
                TPDU_CMD_MBA_QUERYRSP=10,
                TPDU_CMD_MBA_VERIFYREQ=11,
                TPDU_CMD_MBA_VERIFYRSP=12,
                TPDU_CMD_CLOSE=13,
                TPDU_CMD_CLIENT_ADDR=210,
                )

TPDUBase = Struct(
    "Magic" / Default(Int8ul, 0),
    "Version" / Default(Int8ul, 0),
    "Cmd" / TPDU_CMD,
    "EncHeadLen" / Default(Int8ul, 0),
    "HeadLen" / Default(Int32ub, 0),  # This is EXPLICITLY endian swapped.
    "BodyLen" / Default(Int32ul, 0),
)

TQQAuthInfo = Struct(
    "Uin" / Int32ub,
    "SignLen" / Int8ub,
    "SignData" / Array(this.SignLength, Int8ub),
    "Sign2Len" / Int8ub,
    "Sign2Data" / Array(this.SignLength, Int8ub)
)

TQQUnifiedAuthInfo = Struct(
    "Uin" / Int32ub,
    "Len" / Int8ub,
    "SigInfo" / Bytes(this.Len),  # Max 256
)

# Metalib union
# TPDUExtAuthData = Switch(this.AuthType, {
#     1: TQQAuthInfo,  # "AuthQQV1",
#     2: TQQAuthInfo,  # "AuthQQV2",
#     3: TQQUnifiedAuthInfo,  # "AuthQQUnified",
# })


def TPDUExtAuthData(selector):
    return Switch(selector, {
        1: TQQAuthInfo,  # "AuthQQV1",
        2: TQQAuthInfo,  # "AuthQQV2",
        3: TQQUnifiedAuthInfo,  # "AuthQQUnified",
    })


TPDUExtAuthInfo = Struct(
    "EncMethod" / Int32ub,
    "ServiceID" / Int32ub,
    "AuthType" / Int32ub,
    #"AuthData" / TPDUExtAuthData,
    "AuthData" / TPDUExtAuthData(selector=this.AuthType)
)

TPDUHeadExtMap = {
    TPDU_CMD.TPDU_CMD_AUTH: TPDUExtAuthInfo,
}
