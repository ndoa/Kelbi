import io
import socket
import struct
import threading
from Packets import *
from hexdump import hexdump
from Crypto.Cipher import AES #pip install pycryptodome


def fixed_recv(conn, n):
    b = bytearray()
    while len(b) != n:
        b.extend(conn.recv(n - len(b)))

    return b


class GameClient():
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.handler_table = {
            TPDU_CMD.TPDU_CMD_AUTH: self.handle_tpdu_auth,
            TPDU_CMD.TPDU_CMD_SYNACK: self.handle_tpdu_synack,
            TPDU_CMD.TPDU_CMD_CLOSE: self.handle_tpdu_close,
            TPDU_CMD.TPDU_CMD_NONE: self.handle_tpdu_cmd_none,
        }
        self.enc_method = TCONN_SEC_ENC.TCONN_SEC_NONE

    def handle_tpdu_auth(self, packet):
        # Send the TPDU_CMD_SYN packet to the client.

        self.enc_method = packet.Head.Ext.EncMethod
        print("enc_method:", self.enc_method)
        encrypt_syn_info = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        if self.enc_method == TCONN_SEC_ENC.TCONN_SEC_AES.name:
            # init aes128 cipher
            key = b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
            iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)

            # offset + length - 6 == tsf4g{X} == 0x74, 0x73, 0x66, 0x34, 0x67, {X}
            # X = len(tsf4g{x}) = 6
            encrypt_syn_info = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x74, 0x73, 0x66, 0x34, 0x67, 16])
            encrypt_syn_info = cipher.encrypt(encrypt_syn_info)
            print("s->c:encrypt_syn_info:")
            hexdump(encrypt_syn_info)

        ext = TPDUExtSyn.build(dict(
            Len=len(encrypt_syn_info),
            EncryptSynInfo=encrypt_syn_info,
        ))

        send_tpdu_frame(self.conn, TPDU_CMD.TPDU_CMD_SYN, ext, bytes([]))

    def handle_tpdu_synack(self, packet):
        # Got synack, now send TPDU_CMD_IDENT.
        # inner_ext = TPDUIdentInfo.build(dict(
        #     Pos=0,
        #     Ident=0
        # ))

        if self.enc_method == TCONN_SEC_ENC.TCONN_SEC_AES.name:
            key = b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
            iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            encrypt_syn_info = packet.Head.Ext.EncryptSynInfo
            print("c->s:encrypt_syn_info:")
            hexdump(encrypt_syn_info)
            syn_info = cipher.decrypt(encrypt_syn_info)
            print("c->s:syn_info:")
            hexdump(syn_info)

            key = b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
            iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            encrypt_body = packet.Body
            print("c->s:encrypt_body:")
            hexdump(encrypt_body)
            body = cipher.decrypt(encrypt_body)
            print("c->s:body:")
            hexdump(body)

        inner_ext = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        if self.enc_method == TCONN_SEC_ENC.TCONN_SEC_AES.name:
            key = b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
            iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            inner_ext = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                               17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0x74, 0x73, 0x66, 0x34, 0x67, 12])
            inner_ext = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x74, 0x73, 0x66, 0x34, 0x67, 12])
            inner_ext = cipher.encrypt(inner_ext)
            print("inner_ext:")
            hexdump(inner_ext)

        ext = TPDUExtIdent.build(dict(
            Len=len(inner_ext),
            EncryptIdent=inner_ext,
        ))

        send_tpdu_frame(self.conn, TPDU_CMD.TPDU_CMD_IDENT, ext, bytes([]))

        # Send Queue info
        # ext = TPDUExtQueInfo.build(dict(
        #     Pos=30,
        #     Max=30,
        #     WaitTime=60,
        # ))

        # send_tpdu_frame(self.conn, TPDU_CMD.TPDU_CMD_QUEINFO, ext, bytes([]))

        # ext = TPDUExtMiBao.build(dict(
        #     Len=4096,
        #     MiBaoBuffer=bytes(bytearray(4096))
        # ))
        # send_tpdu_frame(self.conn, TPDU_CMD.TPDU_CMD_MBA_QUERYRSP, ext, bytes([]))

        encrypt_s_key =bytes(bytearray(128))

        if self.enc_method == TCONN_SEC_ENC.TCONN_SEC_AES.name:
            key = b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
            iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            encrypt_s_key = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                   17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
                                   33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
                                   49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
                                   65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
                                   81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96,
                                   97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
                                   113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128,
                                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x74, 0x73, 0x66, 0x34, 0x67, 16])
            encrypt_s_key = cipher.encrypt(encrypt_s_key)
            print("encrypt_s_key:")
            hexdump(encrypt_s_key)

        ext = TPDUExtChgSkey.build(dict(
            Type=0,
            Len=len(encrypt_s_key),
            EncryptSkey=encrypt_s_key
        ))

        send_tpdu_frame(self.conn, TPDU_CMD.TPDU_CMD_CHGSKEY, ext, bytes([]))

        pass

    def handle_tpdu_close(self, packet):
        print("Client closed connection!")

    # TPDU_CMD_NONE packets are used as the container
    # for csproto packets.
    def handle_tpdu_cmd_none(self, packet):
        hexdump(packet.Body)
        enc_header_bytes = packet.Body[:4]
        csproto_packet_bytes = packet.Body[4:]

        csproto_packet = CSPkg.parse(csproto_packet_bytes)
        print("Got CSPkg:", csproto_packet)

        if int(csproto_packet.Head.CmdID) == CS_CMD_ID.CS_CMD_CHECK_VERSION_REQ:
            out = io.BytesIO()
            body = CSCheckVersionRsp.build(dict(
                ErrNo=0,
                MajorVerNo=csproto_packet.Body.MajorVerNo + 1,
                MinorVerNo=csproto_packet.Body.MinorVerNo,
                RevisVerNo=csproto_packet.Body.RevisVerNo,
                BuildVerNo=csproto_packet.Body.BuildVerNo,
                Feature=csproto_packet.Body.Feature,
            ))

            head = CSPkgHead.build(dict(
                CmdID=CS_CMD_ID.CS_CMD_CHECK_VERSION_RSP,
                HeadLen=16,
                BodyLen=len(body),
                SeqID=1,
                NoUse=0,
            ))
            out.write(head)
            out.write(body)

            send_tpdu_frame(self.conn, TPDU_CMD.TPDU_CMD_NONE, bytes([]), out.getvalue())

            pass

    def _read_tpdu_packet_frame(self):
        # Read the TPDUBase (packet header)
        # print("Reading TPDUBase header")
        baseSize = 12
        header_bytes = fixed_recv(self.conn, baseSize)
        # hexdump(header_bytes)

        # Temporarily parse the header to get the size of the header ext and body.
        header = TPDUBase.parse(header_bytes)
        # print(header)

        # assert(header.EncHeadLen == 0)

        header_ext_bytes = fixed_recv(self.conn, header.HeadLen - baseSize)
        body_bytes = fixed_recv(self.conn, header.BodyLen)

        full_frame_bytes = io.BytesIO()
        full_frame_bytes.write(header_bytes)
        full_frame_bytes.write(header_ext_bytes)
        full_frame_bytes.write(body_bytes)
        full_frame_bytes = full_frame_bytes.getvalue()
        # hexdump(full_frame_bytes)

        frame = TPDUFrame.parse(full_frame_bytes)
        return frame

    def HandlePacketsQQMode(self):
        while True:
            # Read one packet frame off the stream.
            frame = self._read_tpdu_packet_frame()
            print("\nC->S:")
            print(frame)

            # Call our handler (if one exists)
            cmd = int(frame.Head.Base.Cmd)
            if cmd in self.handler_table:
                self.handler_table[cmd](frame)
            else:
                print("Missing handler for TPDU packet: {}".format(
                    frame.Head.Base.Cmd))

    # def HandlePacketsTDRMode(self):
    #     while True:
    #         self.conn.send(bytes([0x05, 0x08, 0x00, 0x10, 0x00, 0x00, 0x00, 0x3F,
    #                        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))

    #         data = self.conn.recv(1024)
    #         hexdump(data)
    #         self.conn.send(data)
    #         print("done echoing...")

    #         data = self.conn.recv(1024)
    #         hexdump(data)
    #         break


def send_tpdu_frame(conn, cmd, head_ext, body, enc_head=bytes([])):
    frame = build_tpdu_frame(cmd, enc_head, head_ext, body)
    conn.sendall(frame)

    # _re_parse the bytes as a Construct struct for pretty printing.
    print("\nS->C:")
    print(TPDUFrame.parse(frame))


def print_tpdu_frame(cmd, head_ext, body, enc_head=bytes([])):
    frame = build_tpdu_frame(cmd, enc_head, head_ext, body)
    print("\nprint_tpdu_frame:")
    print(TPDUFrame.parse(frame))


def build_tpdu_frame(cmd, enc_head, head_ext, body):
    out = io.BytesIO()
    base = TPDUBase.build(dict(
        Magic=TPDU_MAGIC,
        Version=TPDU_VERSION,
        Cmd=cmd.value,
        EncHeadLen=len(enc_head),
        HeadLen=len(head_ext) + 12,
        BodyLen=len(body),
    ))
    out.write(base)
    out.write(enc_head)
    out.write(head_ext)
    out.write(body)
    return out.getvalue()


def listen():
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    connection.bind(('127.0.0.1', 8142))
    connection.listen(10)
    print("Starting server...")
    while True:
        current_connection, address = connection.accept()
        print("Got connection", address)

        game_client = GameClient(current_connection, address)
        t = threading.Thread(
            target=GameClient.HandlePacketsQQMode, args=(game_client,))
        t.start()


def test():
    key = b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
    iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'

    syn_info = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x74, 0x73, 0x66, 0x34, 0x67, 16
                              ])

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypt_syn_info = cipher.encrypt(syn_info)
    hexdump(encrypt_syn_info)

    ext = TPDUExtSyn.build(dict(
        Len=32,
        EncryptSynInfo=encrypt_syn_info,
    ))

    print(TPDUExtSyn.parse(ext))
    print_tpdu_frame(TPDU_CMD.TPDU_CMD_SYN, ext, bytes([]))


if __name__ == "__main__":
    try:
        #test()
        listen()
    except KeyboardInterrupt:
        pass
