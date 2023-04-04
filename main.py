import io
import socket
import struct
import threading
from Packets import *
from hexdump import hexdump


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

    def handle_tpdu_auth(self, packet):
        # Send the TPDU_CMD_SYN packet to the client.
        ext = TPDUExtSyn.build(dict(
            Len=16,
            EncryptSynInfo=bytes(
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ))

        send_tpdu_frame(self.conn, TPDU_CMD.TPDU_CMD_SYN, ext, bytes([]))

    def handle_tpdu_synack(self, packet):
        # Got synack, now send TPDU_CMD_IDENT.
        # inner_ext = TPDUIdentInfo.build(dict(
        #     Pos=0,
        #     Ident=0
        # ))

        
        inner_ext = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

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

        ext = TPDUExtChgSkey.build(dict(
            Type=0,
            Len=128,
            EncryptSkey=bytes(bytearray(128))
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
                MajorVerNo=csproto_packet.Body.MajorVerNo+1,
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


        """
        Got CSPkg: Container:
            Head = Container:
                CmdID = (enum) CS_CMD_CHECK_VERSION_REQ 21
                HeadLen = 16
                BodyLen = 48
                SeqID = 2
                NoUse = 0
            Body = Container:
                MajorVerNo = 2
                MinorVerNo = 0
                RevisVerNo = 11
                BuildVerNo = 860
                IgnoreTag = 0
                ProtoVer = 1
                Feature = Container:
                    FeatureHash = 740454117
                    FeatureEnabled = 15564440302519814839
                Reserve1 = 0
                Reserve2 = 0
                TGPTicketLen = 0
                TGPTicket = ListContainer:
        """



    def _read_tpdu_packet_frame(self):
        # Read the TPDUBase (packet header)
        #print("Reading TPDUBase header")
        baseSize = 12
        header_bytes = fixed_recv(self.conn, baseSize)
        # hexdump(header_bytes)

        # Temporarily parse the header to get the size of the header ext and body.
        header = TPDUBase.parse(header_bytes)
        # print(header)

        #assert(header.EncHeadLen == 0)

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

def build_tpdu_frame(cmd, enc_head, head_ext, body):
    out = io.BytesIO()
    base = TPDUBase.build(dict(
        Magic=TPDU_MAGIC,
        Version=TPDU_VERSION,
        Cmd=cmd.value,
        EncHeadLen=len(enc_head),
        HeadLen=len(head_ext)+12,
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


if __name__ == "__main__":

    # ext = TPDUExtIdent.build(dict(
    #     Len=4,
    #     EncryptIdent=[0, 0, 0, 0],
    # ))

    # resp = TPDUFrame.build(dict(
    #     Head=dict(
    #         Base=dict(
    #             Magic=TPDU_MAGIC,
    #             Version=TPDU_VERSION,
    #             Cmd=TPDU_CMD.TPDU_CMD_IDENT,
    #             EncHeadLen=0,
    #             HeadLen=12+len(ext),
    #             BodyLen=0,
    #         ),
    #         Ext=TPDUExtIdent.parse(ext)
    #     ),
    #     Body=dict()
    # ))

    # print(resp)
    # print(TPDUFrame.parse(resp))
    # os.exit(1)

    # data = bytes([0x55, 0x0E, 0x03, 0x00, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x24, 0x89, 0xE8, 0x65, 0x00, 0x00, 0x00, 0x03, 0x7D, 0xE9, 0x81, 0x15, 0x48, 0x00, 0x01, 0x63, 0x2C, 0x78, 0xC9, 0x00, 0x40, 0x65, 0x2D, 0xF7, 0xD0, 0x1E, 0x90, 0x49, 0xDC, 0x2B, 0x4E, 0xF8, 0x48, 0xEC,
    #               0x7C, 0x18, 0xC4, 0xBF, 0xB6, 0x92, 0x6B, 0x14, 0x2E, 0xE5, 0xFF, 0x01, 0xA8, 0xC7, 0xF8, 0x25, 0xC6, 0x66, 0x0B, 0x25, 0xA8, 0x08, 0xC0, 0x63, 0xC3, 0xCC, 0xA7, 0x34, 0x69, 0x3E, 0x67, 0xA1, 0x3E, 0xFE, 0xB4, 0x0C, 0xF0, 0x83, 0x31, 0x11, 0x7B, 0xFB, 0x8F, 0x59, 0x42, 0xDC, 0x75, 0x34, 0xAA, 0xD8, 0x24])
    # frame = TPDUFrame.parse(data)
    # print(frame)
    # os.exit(1)
    # data = b'\x00\x00\x00\x03\x24\x89\xE8\x65\x00\x00\x00\x03\x00\x00\x00\x55'
    # print(TPDUExtAuthInfo.parse(data))

    try:
        listen()
    except KeyboardInterrupt:
        pass
