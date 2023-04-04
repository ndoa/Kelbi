import socket
from hexdump import hexdump

HOST = "127.0.0.1"
PORT = 8142

# Read exactly `size` bytes from the connection (to deal with TCP)


def recv_exactly(conn, size):
    buf = []
    while len(buf) < size:
        tmp = conn.recv(size-len(buf))
        buf.append(tmp)
    return buf


def main():
    print("starting server")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                headerBytes = recv_exactly(conn, 12)
                
                #data = conn.recv(1024)
                # hexdump(data)

                if not data:
                    break
                # conn.sendall(data)


if __name__ == '__main__':
    main()
