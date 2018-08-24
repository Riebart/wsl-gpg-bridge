import sys
import socket
import select
import threading

assuan_socket = sys.argv[1]
unix_socket = sys.argv[2]


def handle(sock, address, remote_address, preamble):
    rs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rs.connect(remote_address)
    rs.sendall(preamble)
    while True:
        irdy, ordy, erdy = select.select([rs, sock], [], [], 0.1)
        if rs in irdy:
            print("Remote has stuff")
            buf = rs.recv(4096)
            # If we've been notified there's a receive, but no bytes read, then
            # we close the socket
            if len(buf) == 0:
                break
            else:
                print("To unix:", buf)
                sock.sendall(buf)
        if sock in irdy:
            print("Unix has stuff")
            buf = sock.recv(4096)
            if len(buf) == 0:
                break  # Connection closed, see above.
            else:
                print("To remote:", buf)
                rs.sendall(buf)
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()
    rs.shutdown(socket.SHUT_RDWR)
    rs.close()


# Step 1: Open a TCP connect socket to the windows socket, and vomit in the second line of the file
with open(assuan_socket, "rb") as fp:
    windows_port = int(fp.readline().strip().decode("ascii"))
    windows_payload = fp.read()

us = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
us.bind(unix_socket)
us.listen(1)

while True:
    print("Selecting...")
    irdy, ordy, erdy = select.select([us], [], [], 5)
    if len(irdy) > 0:
        # handle the server socket
        try:
            client, address = us.accept()
            print("Accepting from (%s, %s)" % (str(client), str(address)))
            thread = threading.Thread(target=lambda c=client, a=address, r=('127.0.0.1', windows_port), p=windows_payload: handle(c, a, r, p))
            thread.start()
        except socket.error as e:
            pass
