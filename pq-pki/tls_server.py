import socket
import ssl

HOST = "0.0.0.0"
PORT = 8443

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

context.load_cert_chain(
    certfile="servers/server1/server1-fullchain.crt",
    keyfile="servers/server1/server1.key"
)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:

    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print(f"TLS server listening on port {PORT}...")

    with context.wrap_socket(
        server_socket,
        server_side=True
    ) as tls_server:

        while True:
            conn, addr = tls_server.accept()

            print(f"Secure connection from {addr}")

            data = conn.recv(1024)

            print("Received:", data.decode())

            conn.sendall(b"Hello from the TLS server!\n")

            conn.close()
