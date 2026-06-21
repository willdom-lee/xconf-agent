import socket
import sys
import threading

def handle_client(client_socket):
    try:
        request = client_socket.recv(4096)
        if not request:
            return
        
        # Parse the request line (e.g. "CONNECT google.com:443 HTTP/1.1")
        first_line = request.split(b'\n')[0]
        url = first_line.split(b' ')[1]
        
        # Check if it is a CONNECT tunnel (HTTPS)
        http_method = first_line.split(b' ')[0]
        
        if http_method == b'CONNECT':
            # HTTPS tunnel
            host, port = url.split(b':')
            port = int(port)
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((host.decode(), port))
            client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            
            # Forward data bidirectionally
            threading.Thread(target=forward, args=(client_socket, remote_socket)).start()
            forward(remote_socket, client_socket)
        else:
            # HTTP request
            if b'://' in url:
                url = url.split(b'://')[1]
            temp = url.split(b'/')[0]
            if b':' in temp:
                host, port = temp.split(b':')
                port = int(port)
            else:
                host = temp
                port = 80
            
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((host.decode(), port))
            remote_socket.sendall(request)
            
            # Forward data bidirectionally
            threading.Thread(target=forward, args=(client_socket, remote_socket)).start()
            forward(remote_socket, client_socket)
    except Exception as e:
        pass
    finally:
        try:
            client_socket.close()
        except:
            pass

def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except:
        pass
    finally:
        try:
            src.close()
        except:
            pass
        try:
            dst.close()
        except:
            pass

def start_proxy(ip, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((ip, port))
    server.listen(100)
    print(f"Proxy listening on {ip}:{port}...")
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == '__main__':
    ip = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 7890
    start_proxy(ip, port)
