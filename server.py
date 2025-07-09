import paramiko
import threading
import socket

class MinimalSSHServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL
    
    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

def handle_connection(client_socket):
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(paramiko.RSAKey.generate(2048))
    
    server = MinimalSSHServer()
    transport.set_subsystem_handler('sftp', paramiko.SFTPServer)
    
    transport.start_server(server=server)
    
    channel = transport.accept(20)
    if channel is None:
        return
    
    channel.send(b"Welcome to Secure Vault!\n")
    channel.send(b"Type 'exit' to quit.\n")
    
    while True:
        try:
            command = channel.recv(1024).decode().strip()
            if command.lower() == 'exit':
                break
            channel.send(f"You typed: {command}\n".encode())
        except:
            break
    
    channel.close()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 2222))
    server_socket.listen(100)
    
    print("SSH Server running on port 2222...")
    
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        client_thread = threading.Thread(target=handle_connection, args=(client_socket,))
        client_thread.start()

if __name__ == "__main__":
    main() 