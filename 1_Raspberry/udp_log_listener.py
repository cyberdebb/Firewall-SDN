# udp_log_server.py
import socket

# IP e porta para escutar (0.0.0.0 escuta em todas as interfaces de rede)
UDP_IP = "0.0.0.0"
UDP_PORT = 12345 # A mesma porta configurada nos ESPs

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"--- Servidor de Logs UDP iniciado. Escutando na porta {UDP_PORT} ---")
print("--- Pressione Ctrl+C para sair. ---")

try:
    while True:
        data, addr = sock.recvfrom(1024) # Tamanho do buffer
        # Imprime o log formatado, removendo espaços em branco extras
        print(data.decode(errors='ignore').strip())
except KeyboardInterrupt:
    print("\n--- Servidor de logs encerrado. ---")