import socket, sys, threading, base64, random, hashlib

HOST = "127.0.0.1"
PORT = 8080

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:

    server.bind((HOST, PORT))
    server.listen()
    
    print("Servidor rodando")
    while True:
        (client, address) = server.accept()
        
        print(f"Conexão com o cliente do address {address}")
        try:            
            text = client.recv(2048)
            
            print(text)
            print("primeiro print")

            client.send(b"Ola client")
            
            text = client.recv(2048)
            
            print(text)
            print("segundo print")
            
            client.close()
        except KeyboardInterrupt:
            sys.exit(1)
        except Exception as e:
            print(e)
            sys.exit(1)
