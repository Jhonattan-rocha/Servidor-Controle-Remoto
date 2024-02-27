import socket
import threading
import sys
from cryptography.fernet import Fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from kivy.app import App
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
import struct

HOST =  "127.0.0.1"
PORT = 8080
BYTES = 2048
DARK_GREY = '#121212'
MEDIUM_GREY = '#1F1B24'
OCEAN_BLUE = '#464EB8'
WHITE = "white"
FONT = ("Helvetica", 17)
BUTTON_FONT = ("Helvetica", 15)
SMALL_FONT = ("Helvetica", 13)


class Client(App):
    def __init__(self, HOST, PORT, BYTES) -> None:
        super(Client, self).__init__()
        self.HOST = HOST
        self.PORT = PORT
        self.BYTES = BYTES
        self.key = None
        self.fernet = None
        self.public_key = None
        self.private_key = None
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        self.public_key = public_key
        self.private_key = private_key

    # Função para criptografar a chave do Fernet usando a chave pública
    def encrypt_key_with_public_key(self, fernet_key, public_key):
        encrypted_key = public_key.encrypt(
            fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key

    # Função para descriptografar a chave do Fernet usando a chave privada
    def decrypt_key_with_private_key(self, encrypted_key, private_key):
        fernet_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return fernet_key

    def encrypt_large_message(self, message):
        try:
            return self.fernet.encrypt(message)
        except Exception as e:
            print(e)
            return b""

    def decrypt_large_message(self, encrypted_blocks):
        try:
            return self.fernet.decrypt(encrypted_blocks)
        except Exception as e:
            print(e)
            return b""
    
    def receive_message(self, sock: socket.socket):
        # primeiro, receba o tamanho da mensagem
        raw_msglen = sock.recv(4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # em seguida, receba a mensagem em blocos
        chunks = []
        bytes_received = 0
        while bytes_received < msglen:
                                #testa se o que falta é menor que 2048, pois é o máximo, se não for menor, ele sempre lerá 20248 até acabar
            chunk = sock.recv(min(msglen - bytes_received, 2048))
            if not chunk:
                raise RuntimeError('Conexão interrompida')
            chunks.append(chunk)
            bytes_received += len(chunk)
        # junte os blocos e retorne a mensagem
        return b" ".join(chunks)

    def send_message(self, sock, message):
        # primeiro, envie o tamanho da mensagem
        msglen = len(message)
        sock.sendall(struct.pack('>I', msglen))
        # em seguida, envie a mensagem em blocos
        offset = 0
        while offset < msglen:
            sent = sock.send(message[offset:offset+2048])
            if not sent:
                raise RuntimeError('Conexão interrompida')
            offset += sent

    def send_file(self, sock, file_path):
        with open(file_path, 'rb') as f:
            file_data = f.read()
        encrypted_data = self.encrypt_large_message(file_data)
        self.send_message(sock, encrypted_data)

    def receive_file(self, sock, file_path):
        encrypted_data = self.receive_message(sock)
        decrypted_data = self.decrypt_large_message(encrypted_data)
        with open(file_path, 'wb') as f:
            f.write(decrypted_data)
    
    def set_crypt_key(self, client: socket.socket):
        self.generate_key_pair()
        client.sendall(self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        fer_key = client.recv(2048)
        self.key = self.decrypt_key_with_private_key(fer_key, self.private_key)
        self.fernet = Fernet(self.key)
    
    def connect(self):
        try:
            user = str(self.username_textbox.text).encode()
            if user:
                self.client.connect((HOST, PORT))
            
                self.set_crypt_key(self.client)
            
                self.send_message(self.client, self.encrypt_large_message(user))
                
                threading.Thread(target=self.listen_messages, args=(self.client, )).start()
                
                self.username_button.disabled = True
                self.username_textbox.disabled = True
                self.message_textbox.disabled = False
                self.message_button.disabled = False
        except Exception as e:
            print(e, 'dentro do connect')
            self.client.close()
        
    def add_message(self, message):
        self.message_box.disabled = False
        self.message_box.text += message + '\n'
        self.message_box.disabled = True
        
    def send_message_from_GUI(self, client: socket.socket):
        mes = str(self.message_textbox.text).encode()
        self.send_message(client, self.encrypt_large_message(mes))
        self.message_textbox.text = ""
    
    def listen_messages(self, client: socket.socket):
        try:
            while True:
                message = self.receive_message(client)
                if message:
                    Clock.schedule_once(lambda dt: self.add_message(self.decrypt_large_message(message).decode()))
                else:
                    client.close()
                    break
        except Exception as e:
            print(e)
            print("Ouvindo mensagens")
            client.close()
            sys.exit(1)
            
    def on_stop(self):
        self.client.sendall(b'exit')
        self.client.close()
        sys.exit(0)

    
    def build(self):
        try:
            self.root_layout = BoxLayout(orientation='vertical', size=(600, 100))

            # Top Frame
            self.top_frame = BoxLayout(orientation='horizontal', spacing=10)
            self.username_label = Label(text="Enter username:", font_size=16)
            self.username_textbox = TextInput(font_size=16, width=300)
            self.username_button = Button(text="Join", font_size=16, on_press=lambda x: self.connect())

            self.top_frame.add_widget(self.username_label)
            self.top_frame.add_widget(self.username_textbox)
            self.top_frame.add_widget(self.username_button)

            # Middle Frame
            self.middle_frame = ScrollView(size=(600, 400))
            self.message_box = TextInput(font_size=14, size_hint_y=None, height=400, multiline=True, readonly=True, background_color=(255,255,255))

            self.middle_frame.add_widget(self.message_box)

            # Bottom Frame
            self.bottom_frame = BoxLayout(size=(150, 100), orientation='horizontal', spacing=10)
            self.message_textbox = TextInput(font_size=16, width=480)
            self.message_button = Button(text="Send", font_size=16, on_press=lambda x: self.send_message_from_GUI(self.client))
            
            self.message_box.disabled = True
            self.message_button.disabled = True
            
            self.bottom_frame.add_widget(self.message_textbox)
            self.bottom_frame.add_widget(self.message_button)

            # Adiciona os frames ao layout principal
            self.root_layout.add_widget(self.top_frame)
            self.root_layout.add_widget(self.middle_frame)
            self.root_layout.add_widget(self.bottom_frame)

            return self.root_layout
        
        except KeyboardInterrupt as e:
            print(e)
            sys.exit(1)
        except Exception as e:
            print(e)
            sys.exit(1)


if __name__ == "__main__":
    client = Client(HOST, PORT, BYTES)
    client.run()
