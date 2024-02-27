import net from 'net';
import crypto from 'crypto';

const HOST = "127.0.0.1"; 
const PORT = 8080;         

class Client{
  constructor(host, port){
    this.host = host;
    this.port = port;
    this.publicKey = null;
    this.privateKey = null;
    this.secretKey = null;
  }
  async receiveMessage(socket) {
    // Primeiro, receba o tamanho da mensagem
    const rawMsgLenBuffer = await this.receiveData(socket, 4);
    if (!rawMsgLenBuffer) {
        return null;
    }
    const msgLen = this.unpackUInt32BE(rawMsgLenBuffer);
    
    // Em seguida, receba a mensagem em blocos
    const chunks = [];
    let bytesReceived = 0;
    while (bytesReceived < msgLen) {
        const chunk = await this.receiveData(socket, Math.min(msgLen - bytesReceived, 2048));
        if (!chunk) {
            throw new Error('Conexão interrompida');
        }
        chunks.push(chunk);
        bytesReceived += chunk.length;
    }
    
    // Junte os blocos e retorne a mensagem
    return Buffer.concat(chunks);
  }

  async sendMessage(socket, message) {
      // Primeiro, envie o tamanho da mensagem
      const msgLen = message.length;
      const msgLenBuffer = this.packUInt32BE(msgLen);
      await this.sendData(socket, msgLenBuffer);
      
      // Em seguida, envie a mensagem em blocos
      let offset = 0;
      while (offset < msgLen) {
          const chunkSize = Math.min(msgLen - offset, 2048);
          const chunk = message.slice(offset, offset + chunkSize);
          await this.sendData(socket, chunk);
          offset += chunkSize;
      }
  }

  async receiveData(socket, size) {
      let buffer = Buffer.alloc(size);
      let bytesRead = 0;
      while (bytesRead < size) {
        const chunk = await this.receive(socket, size - bytesRead);
        if (!chunk) {
            return null;
        }
        buffer = Buffer.concat([buffer, chunk]);
        bytesRead += chunk.length;
        if(bytesRead < size){
          return buffer;
        }
      }

      return null;
  }

  async sendData(socket, data) {
      return new Promise((resolve, reject) => {
          socket.write(data, (err) => {
              if (err) {
                  reject(new Error('Conexão interrompida'));
              } else {
                  resolve();
              }
          });
      });
  }

  async receive(socket, size) {
    return new Promise((resolve, reject) => {
        let receivedData = Buffer.alloc(0);
        const onData = (data) => {
            receivedData = Buffer.concat([receivedData, data]);
            resolve(receivedData)
        };

        socket.on('data', onData);
    });
  }

  unpackUInt32BE(buffer) {
      return buffer.readUInt32BE(0);
  }

  packUInt32BE(value) {
      const buffer = Buffer.alloc(4);
      buffer.writeUInt32BE(value, 0);
      return buffer;
  }

  generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  encryptKeyWithPublicKey(key, clientPublicKey) {
    return crypto.publicEncrypt(clientPublicKey, key);
  }

  decryptKeyWithPrivateKey(key, privateKey) {
    return crypto.privateDecrypt(privateKey, key);
  }

  async setCryptKey(client) {
    this.generateKeyPair();
    const utf8EncodeText = new TextEncoder();
    const utf8DecodeText = new TextDecoder();
    let bytes = utf8EncodeText.encode(this.publicKey);
    client.write(bytes);
    const serverEncryptedKey = await this.receiveData(client, 2048);
    this.secretKey = this.decryptKeyWithPrivateKey(utf8DecodeText.decode(serverEncryptedKey), this.privateKey);
  }

  encrypt(data) {
    const iv = crypto.randomBytes(16); // Vetor de inicialização
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(this.secretKey), iv);
    const encryptedData = Buffer.concat([cipher.update(data, 'utf-8'), cipher.final()]);

    return { iv: iv.toString('base64'), encryptedData: encryptedData.toString('base64') };
  }

  decrypt(encryptedData, iv) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(this.secretKey), Buffer.from(iv, 'base64'));
    const decryptedData = Buffer.concat([decipher.update(Buffer.from(encryptedData, 'base64')), decipher.final()]);

    return decryptedData.toString('utf-8');
  }

  async run(){
    const client = net.createConnection({ host: this.host, port: this.port, keepAlive: true }, () => {
      console.log('Conectado ao servidor');
    });

    await this.setCryptKey(client);
    console.log(this.secretKey, "depois da func")
    client.write("Nada a se dizer");

    client.on('end', () => {
      console.log('Conexão encerrada');
    });
  }
}


let client = new Client(HOST, PORT);
client.run();
