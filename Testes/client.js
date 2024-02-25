import net from 'net';

const HOST = "127.0.0.1";  // Endereço IP do servidor
const PORT = 8080;         // Porta utilizada pelo servidor

// Cria um socket TCP e se conecta ao servidor
const client = net.createConnection({ host: HOST, port: PORT }, () => {
  console.log('Conectado ao servidor');
});

// Variável para armazenar os dados recebidos
let receivedData = '';

// Recebe dados enviados pelo servidor
client.on('data', (chunk) => {
  receivedData += chunk.toString();

  // Verifica se a mensagem está completa
  if (receivedData.includes('\n')) {
    console.log('Dados recebidos:', receivedData);

    // Processa a mensagem completa aqui

    // Limpa a variável para a próxima mensagem
    receivedData = '';
  }
});

// Encerra a conexão com o servidor
client.on('end', () => {
  console.log('Conexão encerrada');
});


// Envia uma mensagem para o servidor
var message = 'Ola, servidor! Aqui esta minha mensagem.\n';
client.write(message);

var message = 'Como vai voca?\n';
client.write(message);