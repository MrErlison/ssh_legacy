# Cliente SSH em Python (`ssh.py`)

O `ssh.py` é um script em Python que implementa um cliente SSH interativo. Ele utiliza a biblioteca `paramiko` para estabelecer conexões seguras e permite acessar o shell remoto do servidor, apresentando comportamento similar ao cliente SSH tradicional de linha de comando.

## Pré-requisitos

- Python 3.6 ou superior
- Biblioteca `paramiko`

Para instalar a dependência necessária, execute:

```bash
sudo python3 -mpip install paramiko --break-system-packages
```

Em seguida torne o script executável:

```bash
chmod +x ssh.py
```

## Principais Funcionalidades

- **Acesso Interativo (Shell):** Conecta-se e abre uma sessão de shell completa, gerenciando a entrada (stdin) e saída (stdout) em tempo real, permitindo executar comandos perfeitamente.
- **Múltiplos Métodos de Autenticação:**
  - Autenticação por usuário e senha.
  - Autenticação via chave privada RSA (com suporte a arquivos de chave protegidos por senha/passphrase).

- **Prompts Interativos:** Caso credenciais vitais (como *host*, *usuário*, *senha* ou *passphrase* da chave) não sejam informadas via linha de comando, o script solicita essas informações de forma segura no terminal.

- **Segurança por Padrão:** Por padrão, o cliente **rejeita** a conexão caso a chave apresentada pelo host (*host key*) seja desconhecida/não confiável, protegendo contra ataques *Man-in-the-Middle* (MITM). Há uma flag explícita (`--insecure`) para aceitar hosts desconhecidos caso seja estritamente necessário.

- **Fallback para Autenticação Legada (KEX):** Útil ao conectar-se a servidores defasados (como switches e roteadores legados). Caso a negociação de algoritmos de troca de chave (KEX) falhe inicialmente, o script tenta reconectar automaticamente utilizando algoritmos antigos como `diffie-hellman-group14-sha1` e `diffie-hellman-group1-sha1`.

- **Encerramento Limpo:** Captura sinais do sistema (como `Ctrl+C`) para fechar a conexão de forma limpa e graciosa.

## Como Usar

A estrutura básica da linha de comando é semelhante à do utilitário SSH padrão.

```bash
./ssh.py [destination] [opções]
```

### Argumentos e Opções

- `destination`: O destino da conexão. Pode ser apenas o IP/Hostname ou no formato `usuario@host`.
- `-l USER`: Especifica o usuário da conexão.
- `-p PORT`: Específica a porta SSH (o valor padrão é `22`).
- `-i KEYFILE`: Caminho para o arquivo de chave privada (ex: `~/.ssh/id_rsa`).
- `--insecure`: Permite a conexão a hosts com chaves desconhecidas (utiliza o `AutoAddPolicy` do Paramiko).

### Exemplos de Uso

**1. Conexão Simples**

```bash
./ssh.py root@192.168.0.10
# ou
./ssh.py 192.168.0.10 -l root
```
*(O script solicitará a senha interativamente).*

**2. Utilizando Chave Privada**

```bash
./ssh.py root@192.168.0.10 -i ~/.ssh/id_rsa
```
*(Se a chave privada tiver senha, o script perguntará qual é a senha no terminal).*

**3. Porta Customizada**

```bash
./ssh.py myuser@meuservidor.com -p 2222
```

**4. Conectando pela Primeira Vez (Permitir Host Desconhecido)**

Se for a primeira vez que você está conectando a um servidor ou o servidor não estiver no seu `known_hosts`, você pode usar a flag insegura para contornar a rejeição de segurança.

```bash
./ssh.py root@192.168.0.10 --insecure
```

**5. Modo 100% Interativo**

Você pode simplesmente iniciar o script sem nenhum argumento. Ele perguntará o Host, Usuário e Senha dinamicamente:

```bash
./ssh.py
```

## Arquitetura do Código

A aplicação está separada da seguinte forma:

- **`SSHConfig`**: (*Dataclass*) Armazena a configuração imutável e estruturada da conexão (host, credenciais, porta).

- **`SSHParser`**: Lida com a coleta de informações — tanto pegando do `argparse` via argumentos de terminal quanto promovendo inputs interativos (`getpass.getpass`) de dados faltantes.

- **`SecureSSHClient`**: Classe principal que envolve o cliente SSH Paramiko. É responsável por definir as políticas de chaves públicas, gerenciar o *fallback* de algoritmos legados (`try/except` customizado para KEX failure), e estabelecer o túnel.

- **`InteractiveShell`**: Lida com a troca de buffers (streams). Usa a chamada de sistema `select.select` para escutar tanto a resposta contínua do servidor remoto (`chan`) quanto as coisas que o usuário digita localmente (`sys.stdin`).
