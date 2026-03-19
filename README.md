# 🛡️ PortScanner

![.NET](https://img.shields.io/badge/.NET-10.0-purple?style=flat-square&logo=dotnet)
![Type](https://img.shields.io/badge/Type-Red%20Team-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> **High-Performance Asynchronous TCP/UDP Port Scanner & Banner Grabber**

O **PortScanner** é uma ferramenta de reconhecimento ofensivo (**Recon**) desenvolvida em **C# puro**.
Diferente de scanners síncronos tradicionais, ele utiliza o poder do **Task Parallel Library (TPL)** e **Async/Await** para escanear milhares de portas simultaneamente sem bloquear a thread principal ou exaurir os recursos do sistema operacional.

Desenvolvido com foco em **Performance**, **Flexibilidade** e **Interoperabilidade** (saída TXT, JSON e CSV).

---

## 🔥 Funcionalidades

- 🚀 **Multi-threaded Scanning:** `SemaphoreSlim` com concorrência configurável (padrão: 200, ajustável via `-c`).
- 🔌 **Scan TCP e UDP:** Suporte a ambos os protocolos em paralelo com `--udp`.
- 🌐 **Múltiplos Alvos:** Aceita múltiplos `-t`, notação CIDR (`192.168.1.0/24`) e listas via arquivo (`-iL`).
- 📡 **Ping Sweep:** Para CIDR e múltiplos hosts, filtra automaticamente os hosts online antes de escanear portas.
- 🕵️ **OS Fingerprinting Passivo:** Detecta Linux/Unix, Windows ou Cisco com base no TTL dos pacotes ICMP.
- 🧲 **Banner Grabbing por Protocolo:** Envia probes específicos por serviço — HTTP (`HEAD`), SMTP (`EHLO`), POP3 (`CAPA`), IMAP (`CAPABILITY`), Redis (`PING`), DNS, SNMP, NTP.
- 🧠 **Service Version Extraction:** Regex para extrair software e versão do banner (ex: `Apache/2.4.51`).
- 🔎 **DNS Reverso (PTR):** Resolve o hostname de cada IP com porta aberta após o scan.
- ⏱️ **Timeout Adaptativo:** Mede o RTT via ping e ajusta o timeout automaticamente (`--adaptive-timeout`).
- 🗂️ **Top Ports:** Escaneia as N portas mais comuns sem precisar especificar ranges (`--top-ports`).
- 📊 **Relatórios Múltiplos:** Gera `.txt`, `.json` e `.csv` simultaneamente com `-o`.
- 📋 **Tabela Resumo:** Exibe tabela formatada com todas as portas abertas, hostname e banner ao final do scan.
- 🔇 **Modos de Output:** Verboso (`-v`, mostra portas fechadas) e silencioso (`-q`, só portas abertas).
- ⚡ **Cancelamento Gracioso:** Ctrl+C finaliza o scan e ainda gera o relatório parcial do que foi encontrado.

---

## 🛠️ Instalação e Build

### Pré-requisitos
- .NET SDK **8.0 ou superior** (Recomendado: **.NET 10**)
- Permissões de **Root/Admin** (necessário para OS Fingerprinting via ICMP e scan UDP)

### Compilando (Windows / Linux / macOS)

```bash
git clone https://github.com/joaovctn/PortScanner.git
cd PortScanner
dotnet build -c Release
```

---

## 💻 Como Usar

### Sintaxe Básica

```bash
./PortScanner -t <ALVO> [opções]
```

### Argumentos

| Argumento            | Descrição                                                        | Exemplo                          |
|----------------------|------------------------------------------------------------------|----------------------------------|
| `-t <alvo>`          | Alvo: IP, domínio ou CIDR (pode ser repetido)                   | `-t 192.168.1.0/24`              |
| `-iL <arquivo>`      | Carrega lista de alvos de um arquivo (# = comentário)            | `-iL targets.txt`                |
| `-p <portas>`        | Portas: lista, intervalo ou `all` (padrão: `1-1000`)            | `-p 22,80,1000-2000`             |
| `--top-ports <N>`    | Escaneia as N portas mais comuns (máx: 100)                     | `--top-ports 50`                 |
| `-o <arquivo>`       | Salva relatório em `.txt`, `.json` e `.csv`                     | `-o relatorio.txt`               |
| `-timeout <ms>`      | Timeout por porta em ms (padrão: `1500`)                        | `-timeout 500`                   |
| `--adaptive-timeout` | Ajusta timeout automaticamente com base no RTT                  | `--adaptive-timeout`             |
| `-c <número>`        | Concorrência máxima (padrão: `200`)                             | `-c 500`                         |
| `--udp`              | Inclui scan UDP além do TCP                                     | `--udp`                          |
| `-v`                 | Modo verboso: exibe portas fechadas também                      | `-v`                             |
| `-q`                 | Modo silencioso: exibe apenas portas abertas                    | `-q`                             |

---

## 📸 Exemplos de Uso

### Scan simples
```bash
./PortScanner -t scanme.nmap.org
```

### Top 100 portas mais comuns
```bash
./PortScanner -t scanme.nmap.org --top-ports 100
```

### Scan de rede inteira com relatório
```bash
./PortScanner -t 192.168.1.0/24 -p 22,80,443,3389 -o resultado.txt
```

### Múltiplos alvos via arquivo com TCP + UDP
```bash
./PortScanner -iL targets.txt -p all -c 500 --udp -o relatorio.txt
```

### Múltiplos alvos diretos
```bash
./PortScanner -t 10.0.0.1 -t 10.0.0.2 -p 80,443
```

### Com timeout adaptativo e modo verboso
```bash
./PortScanner -t 10.0.0.1 -p 1-65535 --adaptive-timeout -v
```

---

## 📸 Exemplo de Saída

```text
[i] Alvo: scanme.nmap.org (45.33.32.156)
[*] Detectando Sistema Operacional... Linux/Unix (TTL=54)
[i] Portas: 3 portas selecionadas | Concorrência: 200

--- INICIANDO SCAN ---

[+] 45.33.32.156    TCP  22    SSH            ABERTA | OpenSSH/6.6.1
[+] 45.33.32.156    TCP  80    HTTP           ABERTA | Apache/2.4.7
[+] 45.33.32.156    TCP  9929  Desconhecido   ABERTA

--- Scan finalizado em 0.61s ---

[*] Resolvendo hostnames (DNS reverso)... Concluído.

╔═════════════════╦══════╦═══════╦════════════════╦══════════════════════╦════════════════╗
║ IP              ║ PROT ║ PORTA ║ SERVIÇO        ║ HOSTNAME             ║ BANNER/VERSÃO  ║
╠═════════════════╬══════╬═══════╬════════════════╬══════════════════════╬════════════════╣
║ 45.33.32.156    ║ TCP  ║ 22    ║ SSH            ║ scanme.nmap.org      ║ OpenSSH/6.6.1  ║
║ 45.33.32.156    ║ TCP  ║ 80    ║ HTTP           ║ scanme.nmap.org      ║ Apache/2.4.7   ║
║ 45.33.32.156    ║ TCP  ║ 9929  ║ Desconhecido   ║ scanme.nmap.org      ║                ║
╚═════════════════╩══════╩═══════╩════════════════╩══════════════════════╩════════════════╝
  Total: 3 porta(s) aberta(s)

[+] Relatório TXT salvo em: relatorio.txt
[+] Relatório JSON salvo em: relatorio.json
[+] Relatório CSV salvo em: relatorio.csv
```

---

## 🧾 JSON Output

```json
{
  "scan_date": "2026-03-19T14:22:10",
  "os_fingerprint": "Linux/Unix (TTL=54)",
  "targets": ["scanme.nmap.org"],
  "open_ports": [
    { "ip": "45.33.32.156", "hostname": "scanme.nmap.org", "protocol": "TCP", "port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_6.6.1p1" },
    { "ip": "45.33.32.156", "hostname": "scanme.nmap.org", "protocol": "TCP", "port": 80, "service": "HTTP", "banner": "HTTP/1.1 200 OK" },
    { "ip": "45.33.32.156", "hostname": "scanme.nmap.org", "protocol": "TCP", "port": 9929, "service": "Desconhecido", "banner": "" }
  ]
}
```

---

## 🧠 Detalhes Técnicos

### 1. Concorrência Segura
`SemaphoreSlim` controla as conexões simultâneas. O valor padrão é 200 e pode ser ajustado com `-c` para evitar sobrecarga na rede local.

### 2. Async/Await com CancellationToken
Timeout implementado via `CancellationTokenSource.CancelAfter()` integrado ao `ConnectAsync`, garantindo que conexões TCP expiradas sejam descartadas corretamente sem vazar recursos.

### 3. Ping Sweep Paralelo
Para múltiplos hosts, o sweep usa `SendPingAsync` em paralelo com `Task.WhenAll`, filtrando hosts offline antes de consumir slots do semaphore com scan de portas.

### 4. DNS Reverso Paralelo
PTR lookups feitos em paralelo via `Dns.GetHostEntryAsync` e `ConcurrentDictionary` para evitar race conditions.

### 5. Regex Versioning
```regex
([a-zA-Z0-9_\-]+)\/([\d\.]+[a-z]?)
```

---

## ⚠️ Disclaimer

Ferramenta desenvolvida para fins **educacionais** e uso em ambientes **autorizados**
(CTF, Pentest contratado, Bug Bounty).

O autor não se responsabiliza pelo uso indevido.
**Scanning não autorizado é crime.**

---

<p align="center">
Desenvolvido por <a href="https://github.com/joaovctn">João Santos</a> 💀
</p>
