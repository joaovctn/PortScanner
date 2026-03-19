# 🛡️ PortScanner

![.NET](https://img.shields.io/badge/.NET-10.0-purple?style=flat-square&logo=dotnet)
![Type](https://img.shields.io/badge/Type-Red%20Team-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> **High-Performance Asynchronous TCP/UDP Port Scanner & Banner Grabber**

O **PortScanner** é uma ferramenta de reconhecimento ofensivo (**Recon**) desenvolvida em **C# puro**.
Utiliza o **Task Parallel Library (TPL)** e **Async/Await** para escanear milhares de portas simultaneamente sem bloquear a thread principal ou exaurir recursos do sistema.

Desenvolvido com foco em **Performance**, **Flexibilidade** e **Interoperabilidade** (saída TXT, JSON, CSV e XML).

---

## 🔥 Funcionalidades

- 🚀 **Multi-threaded Scanning:** `SemaphoreSlim` com concorrência configurável via `-c`.
- 🔌 **Scan TCP e UDP:** Ambos os protocolos em paralelo com `--udp`.
- 🌐 **Múltiplos Alvos:** Aceita múltiplos `-t`, notação CIDR (`192.168.1.0/24`) e listas via arquivo (`-iL`).
- 📡 **Ping Sweep:** Filtra hosts offline automaticamente antes de escanear portas em redes CIDR.
- 🕵️ **OS Fingerprinting Passivo:** Detecta Linux/Unix, Windows ou Cisco com base no TTL dos pacotes ICMP.
- 🧲 **Banner Grabbing por Protocolo:** Probes ativos por serviço — HTTP, HTTPS, SMTP, POP3, IMAP, Redis, DNS, SNMP, NTP.
- 🧠 **Service Version Extraction:** Regex para extrair software e versão do banner (ex: `Apache/2.4.51`).
- 🔎 **DNS Reverso (PTR):** Resolve o hostname de cada IP com porta aberta após o scan.
- ⏱️ **Timeout Adaptativo:** Mede RTT via ping e ajusta o timeout automaticamente (`--adaptive-timeout`).
- 🗂️ **Top Ports:** Escaneia as N portas mais comuns sem especificar ranges (`--top-ports N`).
- 📊 **Relatórios Múltiplos:** Gera `.txt`, `.json`, `.csv` e `.xml` (nmap-compatible) com `-o`.
- 📋 **Tabela Resumo:** Tabela formatada com IP, protocolo, porta, serviço, hostname e banner ao final.
- 🔍 **Filtered vs Closed:** Diferencia porta filtrada (timeout) de porta fechada (connection refused).
- 🥷 **Modo Stealth:** `--delay <ms>` insere delay + jitter aleatório entre conexões.
- 🔑 **Credenciais Padrão:** `--check-creds` testa FTP anonymous, Redis sem senha e MongoDB sem auth.
- 🛤️ **Traceroute:** `--traceroute` exibe o caminho de rede hop a hop antes do scan.
- 🗄️ **Cache + Diff:** `--cache` salva resultados e exibe o que mudou desde o último scan.
- 👁️ **Watch Mode:** `--watch <s>` repete o scan em loop e alerta sobre mudanças.
- 💬 **Modo Interativo:** `--interactive` abre prompt pós-scan com `info`, `connect` (netcat), `hosts`, `ports`.
- 🔇 **Modos de Output:** Verboso (`-v`) e silencioso (`-q`).
- ⚡ **Cancelamento Gracioso:** Ctrl+C finaliza o scan e ainda gera o relatório parcial.

---

## 🛠️ Instalação e Build

### Pré-requisitos
- .NET SDK **8.0 ou superior** (Recomendado: **.NET 10**)
- Permissões de **Administrador** (necessário para ICMP e scan UDP)

### Compilando

```bash
git clone https://github.com/joaovctn/PortScanner.git
cd PortScanner/PortScanner
dotnet build -c Release
```

---

## 💻 Como Usar

### Sintaxe Básica

```bash
./PortScanner -t <ALVO> [opções]
```

### Argumentos

| Argumento            | Descrição                                                        | Exemplo                    |
|----------------------|------------------------------------------------------------------|----------------------------|
| `-t <alvo>`          | IP, domínio ou CIDR — pode ser repetido                         | `-t 192.168.1.0/24`        |
| `-iL <arquivo>`      | Carrega lista de alvos de arquivo (`#` = comentário)            | `-iL targets.txt`          |
| `-p <portas>`        | Lista, intervalo ou `all` (padrão: `1-1000`)                   | `-p 22,80,1000-2000`       |
| `--top-ports <N>`    | N portas mais comuns — máx: 100                                 | `--top-ports 50`           |
| `-o <arquivo>`       | Salva `.txt`, `.json`, `.csv` e `.xml`                          | `-o relatorio.txt`         |
| `-timeout <ms>`      | Timeout por porta em ms (padrão: `1500`)                        | `-timeout 500`             |
| `--adaptive-timeout` | Ajusta timeout pelo RTT medido                                  | `--adaptive-timeout`       |
| `-c <N>`             | Concorrência máxima (padrão: `200`)                             | `-c 500`                   |
| `--delay <ms>`       | Delay + jitter entre conexões (stealth)                         | `--delay 200`              |
| `--udp`              | Inclui scan UDP além do TCP                                     | `--udp`                    |
| `--traceroute`       | Exibe traceroute antes do scan                                  | `--traceroute`             |
| `--check-creds`      | Verifica credenciais padrão (FTP, Redis, MongoDB)               | `--check-creds`            |
| `--cache`            | Salva cache e exibe diff com scan anterior                      | `--cache`                  |
| `--watch <s>`        | Repete o scan em loop a cada N segundos                         | `--watch 60`               |
| `--interactive`      | Abre prompt interativo após o scan                              | `--interactive`            |
| `-v`                 | Verboso: exibe portas fechadas e filtradas                      | `-v`                       |
| `-q`                 | Silencioso: exibe apenas portas abertas                         | `-q`                       |

---

## 📸 Exemplos de Uso

```bash
# Scan simples
./PortScanner -t scanme.nmap.org

# Top 100 portas + verificação de credenciais
./PortScanner -t 192.168.1.1 --top-ports 100 --check-creds

# Rede inteira com relatórios
./PortScanner -t 192.168.1.0/24 -p 22,80,443,3389 -o resultado.txt

# TCP + UDP via arquivo de alvos
./PortScanner -iL targets.txt -p all -c 500 --udp -o relatorio.txt

# Múltiplos alvos com traceroute e modo interativo
./PortScanner -t 10.0.0.1 -t 10.0.0.2 --traceroute --interactive

# Monitoramento contínuo a cada 60s
./PortScanner -t 10.0.0.1 -p 22,80,443 --watch 60

# Scan stealth com timeout adaptativo
./PortScanner -t 10.0.0.1 -p 1-65535 --adaptive-timeout --delay 300
```

---

## 📸 Exemplo de Saída

```text
[i] Alvo: scanme.nmap.org (45.33.32.156)
[*] Detectando SO... Linux/Unix (TTL=54)
[i] Hosts: 1 | Portas: 3 | Proto: TCP | Conc: 200

--- INICIANDO SCAN ---

[+] 45.33.32.156    TCP  22    SSH            ABERTA | OpenSSH/6.6.1
[+] 45.33.32.156    TCP  80    HTTP           ABERTA | Apache/2.4.7
[+] 45.33.32.156    TCP  9929  Desconhecido   ABERTA

--- Scan finalizado em 0.61s ---

[*] DNS reverso... Concluído.

╔═════════════════╦══════╦═══════╦════════════════╦══════════════════════╦════════════════╗
║ IP              ║ PROT ║ PORTA ║ SERVIÇO        ║ HOSTNAME             ║ BANNER/VERSÃO  ║
╠═════════════════╬══════╬═══════╬════════════════╬══════════════════════╬════════════════╣
║ 45.33.32.156    ║ TCP  ║ 22    ║ SSH            ║ scanme.nmap.org      ║ OpenSSH/6.6.1  ║
║ 45.33.32.156    ║ TCP  ║ 80    ║ HTTP           ║ scanme.nmap.org      ║ Apache/2.4.7   ║
║ 45.33.32.156    ║ TCP  ║ 9929  ║ Desconhecido   ║ scanme.nmap.org      ║                ║
╚═════════════════╩══════╩═══════╩════════════════╩══════════════════════╩════════════════╝
  Total: 3 porta(s) aberta(s)

[+] TXT: relatorio.txt
[+] JSON: relatorio.json
[+] CSV:  relatorio.csv
[+] XML:  relatorio.xml
```

---

## 🧾 JSON Output

```json
{
  "scan_date": "2026-03-19T14:22:10",
  "os_fingerprint": "Linux/Unix (TTL=54)",
  "targets": ["scanme.nmap.org"],
  "open_ports": [
    { "ip": "45.33.32.156", "hostname": "scanme.nmap.org", "protocol": "TCP", "port": 22, "status": "open", "service": "SSH", "banner": "SSH-2.0-OpenSSH_6.6.1p1", "default_creds": "" },
    { "ip": "45.33.32.156", "hostname": "scanme.nmap.org", "protocol": "TCP", "port": 80, "status": "open", "service": "HTTP", "banner": "HTTP/1.1 200 OK", "default_creds": "" }
  ]
}
```

---

## 🏗️ Arquitetura

O projeto é dividido em módulos por responsabilidade:

```
Program.cs                  ← entry point (~10 linhas)

Models/
  ScanResult.cs             ← modelo de dados de um resultado
  ScanOptions.cs            ← todos os flags CLI + Parse() + GetPorts()

Core/
  PortScanner.cs            ← orquestrador principal do fluxo
  ScanContext.cs            ← estado compartilhado de um scan (semaphore, resultados, progresso)
  ScanRunner.cs             ← executa um ciclo TCP+UDP, reutilizado por PortScanner e WatchMode
  TcpScanner.cs             ← lógica de scan TCP com detecção open/closed/filtered
  UdpScanner.cs             ← lógica de scan UDP com probes por protocolo

Recon/
  DnsResolver.cs            ← resolução de alvos, expansão CIDR, PTR lookup paralelo
  PingSweeper.cs            ← ping sweep paralelo
  OsDetector.cs             ← fingerprint por TTL + medição de RTT
  Traceroute.cs             ← traceroute hop a hop com DNS reverso

Grabbers/
  BannerGrabber.cs          ← probes ativos, extração de versão, mapeamento de serviços

Security/
  CredentialChecker.cs      ← FTP anonymous, Redis no-auth, MongoDB no-auth

Reports/
  TxtReporter.cs
  JsonReporter.cs
  CsvReporter.cs
  XmlReporter.cs            ← formato nmap-compatible (Metasploit, Faraday, OpenVAS)

Cache/
  ScanCache.cs              ← persistência em %APPDATA%, diff entre scans

Modes/
  WatchMode.cs              ← loop com diff e atualização de relatórios
  InteractiveMode.cs        ← prompt com info, connect (netcat), hosts, ports
```

---

## 🧠 Detalhes Técnicos

### Concorrência e Cancelamento
`SemaphoreSlim` encapsulado em `ScanContext` controla os slots simultâneos. O timeout por porta usa `CancellationTokenSource.CancelAfter()` linked ao token global — conexões expiradas são descartadas sem vazar recursos.

### Filtered vs Closed
`SocketException` com `ConnectionRefused` → `closed`. Timeout ou `OperationCanceledException` não-global → `filtered`. Visível com `-v`.

### ScanContext
Estado mutável de um scan (resultados, progresso, semaphore, lock do console) encapsulado em um único objeto. Permite que `ScanRunner` seja reutilizado sem estado global.

### Ping Sweep Paralelo
`SendPingAsync` em `Task.WhenAll` para todos os hosts do CIDR simultaneamente, eliminando hosts offline antes de consumir slots do semaphore.

### Regex Versioning
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
