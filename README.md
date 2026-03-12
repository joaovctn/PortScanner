# 🛡️ PortScanner

![.NET](https://img.shields.io/badge/.NET-10.0-purple?style=flat-square&logo=dotnet)
![Type](https://img.shields.io/badge/Type-Red%20Team-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> **High-Performance Asynchronous TCP Port Scanner & Banner Grabber**

O **PortScanner** é uma ferramenta de reconhecimento ofensivo (**Recon**) desenvolvida em **C# puro**.  
Diferente de scanners síncronos tradicionais, ele utiliza o poder do **Task Parallel Library (TPL)** e **Async/Await** para escanear milhares de portas simultaneamente sem bloquear a thread principal ou exaurir os recursos do sistema operacional.

Desenvolvido com foco em **Stealth**, **Performance** e **Interoperabilidade** (saída JSON).

---

## 🔥 Funcionalidades (Features)

- 🚀 **Multi-threaded Scanning:** Utiliza `SemaphoreSlim` para controlar a concorrência e evitar DoS no roteador local.
- 🕵️ **OS Fingerprinting Passivo:** Detecta se o alvo é Linux/Unix ou Windows com base no TTL (Time To Live) de pacotes ICMP.
- 📡 **Banner Grabbing Inteligente:** Envia triggers específicos (ex: `HEAD / HTTP/1.1`) para forçar o serviço a revelar sua versão.
- 🧠 **Service Version Extraction:** Usa Regex avançado para extrair apenas software e versão (ex: `Apache 2.4`).
- 📊 **Relatórios Estruturados:** Gera saída `.txt` (human-readable) e `.json` (machine-readable).
- 🌐 **DNS Resolution:** Resolve domínios automaticamente antes do scan.
- 🛡️ **Resiliência:** Tratamento de erros para timeouts, ICMP bloqueado e falhas de conexão.

---

## 🛠️ Instalação e Build

### Pré-requisitos
- .NET SDK **8.0 ou superior** (Recomendado: **.NET 10**)
- Permissões de **Root/Admin** (necessário apenas para OS Fingerprinting via ICMP)

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
sudo dotnet run -- -t <ALVO> -p <PORTAS> -o <RELATORIO>
./PortScanner -t 192.168.0.1 -p all
```

### Argumentos

| Argumento   | Descrição                                                     | Exemplo                          |
|------------|---------------------------------------------------------------|----------------------------------|
| `-t`       | Define o alvo (IP ou domínio)                                 | `-t scanme.nmap.org`             |
| `-p`       | Define portas (lista, intervalo ou `all`)                     | `-p 22,80,1000-2000`             |
| `-o`       | (Opcional) Salva relatório TXT + JSON                         | `-o report.txt`                  |
| `-timeout` | (Opcional) Timeout em ms por porta (padrão: 1500)             | `-timeout 500`                   |

---

## 📸 Exemplo de Saída (Proof of Concept)

```bash
sudo dotnet run -- -t scanme.nmap.org -p 22,80,9929 -o report.txt
```

```text
[i] Alvo: scanme.nmap.org (45.33.32.156)
[*] Detectando Sistema Operacional... Linux/Unix (TTL Inacessível, mas Online)
[i] Portas: 3 portas selecionadas.

--- INICIANDO SCAN ---

[+] 9929  Desconhecido ABERTA
[+] 80    HTTP        ABERTA | Versão: HTTP/1.1
[+] 22    SSH         ABERTA | Banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13

--- Scan finalizado em 0.47s ---
[+] Relatório salvo com sucesso em: report.txt
[+] Relatório JSON salvo em: report.json
```

---

## 🧾 JSON Output

```json
{
  "target": "scanme.nmap.org",
  "scan_date": "2026-01-08T13:16:28",
  "os_fingerprint": "Linux/Unix (TTL Inacessível, mas Online)",
  "open_ports": [
    { "port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13" },
    { "port": 80, "service": "HTTP", "banner": "HTTP/1.1 200 OK" },
    { "port": 9929, "service": "Desconhecido", "banner": "" }
  ]
}
```

---

## 🧠 Detalhes Técnicos (Under the Hood)

### 1. Concorrência Segura
Uso de `SemaphoreSlim` para limitar conexões simultâneas (padrão: 200).

### 2. Async/Await & Task.WhenAny
Implementação de timeout não-bloqueante usando corrida entre conexão e `Task.Delay`.

### 3. Regex Versioning
Regex utilizada:
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

