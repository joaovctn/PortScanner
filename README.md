# 🛡️ PortScanner

![.NET](https://img.shields.io/badge/.NET-10.0-purple?style=flat-square&logo=dotnet)
![Type](https://img.shields.io/badge/Type-Red%20Team-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> **High-Performance Asynchronous TCP Port Scanner & Banner Grabber**

O **PortScanner** é uma ferramenta de reconhecimento ofensivo (**Recon**) desenvolvida em **C# puro**.  
Diferente de scanners síncronos tradicionais, ele utiliza o poder do **Task Parallel Library (TPL)** e **Async/Await** para escanear milhares de portas simultaneamente, sem bloquear a thread principal ou exaurir os recursos do sistema operacional.

Desenvolvido com foco em **Stealth**, **Performance** e **Interoperabilidade** (saída JSON).

---

## 🔥 Funcionalidades (Features)

- 🚀 **Multi-threaded Scanning**  
  Utiliza `SemaphoreSlim` para controlar a concorrência e evitar DoS no roteador local.

- 🕵️ **OS Fingerprinting Passivo**  
  Detecta se o alvo é Linux/Unix ou Windows com base no TTL (Time To Live) de pacotes ICMP.

- 📡 **Banner Grabbing Inteligente**  
  Envia triggers específicos (ex: `HEAD / HTTP/1.1`) para forçar o serviço a revelar sua versão.

- 🧠 **Service Version Extraction**  
  Usa Regex avançado para extrair apenas software e versão (ex: `Apache 2.4`).

- 📊 **Relatórios Estruturados**  
  Gera saída `.txt` (human-readable) e `.json` (machine-readable) para automação com Python/SIEM.

- 🌐 **DNS Resolution**  
  Resolve domínios automaticamente antes do scan.

- 🛡️ **Resiliência**  
  Tratamento de erros para timeouts, ICMP bloqueado e falhas de conexão.

---

## 🛠️ Instalação e Build

### Pré-requisitos

- .NET SDK **8.0 ou superior** (Recomendado: **.NET 10**)
- Permissões de **Root/Admin**  
  (Necessário apenas para OS Fingerprinting via ICMP)

### Compilando (Windows / Linux / macOS)

```bash
git clone https://github.com/SEU_USUARIO/PortScanner.git
cd PortScanner
dotnet build -c Release
```

---

## 💻 Como Usar

```bash
sudo dotnet run -- -t <ALVO> -p <PORTAS> -o <RELATORIO>
./PortScanner -t 192.168.0.1 -p all
```

---

## ⚠️ Disclaimer

Ferramenta para fins educacionais e ambientes autorizados.
Scanning não autorizado é crime.

---

<p align="center">
Desenvolvido por <a href="https://github.com/joaovctn">João Santos</a> 💀
</p>
