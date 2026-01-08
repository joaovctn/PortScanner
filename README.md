# 🛡️ PortScanner

![Badge](https://img.shields.io/badge/.NET-10.0-purple?style=flat-square&logo=dotnet)
![Badge](https://img.shields.io/badge/Type-Red%20Team-red?style=flat-square)
![Badge](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> **High-Performance Asynchronous TCP Port Scanner & Banner Grabber.**

O **PortScanner** é uma ferramenta de reconhecimento ofensivo (Recon) desenvolvida em C# puro. Diferente de scanners síncronos tradicionais, ele utiliza o poder do `Task Parallel Library (TPL)` e `Async/Await` para escanear milhares de portas simultaneamente sem bloquear a thread principal ou exaurir os recursos do sistema operacional.

Desenvolvido com foco em **Stealth**, **Performance** e **Interoperabilidade** (saída JSON).

---

## 🔥 Funcionalidades (Features)

-   🚀 **Multi-threaded Scanning:** Utiliza `SemaphoreSlim` para controlar a concorrência e evitar DoS no roteador local.
-   🕵️ **OS Fingerprinting Passivo:** Detecta se o alvo é Linux/Unix ou Windows baseando-se no TTL (Time To Live) de pacotes ICMP.
-   📡 **Banner Grabbing Inteligente:** Envia triggers específicos (como `HEAD / HTTP/1.1`) para forçar o serviço a revelar sua versão.
-   🧠 **Service Version Extraction:** Utiliza Regex avançado para limpar o banner e extrair apenas o software e versão (ex: `Apache 2.4`).
-   📊 **Relatórios Estruturados:** Gera saída em `.txt` (human-readable) e `.json` (machine-readable) para automação com Python/SIEM.
-   🌐 **DNS Resolution:** Resolve domínios automaticamente antes do scan.
-   🛡️ **Resiliência:** Lógica de tratamento de erros para timeouts, pings bloqueados e falhas de conexão.

---

## 🛠️ Instalação e Build

### Pré-requisitos
- .NET SDK 8.0 ou superior (Recomendado .NET 10).
- Permissões de Root/Admin (Necessário apenas para o OS Fingerprinting via ICMP).

### Compilando (Windows/Linux/macOS)

```bash
# Clone o repositório
git clone [https://github.com/SEU_USUARIO/PortScanner.git](https://github.com/SEU_USUARIO/PortScanner.git)

# Entre na pasta
cd PortScanner

# Compile (Modo Release para performance máxima)
dotnet build -c Release