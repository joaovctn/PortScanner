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

## 💻 Como Usar
A ferramenta funciona via CLI (Linha de Comando).

Sintaxe Básica

# Rodando direto do código (Linux requer sudo para Ping/ICMP)
sudo dotnet run -- -t <ALVO> -p <PORTAS> -o <RELATORIO>

# Rodando o binário compilado
./PortScanner -t 192.168.0.1 -p all

# Rodando o binário compilado
./PortScanner -t 192.168.0.1 -p all


## Argumentos
Argumento	Descrição	Exemplo
-t	Define o Alvo (IP ou Domínio).	-t scanme.nmap.org
-p	Define as portas. Aceita listas, intervalos e atalhos.	-p 22,80,1000-2000 ou -p all
-o	(Opcional) Salva o resultado em arquivo. Gera TXT e JSON.	-o scan_result.txt
-timeout	(Opcional) Tempo limite em ms por porta. Padrão: 1500.	-timeout 500

## 📸 Exemplo de Saída (Proof of Concept)

Executando contra o servidor de testes do Nmap:

```bash
sudo dotnet run -- -t scanme.nmap.org -p 22,80,9929 -o report.txt

## Console Output

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

## JSON Output (Gerado Automaticamente)

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

## 🧠 Detalhes Técnicos (Under the Hood)

1. Concorrência Segura (Throttling)
Para evitar o esgotamento de file descriptors ou bloqueios de segurança do roteador, o PortScanner não dispara 65.000 threads de uma vez. Utilizamos um SemaphoreSlim para criar um controle de fluxo, permitindo apenas um número fixo de conexões simultâneas ativas (padrão: 200).

2. Async/Await & Task.WhenAny
O timeout nativo do TcpClient é bloqueante e lento. Implementamos um padrão usando Task.WhenAny, que corre uma tarefa de conexão contra uma tarefa de Task.Delay. A que terminar primeiro define o resultado, permitindo timeouts precisos e não-bloqueantes.

3. Regex Versioning
A extração de versão utiliza a expressão regular @"([a-zA-Z0-9_\-]+)\/([\d\.]+[a-z]?)". Isso limpa banners poluídos e entrega apenas o vetor de ataque relevante (ex: identificar um OpenSSH 6.6 vulnerável para CVEs antigos).


## Disclaimer

Esta ferramenta foi desenvolvida para fins educacionais e uso em ambientes autorizados (CTF, Pentest contratado, Bug Bounty). O autor não se responsabiliza pelo uso indevido desta ferramenta para escanear redes sem consentimento. Scanning não autorizado é crime.

<p align="center"> Desenvolvido por <a href="https://www.google.com/search?q=https://github.com/joaovctn">João Santos</a> 💀 </p>