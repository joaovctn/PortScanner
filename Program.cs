using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace PortScannerMonster
{
    class ScanResult
    {
        public int Port { get; set; }
        public bool IsOpen { get; set; }
        public string Banner { get; set; } = "";
        public string ServiceGuess { get; set; } = "";
    }

    class Program
    {
        static SemaphoreSlim _semaphore = new SemaphoreSlim(200);
        static List<ScanResult> _results = new List<ScanResult>();
        static object _lockConsole = new object();
        static object _lockList = new object();

        static string _target = "";
        static string _portsInput = "1-1000";
        static string _outputFile = "";
        static int _timeout = 1500;

        static async Task Main(string[] args)
        {
            Console.Title = "C# Red Team Scanner v5.0 (Final)";

            if (args.Length == 0 || args.Contains("-h") || args.Contains("--help"))
            {
                ShowHelp();
                return;
            }

            ParseArguments(args);

            if (string.IsNullOrEmpty(_target))
            {
                Console.WriteLine("[!] Erro: Alvo não especificado. Use -t <ip>");
                return;
            }

            // RECON (DNS + SO)
            IPAddress? ipAddress = null;
            try
            {
                var entry = await Dns.GetHostEntryAsync(_target);
                ipAddress = entry.AddressList.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork);

                // Fix #1: ipAddress pode ser null se o host não tiver IPv4
                if (ipAddress == null)
                {
                    Console.WriteLine("[!] Erro: Nenhum endereço IPv4 encontrado para o alvo.");
                    return;
                }

                Console.WriteLine($"[i] Alvo: {_target} ({ipAddress})");
            }
            catch
            {
                Console.WriteLine("[!] Erro: DNS falhou.");
                return;
            }

            Console.Write("[*] Detectando Sistema Operacional... ");
            string soDetectado = DetectOS(_target);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(soDetectado);
            Console.ResetColor();

            // Fix #3: ParsePorts agora retorna null em caso de erro
            var portsToScan = ParsePorts(_portsInput);
            if (portsToScan == null) return;

            Console.WriteLine($"[i] Portas: {portsToScan.Count} portas selecionadas.");

            Console.WriteLine("\n--- INICIANDO SCAN ---\n");

            var tasks = new List<Task>();
            var watch = System.Diagnostics.Stopwatch.StartNew();

            foreach (var port in portsToScan)
            {
                tasks.Add(ScanPortAsync(ipAddress, port));
            }

            await Task.WhenAll(tasks);
            watch.Stop();

            Console.WriteLine($"\n--- Scan finalizado em {watch.Elapsed.TotalSeconds:F2}s ---");

            GenerateReport();
            GenerateJsonReport(soDetectado);
        }

        static async Task ScanPortAsync(IPAddress ip, int port)
        {
            await _semaphore.WaitAsync();
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    var connectTask = client.ConnectAsync(ip, port);
                    var timeoutTask = Task.Delay(_timeout);

                    if (await Task.WhenAny(connectTask, timeoutTask) == connectTask && client.Connected)
                    {
                        string rawBanner = await GrabBanner(client, port, _target);
                        string serviceName = GuessService(port);
                        string version = ExtractVersion(rawBanner);

                        lock (_lockList)
                        {
                            _results.Add(new ScanResult
                            {
                                Port = port,
                                IsOpen = true,
                                Banner = rawBanner,
                                ServiceGuess = serviceName
                            });
                        }

                        lock (_lockConsole)
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.Write($"[+] {port.ToString().PadRight(5)} {serviceName.PadRight(10)} ABERTA");

                            if (!string.IsNullOrEmpty(version))
                            {
                                Console.ForegroundColor = ConsoleColor.Cyan;
                                Console.Write($" | Versão: {version}");
                            }
                            else if (!string.IsNullOrEmpty(rawBanner))
                            {
                                Console.ForegroundColor = ConsoleColor.DarkGray;
                                Console.Write($" | Banner: {rawBanner.Trim()}");
                            }
                            Console.WriteLine();
                            Console.ResetColor();
                        }
                    }
                    else
                    {
                        // Fix #5: Suprime exceção não observada da connectTask abandonada
                        _ = connectTask.ContinueWith(_ => { }, TaskContinuationOptions.OnlyOnFaulted);
                    }
                }
            }
            catch { }
            finally
            {
                _semaphore.Release();
            }
        }

        // --- HELPERS ---

        static async Task<string> GrabBanner(TcpClient client, int port, string host)
        {
            try
            {
                Stream stream;

                // Fix #4: Porta 443 usa TLS — SslStream em vez de HTTP puro
                if (port == 443)
                {
                    var sslStream = new SslStream(client.GetStream(), false,
                        (sender, cert, chain, errors) => true); // Aceita qualquer certificado
                    await sslStream.AuthenticateAsClientAsync(host);
                    stream = sslStream;
                }
                else
                {
                    stream = client.GetStream();
                }

                stream.ReadTimeout = 1000;

                if (port == 80 || port == 443 || port == 8080)
                {
                    byte[] req = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
                    await stream.WriteAsync(req, 0, req.Length);
                }

                byte[] buffer = new byte[1024];

                // Para SSL, client.Available não reflete dados descriptografados — tenta ler direto
                bool tryRead = port == 443;

                if (!tryRead)
                {
                    await Task.Delay(200);
                    tryRead = client.Available > 0;
                }

                if (tryRead)
                {
                    int len = await stream.ReadAsync(buffer, 0, buffer.Length);
                    if (len > 0)
                        return Encoding.ASCII.GetString(buffer, 0, len).Split('\n')[0].Trim();
                }
            }
            catch { }
            return "";
        }

        static string ExtractVersion(string banner)
        {
            if (string.IsNullOrEmpty(banner)) return "";
            var match = Regex.Match(banner, @"([a-zA-Z0-9_\-]+)\/([\d\.]+[a-z]?)");
            if (match.Success) return match.Value;
            return "";
        }

        static void GenerateReport()
        {
            if (string.IsNullOrEmpty(_outputFile)) return;
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine($"--- RELATÓRIO DE SCAN: {_target} ---");
                sb.AppendLine($"Data: {DateTime.Now}");
                sb.AppendLine($"Portas Abertas: {_results.Count}");
                sb.AppendLine("PORTA\tSERVIÇO\t\tBANNER / VERSÃO");
                sb.AppendLine("-----\t-------\t\t---------------");

                foreach (var res in _results.OrderBy(r => r.Port))
                    sb.AppendLine($"{res.Port}\t{res.ServiceGuess}\t{res.Banner}");

                File.WriteAllText(_outputFile, sb.ToString());
                Console.WriteLine($"[+] Relatório salvo com sucesso em: {Path.GetFullPath(_outputFile)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Erro ao salvar relatório: {ex.Message}");
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine(@"
USO: scanner.exe [opções]

OPÇÕES:
  -t <ip/dominio>    Define o alvo (Obrigatório)
  -p <portas>        Define as portas (Padrão: 1-1000)
                     Ex: -p 22,80,443 ou -p 1-65535 ou -p all
  -o <arquivo>       Salva o resultado em arquivo txt
  -timeout <ms>      Define o tempo limite (Padrão: 1500ms)

EXEMPLOS:
  scanner.exe -t scanme.nmap.org
  scanner.exe -t 192.168.1.1 -p all -o relatorio_server.txt
            ");
        }

        static void ParseArguments(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                // Fix #2: Verificação de bounds para evitar IndexOutOfRangeException
                switch (args[i])
                {
                    case "-t":
                        if (i + 1 < args.Length) _target = args[++i];
                        else Console.WriteLine("[!] Aviso: -t requer um valor.");
                        break;
                    case "-p":
                        if (i + 1 < args.Length) _portsInput = args[++i];
                        else Console.WriteLine("[!] Aviso: -p requer um valor.");
                        break;
                    case "-o":
                        if (i + 1 < args.Length) _outputFile = args[++i];
                        else Console.WriteLine("[!] Aviso: -o requer um valor.");
                        break;
                    case "-timeout":
                        if (i + 1 < args.Length) int.TryParse(args[++i], out _timeout);
                        else Console.WriteLine("[!] Aviso: -timeout requer um valor.");
                        break;
                }
            }
        }

        // Fix #3: Usa TryParse, valida range (1-65535), retorna null em erro
        static List<int>? ParsePorts(string input)
        {
            if (input.ToLower() == "all") return Enumerable.Range(1, 65535).ToList();

            var result = new HashSet<int>();
            var parts = input.Split(',');

            foreach (var part in parts)
            {
                if (part.Contains("-"))
                {
                    var range = part.Split('-');
                    if (range.Length != 2
                        || !int.TryParse(range[0], out int start)
                        || !int.TryParse(range[1], out int end))
                    {
                        Console.WriteLine($"[!] Erro: Faixa de porta inválida: '{part}'");
                        return null;
                    }
                    if (start > end || start < 1 || end > 65535)
                    {
                        Console.WriteLine($"[!] Erro: Faixa fora do intervalo válido (1-65535): '{part}'");
                        return null;
                    }
                    for (int i = start; i <= end; i++) result.Add(i);
                }
                else
                {
                    if (!int.TryParse(part, out int p) || p < 1 || p > 65535)
                    {
                        Console.WriteLine($"[!] Erro: Porta inválida: '{part}'");
                        return null;
                    }
                    result.Add(p);
                }
            }

            return result.OrderBy(x => x).ToList();
        }

        static string GuessService(int port) => port switch
        {
            21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 => "SMTP",
            53 => "DNS",
            80 => "HTTP",
            443 => "HTTPS",
            3306 => "MySQL",
            3389 => "RDP",
            8080 => "HTTP-Proxy",
            _ => "Desconhecido"
        };

        static string DetectOS(string host)
        {
            try
            {
                using (Ping ping = new Ping())
                {
                    PingReply reply = ping.Send(host, 2000);

                    if (reply.Status == IPStatus.Success)
                    {
                        if (reply.Options == null) return "Linux/Unix (TTL Inacessível, mas Online)";
                        int ttl = reply.Options.Ttl;
                        if (ttl <= 64) return $"Linux/Unix (TTL={ttl})";
                        if (ttl <= 128) return $"Windows (TTL={ttl})";
                        return $"Cisco/Network (TTL={ttl})";
                    }

                    return $"Falha no Ping ({reply.Status})";
                }
            }
            catch // Fix #7: Removido 'ex' não utilizado
            {
                return "Desconhecido (Erro ICMP)";
            }
        }

        static void GenerateJsonReport(string soDetectado)
        {
            if (string.IsNullOrEmpty(_outputFile)) return;

            string jsonFile = Path.ChangeExtension(_outputFile, ".json");
            var sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine($"  \"target\": \"{EscapeJson(_target)}\",");
            sb.AppendLine($"  \"scan_date\": \"{DateTime.Now:yyyy-MM-ddTHH:mm:ss}\",");
            sb.AppendLine($"  \"os_fingerprint\": \"{EscapeJson(soDetectado)}\",");
            sb.AppendLine("  \"open_ports\": [");

            var ordered = _results.OrderBy(r => r.Port).ToList();
            for (int i = 0; i < ordered.Count; i++)
            {
                var r = ordered[i];
                sb.Append($"    {{ \"port\": {r.Port}, \"service\": \"{EscapeJson(r.ServiceGuess)}\", \"banner\": \"{EscapeJson(r.Banner)}\" }}");
                if (i < ordered.Count - 1) sb.AppendLine(",");
                else sb.AppendLine("");
            }

            sb.AppendLine("  ]");
            sb.AppendLine("}");

            File.WriteAllText(jsonFile, sb.ToString());
            Console.WriteLine($"[+] Relatório JSON salvo em: {jsonFile}");
        }

        // Fix #8: EscapeJson completo — trata todos os caracteres especiais JSON
        static string EscapeJson(string s)
        {
            if (s == null) return "";
            var sb = new StringBuilder();
            foreach (char c in s)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"':  sb.Append("\\\""); break;
                    case '\n': sb.Append("\\n");  break;
                    case '\r': sb.Append("\\r");  break;
                    case '\t': sb.Append("\\t");  break;
                    case '\b': sb.Append("\\b");  break;
                    case '\f': sb.Append("\\f");  break;
                    default:
                        if (c < 0x20)
                            sb.Append($"\\u{(int)c:x4}");
                        else
                            sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }
    }
}
