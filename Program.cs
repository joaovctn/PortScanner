#nullable disable
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace PortScannerMonster
{
    class ScanResult
    {
        public int Port { get; set; }
        public bool IsOpen { get; set; }
        public string Banner { get; set; }
        public string ServiceGuess { get; set; }
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

            // 1. INPUT
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

            // 2. RECON (DNS + SO)
            IPAddress ipAddress = null;
            try
            {
                var entry = await Dns.GetHostEntryAsync(_target);
                ipAddress = entry.AddressList.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork);
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

            var portsToScan = ParsePorts(_portsInput);
            Console.WriteLine($"[i] Portas: {portsToScan.Count} portas selecionadas.");

            // 3. SCANNING (Ação)
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

            // 4. REPORTING (Agora sim, com a lista cheia)
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
                        string rawBanner = await GrabBanner(client, port, ip.ToString());
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
                var stream = client.GetStream();
                byte[] buffer = new byte[1024];
                stream.ReadTimeout = 1000;

                // Trigger HTTP
                if (port == 80 || port == 443 || port == 8080)
                {
                    byte[] req = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n");
                    await stream.WriteAsync(req, 0, req.Length);
                }

                if (stream.CanRead)
                {
                    await Task.Delay(200);
                    if (client.Available > 0)
                    {
                        int len = await stream.ReadAsync(buffer, 0, buffer.Length);
                        return Encoding.ASCII.GetString(buffer, 0, len).Split('\n')[0].Trim();
                    }
                }
            }
            catch { }
            return "";
        }

        static string ExtractVersion(string banner)
        {
            if (string.IsNullOrEmpty(banner)) return "";

            var match = Regex.Match(banner, @"([a-zA-Z0-9_\-]+)\/([\d\.]+[a-z]?)");
            if (match.Success)
            {
                return match.Value;
            }
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
                {
                    sb.AppendLine($"{res.Port}\t{res.ServiceGuess}\t{res.Banner}");
                }

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
                switch (args[i])
                {
                    case "-t": _target = args[++i]; break;
                    case "-p": _portsInput = args[++i]; break;
                    case "-o": _outputFile = args[++i]; break;
                    case "-timeout": int.TryParse(args[++i], out _timeout); break;
                }
            }
        }

        static List<int> ParsePorts(string input)
        {
            if (input.ToLower() == "all") return Enumerable.Range(1, 65535).ToList();
            var result = new HashSet<int>();
            var parts = input.Split(',');
            foreach (var part in parts)
            {
                if (part.Contains("-"))
                {
                    var range = part.Split('-');
                    int start = int.Parse(range[0]), end = int.Parse(range[1]);
                    for (int i = start; i <= end; i++) result.Add(i);
                }
                else result.Add(int.Parse(part));
            }
            return result.OrderBy(x => x).ToList();
        }

        static string GuessService(int port)
        {
            return port switch
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
        }
        static string DetectOS(string host)
        {
            try
            {
                using (Ping ping = new Ping())
                {
                    PingReply reply = ping.Send(host, 2000);

                    if (reply.Status == IPStatus.Success)
                    {
                        if (reply.Options == null)
                        {
                            return "Linux/Unix (TTL Inacessível, mas Online)";
                        }

                        int ttl = reply.Options.Ttl;
                        if (ttl <= 64) return $"Linux/Unix (TTL={ttl})";
                        if (ttl <= 128) return $"Windows (TTL={ttl})";
                        return $"Cisco/Network (TTL={ttl})";
                    }

                    return $"Falha no Ping ({reply.Status})";
                }
            }
            catch (Exception ex)
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
            sb.AppendLine($"  \"target\": \"{_target}\",");
            sb.AppendLine($"  \"scan_date\": \"{DateTime.Now:yyyy-MM-ddTHH:mm:ss}\",");
            sb.AppendLine($"  \"os_fingerprint\": \"{soDetectado}\",");
            sb.AppendLine("  \"open_ports\": [");

            var ordered = _results.OrderBy(r => r.Port).ToList();
            for (int i = 0; i < ordered.Count; i++)
            {
                var r = ordered[i];
                sb.Append($"    {{ \"port\": {r.Port}, \"service\": \"{r.ServiceGuess}\", \"banner\": \"{EscapeJson(r.Banner)}\" }}");

                if (i < ordered.Count - 1) sb.AppendLine(",");
                else sb.AppendLine("");
            }

            sb.AppendLine("  ]");
            sb.AppendLine("}");

            File.WriteAllText(jsonFile, sb.ToString());
            Console.WriteLine($"[+] Relatório JSON salvo em: {jsonFile}");
        }

        static string EscapeJson(string s)
        {
            if (s == null) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", "");
        }
    }
}