using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PortScannerMonster
{
    class ScanResult
    {
        public string IP { get; set; } = "";
        public int Port { get; set; }
        public string Protocol { get; set; } = "TCP";
        public bool IsOpen { get; set; }
        public string Banner { get; set; } = "";
        public string ServiceGuess { get; set; } = "";
        public string Hostname { get; set; } = "";
    }

    class Program
    {
        static SemaphoreSlim _semaphore = new SemaphoreSlim(200);
        static ConcurrentBag<ScanResult> _results = new ConcurrentBag<ScanResult>();
        static object _lockConsole = new object();

        static List<string> _targets = new List<string>();
        static string _targetsFile = "";
        static string _portsInput = "1-1000";
        static string _outputFile = "";
        static int _timeout = 1500;
        static int _concurrency = 200;
        static int _topPorts = 0;
        static bool _verbose = false;
        static bool _quiet = false;
        static bool _scanUdp = false;
        static bool _adaptiveTimeout = false;

        static CancellationTokenSource _cts = new CancellationTokenSource();
        static int _totalPorts = 0;
        static int _scannedPorts = 0;

        // Top 100 portas mais comuns (baseado nas estatísticas do nmap)
        static readonly int[] TopPorts =
        {
            80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
            1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81,
            6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433,
            49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153,
            8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357,
            427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
            7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028,
            873, 1755, 2717, 4899, 9100, 119, 37
        };

        // ─────────────────────────────────────────
        //  MAIN
        // ─────────────────────────────────────────
        static async Task Main(string[] args)
        {
            Console.Title = "C# Port Scanner v7.0";

            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                Console.WriteLine("\n[!] Ctrl+C detectado. Finalizando scan...");
                _cts.Cancel();
            };

            if (args.Length == 0 || args.Contains("-h") || args.Contains("--help"))
            {
                ShowHelp();
                WaitExit();
                return;
            }

            ParseArguments(args);

            // Carrega alvos de arquivo se -iL foi usado
            if (!string.IsNullOrEmpty(_targetsFile))
            {
                if (!File.Exists(_targetsFile))
                {
                    Console.WriteLine($"[!] Arquivo de alvos não encontrado: {_targetsFile}");
                    WaitExit();
                    return;
                }
                var lines = File.ReadAllLines(_targetsFile)
                    .Where(l => !string.IsNullOrWhiteSpace(l) && !l.TrimStart().StartsWith("#"));
                _targets.AddRange(lines);
            }

            if (_targets.Count == 0)
            {
                Console.WriteLine("[!] Erro: Nenhum alvo especificado. Use -t <ip> ou -iL <arquivo>");
                WaitExit();
                return;
            }

            _semaphore = new SemaphoreSlim(_concurrency);

            // Resolve todos os alvos para IPs
            var allIps = new List<IPAddress>();
            foreach (var target in _targets)
            {
                try
                {
                    allIps.AddRange(await ResolveTargets(target));
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Erro ao resolver '{target}': {ex.Message}");
                }
            }

            if (allIps.Count == 0)
            {
                Console.WriteLine("[!] Erro: Nenhum endereço IP válido encontrado.");
                WaitExit();
                return;
            }

            // Ping sweep para múltiplos hosts
            if (allIps.Count > 1)
            {
                if (!_quiet) Console.Write($"[*] Ping sweep em {allIps.Count} hosts... ");
                allIps = await PingSweep(allIps);
                if (!_quiet) Console.WriteLine($"{allIps.Count} host(s) online.");

                if (allIps.Count == 0)
                {
                    Console.WriteLine("[!] Nenhum host respondeu ao ping.");
                    WaitExit();
                    return;
                }
            }

            // Timeout adaptativo
            if (_adaptiveTimeout)
            {
                int rtt = MeasureRtt(allIps[0].ToString());
                if (rtt > 0)
                {
                    _timeout = Math.Max(rtt * 4, 500);
                    if (!_quiet) Console.WriteLine($"[i] RTT médio: {rtt}ms → timeout ajustado para {_timeout}ms");
                }
            }

            // Detecção de SO
            string soDetectado = "";
            if (!_quiet)
            {
                Console.Write("[*] Detectando Sistema Operacional... ");
                soDetectado = DetectOS(allIps[0].ToString());
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(soDetectado);
                Console.ResetColor();
            }

            // Determina portas a escanear
            List<int>? portsToScan;
            if (_topPorts > 0)
            {
                portsToScan = TopPorts.Take(Math.Min(_topPorts, TopPorts.Length)).OrderBy(p => p).ToList();
                if (!_quiet) Console.WriteLine($"[i] Usando top {portsToScan.Count} portas mais comuns.");
            }
            else
            {
                portsToScan = ParsePorts(_portsInput);
                if (portsToScan == null)
                {
                    WaitExit();
                    return;
                }
            }

            int protocolCount = _scanUdp ? 2 : 1;
            _totalPorts = allIps.Count * portsToScan.Count * protocolCount;

            if (!_quiet)
            {
                Console.WriteLine($"[i] Hosts: {allIps.Count} | Portas: {portsToScan.Count} | Protocolo: {(_scanUdp ? "TCP+UDP" : "TCP")} | Concorrência: {_concurrency}");
                Console.WriteLine("\n--- INICIANDO SCAN ---\n");
            }

            var tasks = new List<Task>();
            var watch = System.Diagnostics.Stopwatch.StartNew();

            foreach (var ip in allIps)
            {
                foreach (var port in portsToScan)
                {
                    if (_cts.IsCancellationRequested) break;
                    tasks.Add(ScanPortAsync(ip, port));
                    if (_scanUdp)
                        tasks.Add(ScanPortUdpAsync(ip, port));
                }
                if (_cts.IsCancellationRequested) break;
            }

            await Task.WhenAll(tasks);
            watch.Stop();

            if (!_quiet)
                Console.Write("\r" + new string(' ', Console.WindowWidth - 1) + "\r");

            if (_cts.IsCancellationRequested)
                Console.WriteLine($"[!] Scan cancelado após {_scannedPorts}/{_totalPorts} portas em {watch.Elapsed.TotalSeconds:F2}s");
            else if (!_quiet)
                Console.WriteLine($"\n--- Scan finalizado em {watch.Elapsed.TotalSeconds:F2}s ---");

            // DNS reverso
            await ResolveHostnames();

            // Tabela resumo
            PrintSummaryTable();

            // Relatórios
            GenerateTxtReport();
            GenerateJsonReport(soDetectado);
            GenerateCsvReport();

            WaitExit();
        }

        static void WaitExit()
        {
            Console.WriteLine("\nPressione qualquer tecla para fechar...");
            Console.ReadKey();
        }

        // ─────────────────────────────────────────
        //  RESOLUÇÃO DE ALVOS
        // ─────────────────────────────────────────
        static async Task<List<IPAddress>> ResolveTargets(string target)
        {
            var result = new List<IPAddress>();

            if (target.Contains('/'))
            {
                var parts = target.Split('/');
                if (parts.Length == 2
                    && IPAddress.TryParse(parts[0], out IPAddress? baseIp)
                    && int.TryParse(parts[1], out int prefix)
                    && prefix >= 0 && prefix <= 32)
                {
                    result.AddRange(ExpandCidr(baseIp, prefix));
                    if (!_quiet) Console.WriteLine($"[i] CIDR {target} → {result.Count} endereços.");
                    return result;
                }
                throw new ArgumentException($"Notação CIDR inválida: '{target}'");
            }

            if (IPAddress.TryParse(target, out IPAddress? ip))
            {
                if (!_quiet) Console.WriteLine($"[i] Alvo: {target}");
                result.Add(ip);
                return result;
            }

            var entry = await Dns.GetHostEntryAsync(target);
            var ipv4 = entry.AddressList.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (ipv4 == null) throw new Exception("Nenhum endereço IPv4 encontrado.");
            if (!_quiet) Console.WriteLine($"[i] Alvo: {target} ({ipv4})");
            result.Add(ipv4);
            return result;
        }

        static IEnumerable<IPAddress> ExpandCidr(IPAddress baseIp, int prefix)
        {
            byte[] bytes = baseIp.GetAddressBytes();
            uint ipInt = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
            uint mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
            uint network = ipInt & mask;
            uint broadcast = network | ~mask;
            uint start = prefix < 31 ? network + 1 : network;
            uint end   = prefix < 31 ? broadcast - 1 : broadcast;

            for (uint i = start; i <= end; i++)
                yield return new IPAddress(new byte[] { (byte)(i >> 24), (byte)(i >> 16), (byte)(i >> 8), (byte)i });
        }

        // ─────────────────────────────────────────
        //  PING SWEEP
        // ─────────────────────────────────────────
        static async Task<List<IPAddress>> PingSweep(List<IPAddress> ips)
        {
            var alive = new ConcurrentBag<IPAddress>();

            await Task.WhenAll(ips.Select(async ip =>
            {
                try
                {
                    using var ping = new Ping();
                    var reply = await ping.SendPingAsync(ip, 1000);
                    if (reply.Status == IPStatus.Success)
                        alive.Add(ip);
                }
                catch { }
            }));

            return alive.OrderBy(ip => ip.ToString()).ToList();
        }

        // ─────────────────────────────────────────
        //  TIMEOUT ADAPTATIVO
        // ─────────────────────────────────────────
        static int MeasureRtt(string host)
        {
            try
            {
                using var ping = new Ping();
                var times = new List<long>();
                for (int i = 0; i < 3; i++)
                {
                    var reply = ping.Send(host, 2000);
                    if (reply.Status == IPStatus.Success)
                        times.Add(reply.RoundtripTime);
                }
                return times.Count > 0 ? (int)times.Average() : 0;
            }
            catch { return 0; }
        }

        // ─────────────────────────────────────────
        //  DNS REVERSO
        // ─────────────────────────────────────────
        static async Task ResolveHostnames()
        {
            var distinctIps = _results.Select(r => r.IP).Distinct().ToList();
            if (distinctIps.Count == 0) return;

            if (!_quiet) Console.Write("[*] Resolvendo hostnames (DNS reverso)... ");

            var resolved = new ConcurrentDictionary<string, string>();
            await Task.WhenAll(distinctIps.Select(async ip =>
            {
                try
                {
                    var entry = await Dns.GetHostEntryAsync(ip);
                    resolved[ip] = entry.HostName;
                }
                catch { resolved[ip] = ""; }
            }));

            foreach (var result in _results)
            {
                if (resolved.TryGetValue(result.IP, out var hostname))
                    result.Hostname = hostname;
            }

            if (!_quiet) Console.WriteLine("Concluído.");
        }

        // ─────────────────────────────────────────
        //  SCAN TCP
        // ─────────────────────────────────────────
        static async Task ScanPortAsync(IPAddress ip, int port)
        {
            try { await _semaphore.WaitAsync(_cts.Token); }
            catch (OperationCanceledException) { return; }

            try
            {
                if (_cts.IsCancellationRequested) return;

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                timeoutCts.CancelAfter(_timeout);

                using var client = new TcpClient();
                bool connected = false;
                try
                {
                    await client.ConnectAsync(ip, port, timeoutCts.Token);
                    connected = client.Connected;
                }
                catch { }

                if (connected)
                {
                    string rawBanner  = await GrabBanner(client, port, ip.ToString());
                    string service    = GuessService(port);
                    string version    = ExtractVersion(rawBanner);

                    _results.Add(new ScanResult
                    {
                        IP           = ip.ToString(),
                        Port         = port,
                        Protocol     = "TCP",
                        IsOpen       = true,
                        Banner       = rawBanner,
                        ServiceGuess = service
                    });

                    if (!_quiet)
                    {
                        lock (_lockConsole)
                        {
                            Console.Write("\r" + new string(' ', Console.WindowWidth - 1) + "\r");
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.Write($"[+] {ip,-15} TCP  {port.ToString().PadRight(5)} {service.PadRight(14)} ABERTA");
                            if (!string.IsNullOrEmpty(version))
                            {
                                Console.ForegroundColor = ConsoleColor.Cyan;
                                Console.Write($" | {version}");
                            }
                            else if (!string.IsNullOrEmpty(rawBanner))
                            {
                                Console.ForegroundColor = ConsoleColor.DarkGray;
                                Console.Write($" | {rawBanner.Trim()}");
                            }
                            Console.WriteLine();
                            Console.ResetColor();
                        }
                    }
                }
                else if (_verbose && !_quiet)
                {
                    lock (_lockConsole)
                    {
                        Console.Write("\r" + new string(' ', Console.WindowWidth - 1) + "\r");
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.WriteLine($"[-] {ip,-15} TCP  {port.ToString().PadRight(5)} {GuessService(port).PadRight(14)} FECHADA");
                        Console.ResetColor();
                    }
                }
            }
            catch { }
            finally
            {
                _semaphore.Release();
                UpdateProgress();
            }
        }

        // ─────────────────────────────────────────
        //  SCAN UDP
        // ─────────────────────────────────────────
        static async Task ScanPortUdpAsync(IPAddress ip, int port)
        {
            try { await _semaphore.WaitAsync(_cts.Token); }
            catch (OperationCanceledException) { return; }

            try
            {
                if (_cts.IsCancellationRequested) return;

                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = _timeout;

                byte[] probe = GetUdpProbe(port);
                await udp.SendAsync(probe, probe.Length, new IPEndPoint(ip, port));

                try
                {
                    var remoteEp = new IPEndPoint(IPAddress.Any, 0);
                    byte[] response = udp.Receive(ref remoteEp);

                    // Recebeu resposta → aberta
                    string service = GuessService(port);
                    string banner  = Encoding.ASCII.GetString(response).Split('\n')[0].Trim();

                    _results.Add(new ScanResult
                    {
                        IP           = ip.ToString(),
                        Port         = port,
                        Protocol     = "UDP",
                        IsOpen       = true,
                        Banner       = banner,
                        ServiceGuess = service
                    });

                    if (!_quiet)
                    {
                        lock (_lockConsole)
                        {
                            Console.Write("\r" + new string(' ', Console.WindowWidth - 1) + "\r");
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.WriteLine($"[+] {ip,-15} UDP  {port.ToString().PadRight(5)} {service.PadRight(14)} ABERTA");
                            Console.ResetColor();
                        }
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
                {
                    // ICMP port unreachable → fechada
                    if (_verbose && !_quiet)
                    {
                        lock (_lockConsole)
                        {
                            Console.Write("\r" + new string(' ', Console.WindowWidth - 1) + "\r");
                            Console.ForegroundColor = ConsoleColor.DarkGray;
                            Console.WriteLine($"[-] {ip,-15} UDP  {port.ToString().PadRight(5)} {GuessService(port).PadRight(14)} FECHADA");
                            Console.ResetColor();
                        }
                    }
                }
                // Timeout → open|filtered, ignorado silenciosamente
            }
            catch { }
            finally
            {
                _semaphore.Release();
                UpdateProgress();
            }
        }

        static byte[] GetUdpProbe(int port) => port switch
        {
            // DNS version.bind query
            53  => new byte[]
            {
                0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e,
                0x64, 0x00, 0x00, 0x10, 0x00, 0x03
            },
            // SNMP GetRequest (community "public")
            161 => new byte[]
            {
                0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
                0x63, 0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
                0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x05, 0x00
            },
            // NTP client request
            123 => new byte[]
            {
                0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            },
            _   => Array.Empty<byte>()
        };

        static void UpdateProgress()
        {
            int scanned = Interlocked.Increment(ref _scannedPorts);
            if (!_quiet)
            {
                lock (_lockConsole)
                {
                    Console.Write($"\r[*] Progresso: {scanned}/{_totalPorts} ({scanned * 100 / _totalPorts}%)...");
                }
            }
        }

        // ─────────────────────────────────────────
        //  BANNER GRABBING
        // ─────────────────────────────────────────
        static async Task<string> GrabBanner(TcpClient client, int port, string host)
        {
            try
            {
                Stream stream;

                if (port == 443 || port == 8443)
                {
                    var sslStream = new SslStream(client.GetStream(), false,
                        (sender, cert, chain, errors) => true);
                    await sslStream.AuthenticateAsClientAsync(host);
                    stream = sslStream;
                }
                else
                {
                    stream = client.GetStream();
                }

                stream.ReadTimeout = 1000;

                // Probes ativos por protocolo
                byte[]? probe = port switch
                {
                    80 or 443 or 8080 or 8443
                        => Encoding.ASCII.GetBytes($"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
                    25 or 587
                        => Encoding.ASCII.GetBytes("EHLO scanner\r\n"),
                    110 => Encoding.ASCII.GetBytes("CAPA\r\n"),
                    143 => Encoding.ASCII.GetBytes("a001 CAPABILITY\r\n"),
                    6379 => Encoding.ASCII.GetBytes("PING\r\n"),
                    _   => null
                };

                if (probe != null)
                    await stream.WriteAsync(probe, 0, probe.Length);

                byte[] buffer  = new byte[1024];
                bool tryRead   = port == 443 || port == 8443;

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
            return match.Success ? match.Value : "";
        }

        // ─────────────────────────────────────────
        //  TABELA RESUMO
        // ─────────────────────────────────────────
        static void PrintSummaryTable()
        {
            var open = _results.OrderBy(r => r.IP).ThenBy(r => r.Protocol).ThenBy(r => r.Port).ToList();

            if (open.Count == 0)
            {
                Console.WriteLine("\n[i] Nenhuma porta aberta encontrada.");
                return;
            }

            Console.WriteLine();
            Console.WriteLine("╔═════════════════╦══════╦═══════╦════════════════╦══════════════════════╦════════════════╗");
            Console.WriteLine("║ IP              ║ PROT ║ PORTA ║ SERVIÇO        ║ HOSTNAME             ║ BANNER/VERSÃO  ║");
            Console.WriteLine("╠═════════════════╬══════╬═══════╬════════════════╬══════════════════════╬════════════════╣");

            foreach (var r in open)
            {
                string ip       = r.IP.PadRight(15);
                string proto    = r.Protocol.PadRight(4);
                string port     = r.Port.ToString().PadRight(5);
                string service  = Truncate(r.ServiceGuess, 14);
                string hostname = Truncate(r.Hostname, 20);
                string info     = Truncate(ExtractVersion(r.Banner).Length > 0 ? ExtractVersion(r.Banner) : r.Banner, 14);

                Console.ForegroundColor = r.Protocol == "UDP" ? ConsoleColor.Cyan : ConsoleColor.Green;
                Console.WriteLine($"║ {ip} ║ {proto} ║ {port} ║ {service} ║ {hostname} ║ {info} ║");
                Console.ResetColor();
            }

            Console.WriteLine("╚═════════════════╩══════╩═══════╩════════════════╩══════════════════════╩════════════════╝");
            Console.WriteLine($"  Total: {open.Count} porta(s) aberta(s)");
        }

        static string Truncate(string s, int maxLen)
        {
            if (string.IsNullOrEmpty(s)) return new string(' ', maxLen);
            if (s.Length > maxLen) return s[..maxLen];
            return s.PadRight(maxLen);
        }

        // ─────────────────────────────────────────
        //  RELATÓRIOS
        // ─────────────────────────────────────────
        static void GenerateTxtReport()
        {
            if (string.IsNullOrEmpty(_outputFile)) return;
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine("--- RELATÓRIO DE SCAN ---");
                sb.AppendLine($"Data: {DateTime.Now}");
                sb.AppendLine($"Alvos: {string.Join(", ", _targets)}");
                sb.AppendLine($"Portas Abertas: {_results.Count}");
                sb.AppendLine();
                sb.AppendLine($"{"IP",-16} {"PROT",-5} {"PORTA",-7} {"SERVIÇO",-16} {"HOSTNAME",-25} BANNER");
                sb.AppendLine(new string('-', 95));

                foreach (var r in _results.OrderBy(r => r.IP).ThenBy(r => r.Port))
                    sb.AppendLine($"{r.IP,-16} {r.Protocol,-5} {r.Port,-7} {r.ServiceGuess,-16} {r.Hostname,-25} {r.Banner}");

                File.WriteAllText(_outputFile, sb.ToString());
                Console.WriteLine($"\n[+] Relatório TXT salvo em: {Path.GetFullPath(_outputFile)}");
            }
            catch (Exception ex) { Console.WriteLine($"[!] Erro ao salvar TXT: {ex.Message}"); }
        }

        static void GenerateJsonReport(string soDetectado)
        {
            if (string.IsNullOrEmpty(_outputFile)) return;
            try
            {
                string jsonFile = Path.ChangeExtension(_outputFile, ".json");

                var report = new
                {
                    scan_date      = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss"),
                    os_fingerprint = soDetectado,
                    targets        = _targets,
                    open_ports     = _results
                        .OrderBy(r => r.IP).ThenBy(r => r.Port)
                        .Select(r => new
                        {
                            ip       = r.IP,
                            hostname = r.Hostname,
                            protocol = r.Protocol,
                            port     = r.Port,
                            service  = r.ServiceGuess,
                            banner   = r.Banner
                        }).ToList()
                };

                File.WriteAllText(jsonFile, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
                Console.WriteLine($"[+] Relatório JSON salvo em: {jsonFile}");
            }
            catch (Exception ex) { Console.WriteLine($"[!] Erro ao salvar JSON: {ex.Message}"); }
        }

        static void GenerateCsvReport()
        {
            if (string.IsNullOrEmpty(_outputFile)) return;
            try
            {
                string csvFile = Path.ChangeExtension(_outputFile, ".csv");
                var sb = new StringBuilder();
                sb.AppendLine("IP,Hostname,Protocol,Port,Service,Banner");

                foreach (var r in _results.OrderBy(r => r.IP).ThenBy(r => r.Port))
                {
                    string banner = r.Banner.Replace("\"", "\"\"");
                    sb.AppendLine($"\"{r.IP}\",\"{r.Hostname}\",\"{r.Protocol}\",{r.Port},\"{r.ServiceGuess}\",\"{banner}\"");
                }

                File.WriteAllText(csvFile, sb.ToString());
                Console.WriteLine($"[+] Relatório CSV salvo em: {csvFile}");
            }
            catch (Exception ex) { Console.WriteLine($"[!] Erro ao salvar CSV: {ex.Message}"); }
        }

        // ─────────────────────────────────────────
        //  HELP / ARGUMENTOS
        // ─────────────────────────────────────────
        static void ShowHelp()
        {
            Console.WriteLine(@"
USO: scanner.exe [opções]

OPÇÕES:
  -t <ip/dominio/cidr>   Define o alvo (pode ser repetido)
                          Ex: 192.168.1.1 | scanme.nmap.org | 192.168.1.0/24
  -iL <arquivo>          Carrega alvos de um arquivo (um por linha, # = comentário)
  -p <portas>            Portas a escanear (Padrão: 1-1000)
                          Ex: -p 22,80,443 | -p 1-65535 | -p all
  --top-ports <N>        Escaneia as N portas mais comuns (máx: 100)
  -o <arquivo>           Salva resultado em .txt, .json e .csv
  -timeout <ms>          Tempo limite por porta (Padrão: 1500ms)
  --adaptive-timeout     Ajusta timeout automaticamente com base no RTT
  -c <número>            Concorrência máxima (Padrão: 200)
  --udp                  Inclui scan UDP além do TCP
  -v                     Modo verboso: exibe também portas fechadas
  -q                     Modo silencioso: exibe apenas portas abertas

EXEMPLOS:
  scanner.exe -t scanme.nmap.org --top-ports 100
  scanner.exe -t 192.168.1.0/24 -p 22,80,443 -o resultado.txt
  scanner.exe -iL targets.txt -p all -c 500 --udp
  scanner.exe -t 10.0.0.1 -p 1-65535 --adaptive-timeout -v
  scanner.exe -t 10.0.0.1 -t 10.0.0.2 -p 80,443
            ");
        }

        static void ParseArguments(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-t":
                        if (i + 1 < args.Length) _targets.Add(args[++i]);
                        else Console.WriteLine("[!] Aviso: -t requer um valor.");
                        break;
                    case "-iL":
                        if (i + 1 < args.Length) _targetsFile = args[++i];
                        else Console.WriteLine("[!] Aviso: -iL requer um valor.");
                        break;
                    case "-p":
                        if (i + 1 < args.Length) _portsInput = args[++i];
                        else Console.WriteLine("[!] Aviso: -p requer um valor.");
                        break;
                    case "--top-ports":
                        if (i + 1 < args.Length) int.TryParse(args[++i], out _topPorts);
                        else Console.WriteLine("[!] Aviso: --top-ports requer um valor.");
                        break;
                    case "-o":
                        if (i + 1 < args.Length) _outputFile = args[++i];
                        else Console.WriteLine("[!] Aviso: -o requer um valor.");
                        break;
                    case "-timeout":
                        if (i + 1 < args.Length) int.TryParse(args[++i], out _timeout);
                        else Console.WriteLine("[!] Aviso: -timeout requer um valor.");
                        break;
                    case "--adaptive-timeout":
                        _adaptiveTimeout = true;
                        break;
                    case "-c":
                        if (i + 1 < args.Length) int.TryParse(args[++i], out _concurrency);
                        else Console.WriteLine("[!] Aviso: -c requer um valor.");
                        break;
                    case "--udp":
                        _scanUdp = true;
                        break;
                    case "-v":
                        _verbose = true;
                        break;
                    case "-q":
                        _quiet = true;
                        break;
                }
            }
        }

        // ─────────────────────────────────────────
        //  PARSE DE PORTAS
        // ─────────────────────────────────────────
        static List<int>? ParsePorts(string input)
        {
            if (input.ToLower() == "all") return Enumerable.Range(1, 65535).ToList();

            var result = new HashSet<int>();
            foreach (var part in input.Split(','))
            {
                if (part.Contains("-"))
                {
                    var range = part.Split('-');
                    if (range.Length != 2
                        || !int.TryParse(range[0], out int start)
                        || !int.TryParse(range[1], out int end))
                    {
                        Console.WriteLine($"[!] Erro: Faixa inválida: '{part}'");
                        return null;
                    }
                    if (start > end || start < 1 || end > 65535)
                    {
                        Console.WriteLine($"[!] Erro: Faixa fora do intervalo (1-65535): '{part}'");
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

        // ─────────────────────────────────────────
        //  SERVIÇOS E OS
        // ─────────────────────────────────────────
        static string GuessService(int port) => port switch
        {
            21    => "FTP",
            22    => "SSH",
            23    => "Telnet",
            25    => "SMTP",
            53    => "DNS",
            67    => "DHCP",
            68    => "DHCP-Client",
            69    => "TFTP",
            79    => "Finger",
            80    => "HTTP",
            88    => "Kerberos",
            110   => "POP3",
            111   => "RPC",
            119   => "NNTP",
            123   => "NTP",
            135   => "MS-RPC",
            137   => "NetBIOS-NS",
            138   => "NetBIOS-DGM",
            139   => "NetBIOS",
            143   => "IMAP",
            161   => "SNMP",
            162   => "SNMP-Trap",
            179   => "BGP",
            389   => "LDAP",
            443   => "HTTPS",
            445   => "SMB",
            514   => "Syslog",
            515   => "LPD",
            548   => "AFP",
            554   => "RTSP",
            587   => "SMTP-TLS",
            636   => "LDAPS",
            993   => "IMAPS",
            995   => "POP3S",
            1433  => "MSSQL",
            1521  => "Oracle",
            1723  => "PPTP",
            2049  => "NFS",
            3306  => "MySQL",
            3389  => "RDP",
            5060  => "SIP",
            5432  => "PostgreSQL",
            5900  => "VNC",
            6379  => "Redis",
            8080  => "HTTP-Alt",
            8443  => "HTTPS-Alt",
            9200  => "Elasticsearch",
            27017 => "MongoDB",
            _     => "Desconhecido"
        };

        static string DetectOS(string host)
        {
            try
            {
                using var ping = new Ping();
                PingReply reply = ping.Send(host, 2000);
                if (reply.Status == IPStatus.Success)
                {
                    if (reply.Options == null) return "Linux/Unix (TTL Inacessível)";
                    int ttl = reply.Options.Ttl;
                    if (ttl <= 64)  return $"Linux/Unix (TTL={ttl})";
                    if (ttl <= 128) return $"Windows (TTL={ttl})";
                    return $"Cisco/Network (TTL={ttl})";
                }
                return $"Falha no Ping ({reply.Status})";
            }
            catch { return "Desconhecido (Erro ICMP)"; }
        }
    }
}
