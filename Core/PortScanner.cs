using System.Net;
using PortScannerMonster.Cache;
using PortScannerMonster.Grabbers;
using PortScannerMonster.Modes;
using PortScannerMonster.Models;
using PortScannerMonster.Recon;
using PortScannerMonster.Reports;
using PortScannerMonster.Security;

namespace PortScannerMonster.Core
{
    public class PortScanner
    {
        private readonly ScanOptions _opts;

        public PortScanner(ScanOptions opts) => _opts = opts;

        public async Task RunAsync()
        {
            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                Console.WriteLine("\n[!] Ctrl+C detectado. Finalizando...");
                cts.Cancel();
            };

            // ── Carrega alvos de arquivo ──────────────
            if (!string.IsNullOrEmpty(_opts.TargetsFile))
            {
                if (!File.Exists(_opts.TargetsFile))
                {
                    Console.WriteLine($"[!] Arquivo não encontrado: {_opts.TargetsFile}");
                    WaitExit(); return;
                }
                _opts.Targets.AddRange(File.ReadAllLines(_opts.TargetsFile)
                    .Where(l => !string.IsNullOrWhiteSpace(l) && !l.TrimStart().StartsWith("#")));
            }

            if (_opts.Targets.Count == 0)
            {
                Console.WriteLine("[!] Nenhum alvo especificado. Use -t <ip> ou -iL <arquivo>");
                WaitExit(); return;
            }

            // ── Resolve alvos ─────────────────────────
            var allIps = new List<IPAddress>();
            foreach (var target in _opts.Targets)
            {
                try
                {
                    var ips = await DnsResolver.ResolveTargetAsync(target);
                    if (!_opts.Quiet)
                        Console.WriteLine(target.Contains('/') || ips.Count == 1
                            ? $"[i] Alvo: {target}" + (ips.Count > 1 ? $" → {ips.Count} endereços" : $" ({ips[0]})")
                            : $"[i] Alvo: {target} ({ips[0]})");
                    allIps.AddRange(ips);
                }
                catch (Exception ex) { Console.WriteLine($"[!] Erro ao resolver '{target}': {ex.Message}"); }
            }

            if (allIps.Count == 0)
            { Console.WriteLine("[!] Nenhum IP válido encontrado."); WaitExit(); return; }

            // ── Ping sweep ────────────────────────────
            if (allIps.Count > 1)
            {
                if (!_opts.Quiet) Console.Write($"[*] Ping sweep em {allIps.Count} hosts... ");
                allIps = await PingSweeper.SweepAsync(allIps);
                if (!_opts.Quiet) Console.WriteLine($"{allIps.Count} online.");
                if (allIps.Count == 0) { Console.WriteLine("[!] Nenhum host respondeu."); WaitExit(); return; }
            }

            // ── Timeout adaptativo ────────────────────
            if (_opts.AdaptiveTimeout)
            {
                int rtt = OsDetector.MeasureRtt(allIps[0].ToString());
                if (rtt > 0)
                {
                    _opts.Timeout = Math.Max(rtt * 4, 500);
                    if (!_opts.Quiet) Console.WriteLine($"[i] RTT: {rtt}ms → timeout {_opts.Timeout}ms");
                }
            }

            // ── Traceroute ────────────────────────────
            if (_opts.RunTraceroute)
                await Traceroute.RunAsync(allIps[0], cts.Token);

            // ── Detecção de SO ────────────────────────
            string soDetectado = "";
            if (!_opts.Quiet)
            {
                Console.Write("[*] Detectando SO... ");
                soDetectado = OsDetector.Detect(allIps[0].ToString());
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(soDetectado);
                Console.ResetColor();
            }

            // ── Portas ────────────────────────────────
            var ports = _opts.GetPorts();
            if (ports == null) { WaitExit(); return; }

            if (!_opts.Quiet)
            {
                string portInfo = _opts.TopPorts > 0 ? $"top {ports.Count}" : $"{ports.Count}";
                Console.WriteLine($"[i] Hosts: {allIps.Count} | Portas: {portInfo} | " +
                                  $"Proto: {(_opts.ScanUdp ? "TCP+UDP" : "TCP")} | Conc: {_opts.Concurrency}" +
                                  (_opts.Delay > 0 ? $" | Delay: {_opts.Delay}ms" : ""));
            }

            var ctx    = new ScanContext(_opts.Concurrency, cts.Token);
            var runner = new ScanRunner(_opts, cts.Token);

            // ── Watch mode ────────────────────────────
            if (_opts.WatchInterval > 0)
            {
                var watch = new WatchMode(_opts, allIps, ports, soDetectado, ctx);
                await watch.RunAsync();
                WaitExit(); return;
            }

            // ── Scan normal ───────────────────────────
            if (!_opts.Quiet) Console.WriteLine("\n--- INICIANDO SCAN ---\n");

            var (results, elapsed) = await runner.RunAsync(allIps, ports, ctx);

            if (!_opts.Quiet) ScanContext.ClearLine();

            if (cts.IsCancellationRequested)
                Console.WriteLine($"[!] Cancelado após {ctx.ScannedPorts}/{ctx.TotalPorts} portas em {elapsed:F2}s");
            else if (!_opts.Quiet)
                Console.WriteLine($"\n--- Scan finalizado em {elapsed:F2}s ---");

            // ── DNS reverso ───────────────────────────
            if (!_opts.Quiet) Console.Write("[*] DNS reverso... ");
            await DnsResolver.ResolveHostnamesAsync(results);
            if (!_opts.Quiet) Console.WriteLine("Concluído.");

            // ── Credenciais padrão ────────────────────
            if (_opts.CheckCreds)
                await CredentialChecker.CheckAllAsync(results);

            // ── Cache e diff ──────────────────────────
            if (_opts.Cache)
            {
                string cacheKey = string.Join(",", _opts.Targets);
                var previous    = ScanCache.Load(cacheKey);
                if (previous != null)
                {
                    Console.WriteLine("\n[*] Diff com scan anterior:");
                    ScanCache.PrintDiff(previous, results);
                }
                ScanCache.Save(results, cacheKey);
            }

            // ── Tabela + relatórios ───────────────────
            PrintSummaryTable(results);

            if (!string.IsNullOrEmpty(_opts.OutputFile))
            {
                TxtReporter.Generate(_opts.OutputFile, results, _opts);
                JsonReporter.Generate(_opts.OutputFile, results, _opts, soDetectado);
                CsvReporter.Generate(_opts.OutputFile, results);
                XmlReporter.Generate(_opts.OutputFile, results, soDetectado, elapsed);
            }

            // ── Modo interativo ───────────────────────
            if (_opts.Interactive && results.Any(r => r.Status == "open"))
                new InteractiveMode(results).Run();
            else
                WaitExit();
        }

        // ─────────────────────────────────────────────
        private static void PrintSummaryTable(List<ScanResult> results)
        {
            var open = results.Where(r => r.Status == "open")
                              .OrderBy(r => r.IP).ThenBy(r => r.Protocol).ThenBy(r => r.Port)
                              .ToList();

            if (open.Count == 0) { Console.WriteLine("\n[i] Nenhuma porta aberta encontrada."); return; }

            Console.WriteLine();
            Console.WriteLine("╔═════════════════╦══════╦═══════╦════════════════╦══════════════════════╦════════════════╗");
            Console.WriteLine("║ IP              ║ PROT ║ PORTA ║ SERVIÇO        ║ HOSTNAME             ║ BANNER/VERSÃO  ║");
            Console.WriteLine("╠═════════════════╬══════╬═══════╬════════════════╬══════════════════════╬════════════════╣");

            foreach (var r in open)
            {
                string info = BannerGrabber.ExtractVersion(r.Banner);
                if (string.IsNullOrEmpty(info)) info = r.Banner;

                Console.ForegroundColor = r.Protocol == "UDP" ? ConsoleColor.Cyan : ConsoleColor.Green;
                Console.WriteLine(
                    $"║ {r.IP.PadRight(15)} ║ {r.Protocol.PadRight(4)} ║ {r.Port.ToString().PadRight(5)} " +
                    $"║ {Trunc(r.ServiceGuess, 14)} ║ {Trunc(r.Hostname, 20)} ║ {Trunc(info, 14)} ║");
                Console.ResetColor();

                if (!string.IsNullOrEmpty(r.DefaultCreds))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"║ {"".PadRight(15)} ║      ║       ║ ⚠  {Trunc(r.DefaultCreds, 54)} ║");
                    Console.ResetColor();
                }
            }

            Console.WriteLine("╚═════════════════╩══════╩═══════╩════════════════╩══════════════════════╩════════════════╝");
            Console.WriteLine($"  Total: {open.Count} porta(s) aberta(s)");
        }

        private static string Trunc(string s, int max) =>
            string.IsNullOrEmpty(s) ? new string(' ', max) : s.Length > max ? s[..max] : s.PadRight(max);

        private static void WaitExit()
        {
            Console.WriteLine("\nPressione qualquer tecla para fechar...");
            Console.ReadKey();
        }
    }
}
