using System.Net;
using PortScannerMonster.Core;
using PortScannerMonster.Models;
using PortScannerMonster.Recon;
using PortScannerMonster.Reports;

namespace PortScannerMonster.Modes
{
    public class WatchMode
    {
        private readonly ScanOptions    _opts;
        private readonly List<IPAddress> _ips;
        private readonly List<int>       _ports;
        private readonly string          _soDetectado;
        private readonly ScanContext     _ctx;
        private readonly ScanRunner      _runner;

        public WatchMode(ScanOptions opts, List<IPAddress> ips, List<int> ports,
                         string soDetectado, ScanContext ctx)
        {
            _opts        = opts;
            _ips         = ips;
            _ports       = ports;
            _soDetectado = soDetectado;
            _ctx         = ctx;
            _runner      = new ScanRunner(opts, ctx.CancellationToken);
        }

        public async Task RunAsync()
        {
            var previous  = new List<ScanResult>();
            int iteration = 1;

            while (!_ctx.CancellationToken.IsCancellationRequested)
            {
                Console.Clear();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"╔══ Watch Mode — Iteração #{iteration} — {DateTime.Now:HH:mm:ss} ══╗");
                Console.ResetColor();

                var (results, elapsed) = await _runner.RunAsync(_ips, _ports, _ctx);

                ScanContext.ClearLine();
                Console.WriteLine($"\n--- Scan em {elapsed:F2}s ---");

                await DnsResolver.ResolveHostnamesAsync(results);

                PrintDiff(previous, results);
                PrintSummaryTable(results);

                if (!string.IsNullOrEmpty(_opts.OutputFile))
                {
                    TxtReporter.Generate(_opts.OutputFile, results, _opts);
                    JsonReporter.Generate(_opts.OutputFile, results, _opts, _soDetectado);
                    CsvReporter.Generate(_opts.OutputFile, results);
                    XmlReporter.Generate(_opts.OutputFile, results, _soDetectado, elapsed);
                }

                previous = results;
                iteration++;

                for (int i = _opts.WatchInterval; i > 0 && !_ctx.CancellationToken.IsCancellationRequested; i--)
                {
                    Console.Write($"\r[*] Próxima verificação em {i}s... (Ctrl+C para sair)   ");
                    await Task.Delay(1000);
                }
                Console.WriteLine();
            }
        }

        private static void PrintDiff(List<ScanResult> previous, List<ScanResult> current)
        {
            if (!previous.Any()) return;

            var curKeys  = current.Select(Key).ToHashSet();
            var prevKeys = previous.Select(Key).ToHashSet();
            var opened   = current.Where(r => !prevKeys.Contains(Key(r))).ToList();
            var closed   = previous.Where(r => !curKeys.Contains(Key(r))).ToList();

            if (opened.Any())
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\n[+] {opened.Count} porta(s) ABERTAS:");
                foreach (var r in opened)
                    Console.WriteLine($"    {r.IP}:{r.Port}/{r.Protocol} ({r.ServiceGuess})");
                Console.ResetColor();
            }
            if (closed.Any())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n[-] {closed.Count} porta(s) FECHADAS:");
                foreach (var r in closed)
                    Console.WriteLine($"    {r.IP}:{r.Port}/{r.Protocol} ({r.ServiceGuess})");
                Console.ResetColor();
            }
            if (!opened.Any() && !closed.Any())
                Console.WriteLine("[i] Nenhuma mudança detectada.");
        }

        private static void PrintSummaryTable(List<ScanResult> results)
        {
            var open = results.Where(r => r.Status == "open")
                              .OrderBy(r => r.IP).ThenBy(r => r.Protocol).ThenBy(r => r.Port)
                              .ToList();
            if (!open.Any()) return;

            Console.WriteLine();
            Console.WriteLine("╔═════════════════╦══════╦═══════╦════════════════╦════════════════╗");
            Console.WriteLine("║ IP              ║ PROT ║ PORTA ║ SERVIÇO        ║ BANNER/VERSÃO  ║");
            Console.WriteLine("╠═════════════════╬══════╬═══════╬════════════════╬════════════════╣");
            foreach (var r in open)
            {
                string info = Grabbers.BannerGrabber.ExtractVersion(r.Banner);
                if (string.IsNullOrEmpty(info)) info = r.Banner;
                Console.ForegroundColor = r.Protocol == "UDP" ? ConsoleColor.Cyan : ConsoleColor.Green;
                Console.WriteLine($"║ {r.IP.PadRight(15)} ║ {r.Protocol.PadRight(4)} ║ {r.Port.ToString().PadRight(5)} " +
                                  $"║ {Trunc(r.ServiceGuess, 14)} ║ {Trunc(info, 14)} ║");
                Console.ResetColor();
            }
            Console.WriteLine("╚═════════════════╩══════╩═══════╩════════════════╩════════════════╝");
            Console.WriteLine($"  Total: {open.Count} porta(s) aberta(s)");
        }

        private static string Key(ScanResult r) => $"{r.IP}:{r.Protocol}:{r.Port}";
        private static string Trunc(string s, int max) =>
            string.IsNullOrEmpty(s) ? new string(' ', max) : s.Length > max ? s[..max] : s.PadRight(max);
    }
}
