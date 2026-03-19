using System.Text.Json;
using System.Text.RegularExpressions;
using PortScannerMonster.Models;

namespace PortScannerMonster.Cache
{
    public static class ScanCache
    {
        private static string GetPath(string target)
        {
            string dir  = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "PortScanner", "cache");
            Directory.CreateDirectory(dir);
            string safe = Regex.Replace(target, @"[^\w\-.]", "_");
            return Path.Combine(dir, $"{safe}.json");
        }

        public static void Save(List<ScanResult> results, string target)
        {
            try
            {
                var data = new
                {
                    scan_date = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss"),
                    target,
                    results   = results.Select(r => new
                        { r.IP, r.Port, r.Protocol, r.ServiceGuess, r.Banner, r.Hostname })
                };
                File.WriteAllText(GetPath(target),
                    JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
                Console.WriteLine($"[i] Cache salvo em: {GetPath(target)}");
            }
            catch { }
        }

        public static List<ScanResult>? Load(string target)
        {
            try
            {
                string path = GetPath(target);
                if (!File.Exists(path)) return null;

                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                string? date  = doc.RootElement.GetProperty("scan_date").GetString();
                Console.WriteLine($"[i] Cache carregado (scan de {date})");

                return doc.RootElement.GetProperty("results").EnumerateArray().Select(e => new ScanResult
                {
                    IP           = e.GetProperty("IP").GetString()           ?? "",
                    Port         = e.GetProperty("Port").GetInt32(),
                    Protocol     = e.GetProperty("Protocol").GetString()     ?? "TCP",
                    ServiceGuess = e.GetProperty("ServiceGuess").GetString() ?? "",
                    Banner       = e.GetProperty("Banner").GetString()       ?? "",
                    Hostname     = e.GetProperty("Hostname").GetString()     ?? "",
                    Status       = "open"
                }).ToList();
            }
            catch { return null; }
        }

        public static void PrintDiff(List<ScanResult> previous, List<ScanResult> current)
        {
            var curKeys  = current.Select(Key).ToHashSet();
            var prevKeys = previous.Select(Key).ToHashSet();
            var opened   = current.Where(r => !prevKeys.Contains(Key(r))).ToList();
            var closed   = previous.Where(r => !curKeys.Contains(Key(r))).ToList();

            if (!opened.Any() && !closed.Any())
            { Console.WriteLine("  Nenhuma mudança desde o último scan."); return; }

            if (opened.Any())
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  [+] {opened.Count} porta(s) abertas desde o último scan:");
                foreach (var r in opened)
                    Console.WriteLine($"      {r.IP}:{r.Port}/{r.Protocol} ({r.ServiceGuess})");
                Console.ResetColor();
            }
            if (closed.Any())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  [-] {closed.Count} porta(s) fechadas desde o último scan:");
                foreach (var r in closed)
                    Console.WriteLine($"      {r.IP}:{r.Port}/{r.Protocol} ({r.ServiceGuess})");
                Console.ResetColor();
            }
        }

        private static string Key(ScanResult r) => $"{r.IP}:{r.Protocol}:{r.Port}";
    }
}
