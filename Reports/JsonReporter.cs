using System.Text.Json;
using PortScannerMonster.Models;

namespace PortScannerMonster.Reports
{
    public static class JsonReporter
    {
        public static void Generate(string outputFile, List<ScanResult> results, ScanOptions opts, string osFingerprint)
        {
            try
            {
                string path = Path.ChangeExtension(outputFile, ".json");

                var report = new
                {
                    scan_date      = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss"),
                    os_fingerprint = osFingerprint,
                    targets        = opts.Targets,
                    open_ports     = results.OrderBy(r => r.IP).ThenBy(r => r.Port).Select(r => new
                    {
                        ip            = r.IP,
                        hostname      = r.Hostname,
                        protocol      = r.Protocol,
                        port          = r.Port,
                        status        = r.Status,
                        service       = r.ServiceGuess,
                        banner        = r.Banner,
                        default_creds = r.DefaultCreds
                    }).ToList()
                };

                File.WriteAllText(path, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
                Console.WriteLine($"[+] JSON: {path}");
            }
            catch (Exception ex) { Console.WriteLine($"[!] Erro JSON: {ex.Message}"); }
        }
    }
}
