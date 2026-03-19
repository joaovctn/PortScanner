using System.Text;
using PortScannerMonster.Models;

namespace PortScannerMonster.Reports
{
    public static class TxtReporter
    {
        public static void Generate(string outputFile, List<ScanResult> results, ScanOptions opts)
        {
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine("--- RELATÓRIO DE SCAN ---");
                sb.AppendLine($"Data: {DateTime.Now}");
                sb.AppendLine($"Alvos: {string.Join(", ", opts.Targets)}");
                sb.AppendLine($"Portas Abertas: {results.Count(r => r.Status == "open")}");
                sb.AppendLine();
                sb.AppendLine($"{"IP",-16} {"PROT",-5} {"PORTA",-7} {"STATUS",-9} {"SERVIÇO",-16} {"HOSTNAME",-25} BANNER");
                sb.AppendLine(new string('-', 100));

                foreach (var r in results.OrderBy(r => r.IP).ThenBy(r => r.Port))
                    sb.AppendLine($"{r.IP,-16} {r.Protocol,-5} {r.Port,-7} {r.Status,-9} {r.ServiceGuess,-16} {r.Hostname,-25} {r.Banner}");

                File.WriteAllText(outputFile, sb.ToString());
                Console.WriteLine($"\n[+] TXT: {Path.GetFullPath(outputFile)}");
            }
            catch (Exception ex) { Console.WriteLine($"[!] Erro TXT: {ex.Message}"); }
        }
    }
}
