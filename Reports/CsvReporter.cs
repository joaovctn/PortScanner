using System.Text;
using PortScannerMonster.Models;

namespace PortScannerMonster.Reports
{
    public static class CsvReporter
    {
        public static void Generate(string outputFile, List<ScanResult> results)
        {
            try
            {
                string path = Path.ChangeExtension(outputFile, ".csv");
                var sb = new StringBuilder();
                sb.AppendLine("IP,Hostname,Protocol,Port,Status,Service,Banner,DefaultCreds");

                foreach (var r in results.OrderBy(r => r.IP).ThenBy(r => r.Port))
                    sb.AppendLine(
                        $"\"{r.IP}\",\"{r.Hostname}\",\"{r.Protocol}\",{r.Port},\"{r.Status}\"," +
                        $"\"{r.ServiceGuess}\",\"{r.Banner.Replace("\"", "\"\"")}\",\"{r.DefaultCreds}\"");

                File.WriteAllText(path, sb.ToString());
                Console.WriteLine($"[+] CSV: {path}");
            }
            catch (Exception ex) { Console.WriteLine($"[!] Erro CSV: {ex.Message}"); }
        }
    }
}
