using System.Net.Sockets;
using System.Text;
using PortScannerMonster.Models;

namespace PortScannerMonster.Modes
{
    public class InteractiveMode
    {
        private readonly List<ScanResult> _results;

        public InteractiveMode(List<ScanResult> results) => _results = results;

        public void Run()
        {
            Console.WriteLine("\n[>] Modo interativo ativo. Digite 'help' para ver os comandos.");

            while (true)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("[scanner]> ");
                Console.ResetColor();

                var input = Console.ReadLine()?.Trim() ?? "";
                if (string.IsNullOrEmpty(input)) continue;

                var parts = input.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                switch (parts[0].ToLower())
                {
                    case "help":
                        Console.WriteLine(@"
  hosts                    Lista todos os IPs com portas abertas
  ports <ip>               Lista portas abertas de um IP
  info <ip> <porta>        Detalhes de uma porta específica
  connect <ip> <porta>     Conexão TCP raw (tipo netcat)
  clear                    Limpa a tela
  exit / quit              Encerra
");
                        break;

                    case "hosts":
                        foreach (var ip in _results.Where(r => r.Status == "open").Select(r => r.IP).Distinct())
                        {
                            string hostname = _results.First(r => r.IP == ip).Hostname;
                            Console.WriteLine($"  {ip}" + (string.IsNullOrEmpty(hostname) ? "" : $"  ({hostname})"));
                        }
                        break;

                    case "ports":
                        if (parts.Length < 2) { Console.WriteLine("[!] Uso: ports <ip>"); break; }
                        foreach (var r in _results.Where(r => r.IP == parts[1] && r.Status == "open").OrderBy(r => r.Port))
                            Console.WriteLine($"  {r.Protocol,-4} {r.Port,-6} {r.ServiceGuess}");
                        break;

                    case "info":
                        if (parts.Length < 3) { Console.WriteLine("[!] Uso: info <ip> <porta>"); break; }
                        if (int.TryParse(parts[2], out int infoPort))
                        {
                            var r = _results.FirstOrDefault(x => x.IP == parts[1] && x.Port == infoPort);
                            if (r == null) Console.WriteLine("[!] Porta não encontrada nos resultados.");
                            else
                            {
                                Console.WriteLine($"  IP:       {r.IP}");
                                Console.WriteLine($"  Hostname: {r.Hostname}");
                                Console.WriteLine($"  Porta:    {r.Port}/{r.Protocol}");
                                Console.WriteLine($"  Serviço:  {r.ServiceGuess}");
                                Console.WriteLine($"  Status:   {r.Status}");
                                Console.WriteLine($"  Banner:   {r.Banner}");
                                if (!string.IsNullOrEmpty(r.DefaultCreds))
                                    Console.WriteLine($"  Creds:    {r.DefaultCreds}");
                            }
                        }
                        break;

                    case "connect":
                        if (parts.Length < 3) { Console.WriteLine("[!] Uso: connect <ip> <porta>"); break; }
                        if (int.TryParse(parts[2], out int connPort))
                            ConnectRaw(parts[1], connPort).GetAwaiter().GetResult();
                        break;

                    case "clear":
                        Console.Clear();
                        break;

                    case "exit":
                    case "quit":
                        return;

                    default:
                        Console.WriteLine($"[!] Comando desconhecido: '{parts[0]}'. Digite 'help'.");
                        break;
                }
            }
        }

        private static async Task ConnectRaw(string ip, int port)
        {
            Console.WriteLine($"[*] Conectando a {ip}:{port}... (linha vazia para desconectar)\n");
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(ip, port);
                Console.WriteLine("[+] Conectado.\n");

                using var stream = client.GetStream();
                stream.ReadTimeout = 500;
                var cts = new CancellationTokenSource();

                var readTask = Task.Run(async () =>
                {
                    var buf = new byte[4096];
                    while (!cts.Token.IsCancellationRequested)
                    {
                        try
                        {
                            int n = await stream.ReadAsync(buf, cts.Token);
                            if (n == 0) break;
                            Console.Write(Encoding.ASCII.GetString(buf, 0, n));
                        }
                        catch { break; }
                    }
                });

                while (true)
                {
                    var line = Console.ReadLine();
                    if (string.IsNullOrEmpty(line)) break;
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(line + "\r\n"));
                    await Task.Delay(200);
                }

                cts.Cancel();
                await readTask;
                Console.WriteLine("\n[*] Desconectado.");
            }
            catch (Exception ex) { Console.WriteLine($"[!] Erro: {ex.Message}"); }
        }
    }
}
