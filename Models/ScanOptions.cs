namespace PortScannerMonster.Models
{
    public class ScanOptions
    {
        // ── alvos ────────────────────────────────────
        public List<string> Targets { get; set; } = new();
        public string TargetsFile   { get; set; } = "";

        // ── portas ───────────────────────────────────
        public string PortsInput { get; set; } = "1-1000";
        public int    TopPorts   { get; set; } = 0;

        // ── output ───────────────────────────────────
        public string OutputFile { get; set; } = "";

        // ── performance ──────────────────────────────
        public int  Timeout         { get; set; } = 1500;
        public int  Concurrency     { get; set; } = 200;
        public bool AdaptiveTimeout { get; set; } = false;

        // ── stealth ──────────────────────────────────
        public int Delay { get; set; } = 0;

        // ── protocolo ────────────────────────────────
        public bool ScanUdp { get; set; } = false;

        // ── recon ────────────────────────────────────
        public bool RunTraceroute { get; set; } = false;
        public bool CheckCreds    { get; set; } = false;

        // ── modos ────────────────────────────────────
        public int  WatchInterval { get; set; } = 0;
        public bool Interactive   { get; set; } = false;
        public bool Cache         { get; set; } = false;

        // ── display ──────────────────────────────────
        public bool Verbose { get; set; } = false;
        public bool Quiet   { get; set; } = false;

        // ── top 100 portas (estatísticas nmap) ───────
        public static readonly int[] TopPortsList =
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

        // ─────────────────────────────────────────────
        public static ScanOptions Parse(string[] args)
        {
            var opts = new ScanOptions();
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-t":                 if (i+1 < args.Length) opts.Targets.Add(args[++i]); break;
                    case "-iL":                if (i+1 < args.Length) opts.TargetsFile = args[++i]; break;
                    case "-p":                 if (i+1 < args.Length) opts.PortsInput = args[++i]; break;
                    case "--top-ports":
                        if (i+1 < args.Length && int.TryParse(args[++i], out var tp)) opts.TopPorts = tp;
                        break;
                    case "-o":                 if (i+1 < args.Length) opts.OutputFile = args[++i]; break;
                    case "-timeout":
                        if (i+1 < args.Length && int.TryParse(args[++i], out var to)) opts.Timeout = to;
                        break;
                    case "-c":
                        if (i+1 < args.Length && int.TryParse(args[++i], out var cc)) opts.Concurrency = cc;
                        break;
                    case "--delay":
                        if (i+1 < args.Length && int.TryParse(args[++i], out var dl)) opts.Delay = dl;
                        break;
                    case "--watch":
                        if (i+1 < args.Length && int.TryParse(args[++i], out var wi)) opts.WatchInterval = wi;
                        break;
                    case "--adaptive-timeout": opts.AdaptiveTimeout = true; break;
                    case "--udp":              opts.ScanUdp         = true; break;
                    case "--check-creds":      opts.CheckCreds      = true; break;
                    case "--traceroute":        opts.RunTraceroute   = true; break;
                    case "--interactive":       opts.Interactive     = true; break;
                    case "--cache":            opts.Cache           = true; break;
                    case "-v":                 opts.Verbose         = true; break;
                    case "-q":                 opts.Quiet           = true; break;
                }
            }
            return opts;
        }

        public List<int>? GetPorts()
        {
            if (TopPorts > 0)
                return TopPortsList.Take(Math.Min(TopPorts, TopPortsList.Length)).OrderBy(p => p).ToList();

            return ParsePorts(PortsInput);
        }

        private static List<int>? ParsePorts(string input)
        {
            if (input.ToLower() == "all") return Enumerable.Range(1, 65535).ToList();

            var result = new HashSet<int>();
            foreach (var part in input.Split(','))
            {
                if (part.Contains('-'))
                {
                    var r = part.Split('-');
                    if (r.Length != 2 || !int.TryParse(r[0], out int s) || !int.TryParse(r[1], out int e))
                    { Console.WriteLine($"[!] Faixa inválida: '{part}'"); return null; }
                    if (s > e || s < 1 || e > 65535)
                    { Console.WriteLine($"[!] Fora do intervalo (1-65535): '{part}'"); return null; }
                    for (int i = s; i <= e; i++) result.Add(i);
                }
                else
                {
                    if (!int.TryParse(part, out int p) || p < 1 || p > 65535)
                    { Console.WriteLine($"[!] Porta inválida: '{part}'"); return null; }
                    result.Add(p);
                }
            }
            return result.OrderBy(x => x).ToList();
        }

        public static void ShowHelp() => Console.WriteLine(@"
USO: scanner.exe [opções]

ALVOS:
  -t <ip/dominio/cidr>   Alvo (pode ser repetido)
  -iL <arquivo>          Lista de alvos (# = comentário)

PORTAS:
  -p <portas>            1-1000 | 22,80,443 | all  (padrão: 1-1000)
  --top-ports <N>        N portas mais comuns (máx: 100)

PROTOCOLO:
  --udp                  Inclui scan UDP

PERFORMANCE:
  -c <N>                 Concorrência (padrão: 200)
  -timeout <ms>          Timeout por porta (padrão: 1500ms)
  --adaptive-timeout     Ajusta timeout pelo RTT

STEALTH:
  --delay <ms>           Delay + jitter aleatório entre conexões

RECON:
  --traceroute           Traceroute antes do scan
  --check-creds          Verifica credenciais padrão (FTP, Redis, MongoDB)

OUTPUT:
  -o <arquivo>           Salva .txt .json .csv .xml
  -v                     Verboso (mostra fechadas/filtradas)
  -q                     Silencioso (só portas abertas)
  --cache                Salva cache e exibe diff com scan anterior
  --watch <segundos>     Repete o scan em loop
  --interactive          Modo interativo pós-scan

EXEMPLOS:
  scanner.exe -t 192.168.1.0/24 --top-ports 100 --check-creds
  scanner.exe -t 10.0.0.1 -p all --udp --traceroute -o resultado.txt
  scanner.exe -iL hosts.txt -p 80,443 --watch 60
  scanner.exe -t 10.0.0.1 --delay 200 -p 1-1000 --interactive
");
    }
}
