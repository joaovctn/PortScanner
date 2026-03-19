using System.Collections.Concurrent;
using PortScannerMonster.Models;

namespace PortScannerMonster.Core
{
    public class ScanContext
    {
        public ConcurrentBag<ScanResult> Results { get; set; } = new();
        public int TotalPorts { get; set; }
        public int ScannedPorts; // acessado via Interlocked
        public readonly object ConsoleLock = new();
        public SemaphoreSlim Semaphore { get; }
        public CancellationToken CancellationToken { get; }

        public ScanContext(int concurrency, CancellationToken ct)
        {
            Semaphore = new SemaphoreSlim(concurrency);
            CancellationToken = ct;
        }

        public void Reset()
        {
            Results = new ConcurrentBag<ScanResult>();
            Interlocked.Exchange(ref ScannedPorts, 0);
        }

        public void IncrementProgress(bool quiet)
        {
            int n = Interlocked.Increment(ref ScannedPorts);
            if (!quiet && TotalPorts > 0)
                lock (ConsoleLock)
                    Console.Write($"\r[*] Progresso: {n}/{TotalPorts} ({n * 100 / TotalPorts}%)...");
        }

        public static void ClearLine() =>
            Console.Write("\r" + new string(' ', Console.WindowWidth - 1) + "\r");
    }
}
