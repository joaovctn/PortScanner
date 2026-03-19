using System.Net;
using PortScannerMonster.Models;

namespace PortScannerMonster.Core
{
    /// <summary>
    /// Executa um ciclo de scan (TCP + UDP opcional) sobre uma lista de IPs e portas.
    /// Usado tanto pelo fluxo normal quanto pelo WatchMode.
    /// </summary>
    public class ScanRunner
    {
        private readonly ScanOptions _opts;
        private readonly CancellationToken _ct;

        public ScanRunner(ScanOptions opts, CancellationToken ct)
        {
            _opts = opts;
            _ct   = ct;
        }

        public async Task<(List<ScanResult> results, double elapsed)> RunAsync(
            List<IPAddress> ips, List<int> ports, ScanContext ctx)
        {
            ctx.Reset();
            ctx.TotalPorts = ips.Count * ports.Count * (_opts.ScanUdp ? 2 : 1);

            var tcp  = new TcpScanner(_opts, ctx);
            var udp  = _opts.ScanUdp ? new UdpScanner(_opts, ctx) : null;
            var tasks = new List<Task>();
            var watch = System.Diagnostics.Stopwatch.StartNew();

            foreach (var ip in ips)
            {
                foreach (var port in ports)
                {
                    if (_ct.IsCancellationRequested) break;
                    tasks.Add(tcp.ScanAsync(ip, port));
                    if (udp != null) tasks.Add(udp.ScanAsync(ip, port));
                }
                if (_ct.IsCancellationRequested) break;
            }

            await Task.WhenAll(tasks);
            watch.Stop();

            return (ctx.Results.ToList(), watch.Elapsed.TotalSeconds);
        }
    }
}
