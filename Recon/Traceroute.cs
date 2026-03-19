using System.Net;
using System.Net.NetworkInformation;

namespace PortScannerMonster.Recon
{
    public static class Traceroute
    {
        public static async Task RunAsync(IPAddress target, CancellationToken ct)
        {
            Console.WriteLine($"\n[*] Traceroute para {target}:");
            Console.WriteLine("─────────────────────────────────────────────────────");

            for (int ttl = 1; ttl <= 30; ttl++)
            {
                if (ct.IsCancellationRequested) break;

                var options  = new PingOptions(ttl, true);
                IPStatus status = IPStatus.Unknown;
                IPAddress? hopAddr = null;
                long rtt = 0;

                try
                {
                    var sw    = System.Diagnostics.Stopwatch.StartNew();
                    var reply = await Task.Run(() => new Ping().Send(target, 2000, new byte[32], options));
                    sw.Stop();
                    status  = reply.Status;
                    hopAddr = reply.Address;
                    rtt     = sw.ElapsedMilliseconds;
                }
                catch { }

                if (hopAddr != null && !hopAddr.Equals(IPAddress.Any))
                {
                    string hostname = "";
                    try { hostname = (await Dns.GetHostEntryAsync(hopAddr)).HostName; } catch { }

                    string display = string.IsNullOrEmpty(hostname)
                        ? hopAddr.ToString()
                        : $"{hostname} ({hopAddr})";

                    Console.WriteLine($"  {ttl,2}  {rtt,5}ms  {display}");
                }
                else
                {
                    Console.WriteLine($"  {ttl,2}       *  (sem resposta)");
                }

                if (status == IPStatus.Success) break;
            }

            Console.WriteLine("─────────────────────────────────────────────────────\n");
        }
    }
}
