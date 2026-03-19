using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;

namespace PortScannerMonster.Recon
{
    public static class PingSweeper
    {
        public static async Task<List<IPAddress>> SweepAsync(List<IPAddress> ips)
        {
            var alive = new ConcurrentBag<IPAddress>();

            await Task.WhenAll(ips.Select(async ip =>
            {
                try
                {
                    using var ping  = new Ping();
                    var reply       = await ping.SendPingAsync(ip, 1000);
                    if (reply.Status == IPStatus.Success)
                        alive.Add(ip);
                }
                catch { }
            }));

            return alive.OrderBy(ip => ip.ToString()).ToList();
        }
    }
}
