using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using PortScannerMonster.Models;

namespace PortScannerMonster.Recon
{
    public static class DnsResolver
    {
        public static async Task<List<IPAddress>> ResolveTargetAsync(string target)
        {
            var result = new List<IPAddress>();

            if (target.Contains('/'))
            {
                var parts = target.Split('/');
                if (parts.Length == 2
                    && IPAddress.TryParse(parts[0], out var baseIp)
                    && int.TryParse(parts[1], out int prefix)
                    && prefix >= 0 && prefix <= 32)
                {
                    result.AddRange(ExpandCidr(baseIp, prefix));
                    return result;
                }
                throw new ArgumentException($"CIDR inválido: '{target}'");
            }

            if (IPAddress.TryParse(target, out var ip))
            {
                result.Add(ip);
                return result;
            }

            var entry = await Dns.GetHostEntryAsync(target);
            var ipv4  = entry.AddressList.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                        ?? throw new Exception("Nenhum IPv4 encontrado para o hostname.");
            result.Add(ipv4);
            return result;
        }

        public static IEnumerable<IPAddress> ExpandCidr(IPAddress baseIp, int prefix)
        {
            byte[] b  = baseIp.GetAddressBytes();
            uint ip   = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
            uint mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
            uint net  = ip & mask;
            uint bcast = net | ~mask;
            uint start = prefix < 31 ? net + 1 : net;
            uint end   = prefix < 31 ? bcast - 1 : bcast;

            for (uint i = start; i <= end; i++)
                yield return new IPAddress(new byte[] { (byte)(i >> 24), (byte)(i >> 16), (byte)(i >> 8), (byte)i });
        }

        public static async Task ResolveHostnamesAsync(IEnumerable<ScanResult> results)
        {
            var map = new ConcurrentDictionary<string, string>();
            var ips = results.Select(r => r.IP).Distinct().ToList();

            await Task.WhenAll(ips.Select(async ip =>
            {
                try { map[ip] = (await Dns.GetHostEntryAsync(ip)).HostName; }
                catch { map[ip] = ""; }
            }));

            foreach (var r in results)
                if (map.TryGetValue(r.IP, out var h)) r.Hostname = h;
        }
    }
}
