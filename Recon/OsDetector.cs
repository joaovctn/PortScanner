using System.Net.NetworkInformation;

namespace PortScannerMonster.Recon
{
    public static class OsDetector
    {
        public static string Detect(string host)
        {
            try
            {
                using var ping = new Ping();
                var reply = ping.Send(host, 2000);
                if (reply.Status == IPStatus.Success)
                {
                    if (reply.Options == null) return "Linux/Unix (TTL inacessível)";
                    int ttl = reply.Options.Ttl;
                    if (ttl <= 64)  return $"Linux/Unix (TTL={ttl})";
                    if (ttl <= 128) return $"Windows (TTL={ttl})";
                    return $"Cisco/Network (TTL={ttl})";
                }
                return $"Falha no Ping ({reply.Status})";
            }
            catch { return "Desconhecido (Erro ICMP)"; }
        }

        public static int MeasureRtt(string host)
        {
            try
            {
                using var ping = new Ping();
                var times = new List<long>();
                for (int i = 0; i < 3; i++)
                {
                    var r = ping.Send(host, 2000);
                    if (r.Status == IPStatus.Success) times.Add(r.RoundtripTime);
                }
                return times.Count > 0 ? (int)times.Average() : 0;
            }
            catch { return 0; }
        }
    }
}
