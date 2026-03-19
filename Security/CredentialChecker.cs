using System.Net.Sockets;
using System.Text;
using PortScannerMonster.Models;

namespace PortScannerMonster.Security
{
    public static class CredentialChecker
    {
        public static async Task CheckAllAsync(IEnumerable<ScanResult> results)
        {
            var targets = results
                .Where(r => r.Status == "open" && r.Protocol == "TCP"
                         && new[] { 21, 6379, 27017 }.Contains(r.Port))
                .ToList();

            if (targets.Count == 0) return;

            Console.WriteLine("\n[*] Verificando credenciais padrão...");

            foreach (var r in targets)
            {
                string? cred = r.Port switch
                {
                    21    => await CheckFtpAnonymousAsync(r.IP),
                    6379  => await CheckRedisNoAuthAsync(r.IP),
                    27017 => await CheckMongoNoAuthAsync(r.IP),
                    _     => null
                };

                if (cred != null)
                {
                    r.DefaultCreds = cred;
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!!!] {r.IP}:{r.Port} — {cred}");
                    Console.ResetColor();
                }
            }
        }

        private static async Task<string?> CheckFtpAnonymousAsync(string ip)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(ip, 21);
                var stream = client.GetStream();
                stream.ReadTimeout = 3000;
                var buf = new byte[1024];

                await stream.ReadAsync(buf, 0, buf.Length);
                await stream.WriteAsync(Encoding.ASCII.GetBytes("USER anonymous\r\n"));
                int n = await stream.ReadAsync(buf, 0, buf.Length);
                if (!Encoding.ASCII.GetString(buf, 0, n).StartsWith("331")) return null;

                await stream.WriteAsync(Encoding.ASCII.GetBytes("PASS anonymous@\r\n"));
                n = await stream.ReadAsync(buf, 0, buf.Length);
                if (Encoding.ASCII.GetString(buf, 0, n).StartsWith("230"))
                    return "FTP login anônimo aceito (USER: anonymous / PASS: anonymous@)";
            }
            catch { }
            return null;
        }

        private static async Task<string?> CheckRedisNoAuthAsync(string ip)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(ip, 6379);
                var stream = client.GetStream();
                stream.ReadTimeout = 2000;
                await stream.WriteAsync(Encoding.ASCII.GetBytes("PING\r\n"));
                var buf = new byte[256];
                int n = await stream.ReadAsync(buf);
                if (Encoding.ASCII.GetString(buf, 0, n).Contains("+PONG"))
                    return "Redis sem autenticação (PING → PONG)";
            }
            catch { }
            return null;
        }

        private static async Task<string?> CheckMongoNoAuthAsync(string ip)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(ip, 27017);
                var stream = client.GetStream();
                stream.ReadTimeout = 2000;

                // OP_MSG isMaster
                byte[] msg =
                {
                    0x27,0x00,0x00,0x00, 0x01,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00, 0xdd,0x07,0x00,0x00,
                    0x00,0x00,0x00,0x00, 0x00,
                    0x18,0x00,0x00,0x00,
                    0x10,0x69,0x73,0x4d,0x61,0x73,0x74,0x65,0x72,0x00,
                    0x01,0x00,0x00,0x00, 0x00
                };
                await stream.WriteAsync(msg);
                var buf = new byte[512];
                int n = await stream.ReadAsync(buf);
                if (n > 16) return "MongoDB sem autenticação (respondeu ao isMaster)";
            }
            catch { }
            return null;
        }
    }
}
