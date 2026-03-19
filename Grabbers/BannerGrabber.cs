using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace PortScannerMonster.Grabbers
{
    public class BannerGrabber
    {
        public async Task<string> GrabAsync(TcpClient client, int port, string host)
        {
            try
            {
                Stream stream;
                if (port == 443 || port == 8443)
                {
                    var ssl = new SslStream(client.GetStream(), false, (_, _, _, _) => true);
                    await ssl.AuthenticateAsClientAsync(host);
                    stream = ssl;
                }
                else stream = client.GetStream();

                stream.ReadTimeout = 1000;

                byte[]? probe = port switch
                {
                    80 or 443 or 8080 or 8443
                        => Encoding.ASCII.GetBytes($"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
                    25 or 587 => Encoding.ASCII.GetBytes("EHLO scanner\r\n"),
                    110       => Encoding.ASCII.GetBytes("CAPA\r\n"),
                    143       => Encoding.ASCII.GetBytes("a001 CAPABILITY\r\n"),
                    6379      => Encoding.ASCII.GetBytes("PING\r\n"),
                    _         => null
                };

                if (probe != null) await stream.WriteAsync(probe);

                bool tryRead = port == 443 || port == 8443;
                if (!tryRead) { await Task.Delay(200); tryRead = client.Available > 0; }

                if (tryRead)
                {
                    var buf = new byte[1024];
                    int len = await stream.ReadAsync(buf);
                    if (len > 0)
                        return Encoding.ASCII.GetString(buf, 0, len).Split('\n')[0].Trim();
                }
            }
            catch { }
            return "";
        }

        public static string ExtractVersion(string banner)
        {
            if (string.IsNullOrEmpty(banner)) return "";
            var m = Regex.Match(banner, @"([a-zA-Z0-9_\-]+)\/([\d\.]+[a-z]?)");
            return m.Success ? m.Value : "";
        }

        public static string GuessService(int port) => port switch
        {
            21    => "FTP",           22    => "SSH",           23    => "Telnet",
            25    => "SMTP",          53    => "DNS",            67    => "DHCP",
            68    => "DHCP-Client",   69    => "TFTP",           79    => "Finger",
            80    => "HTTP",          88    => "Kerberos",       110   => "POP3",
            111   => "RPC",           119   => "NNTP",           123   => "NTP",
            135   => "MS-RPC",        137   => "NetBIOS-NS",     138   => "NetBIOS-DGM",
            139   => "NetBIOS",       143   => "IMAP",           161   => "SNMP",
            162   => "SNMP-Trap",     179   => "BGP",            389   => "LDAP",
            443   => "HTTPS",         445   => "SMB",            514   => "Syslog",
            515   => "LPD",           548   => "AFP",            554   => "RTSP",
            587   => "SMTP-TLS",      636   => "LDAPS",          993   => "IMAPS",
            995   => "POP3S",         1433  => "MSSQL",          1521  => "Oracle",
            1723  => "PPTP",          2049  => "NFS",            3306  => "MySQL",
            3389  => "RDP",           5060  => "SIP",            5432  => "PostgreSQL",
            5900  => "VNC",           6379  => "Redis",          8080  => "HTTP-Alt",
            8443  => "HTTPS-Alt",     9200  => "Elasticsearch",  27017 => "MongoDB",
            _     => "Desconhecido"
        };
    }
}
