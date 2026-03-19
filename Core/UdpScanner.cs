using System.Net;
using System.Net.Sockets;
using System.Text;
using PortScannerMonster.Grabbers;
using PortScannerMonster.Models;

namespace PortScannerMonster.Core
{
    public class UdpScanner
    {
        private readonly ScanOptions _opts;
        private readonly ScanContext _ctx;

        public UdpScanner(ScanOptions opts, ScanContext ctx)
        {
            _opts = opts;
            _ctx  = ctx;
        }

        public async Task ScanAsync(IPAddress ip, int port)
        {
            try { await _ctx.Semaphore.WaitAsync(_ctx.CancellationToken); }
            catch (OperationCanceledException) { return; }

            if (_opts.Delay > 0)
                await Task.Delay(_opts.Delay + Random.Shared.Next(_opts.Delay / 2));

            try
            {
                if (_ctx.CancellationToken.IsCancellationRequested) return;

                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = _opts.Timeout;

                byte[] probe = GetProbe(port);
                await udp.SendAsync(probe, probe.Length, new IPEndPoint(ip, port));

                try
                {
                    var remote   = new IPEndPoint(IPAddress.Any, 0);
                    byte[] resp  = udp.Receive(ref remote);
                    string service = BannerGrabber.GuessService(port);

                    _ctx.Results.Add(new ScanResult
                    {
                        IP = ip.ToString(), Port = port, Protocol = "UDP", Status = "open",
                        Banner       = Encoding.ASCII.GetString(resp).Split('\n')[0].Trim(),
                        ServiceGuess = service
                    });

                    if (!_opts.Quiet)
                        lock (_ctx.ConsoleLock)
                        {
                            ScanContext.ClearLine();
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.WriteLine($"[+] {ip,-15} UDP  {port,-5} {service,-14} ABERTA");
                            Console.ResetColor();
                        }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
                {
                    // ICMP port unreachable → closed
                    if (_opts.Verbose && !_opts.Quiet)
                        lock (_ctx.ConsoleLock)
                        {
                            ScanContext.ClearLine();
                            Console.ForegroundColor = ConsoleColor.DarkRed;
                            Console.WriteLine($"[-] {ip,-15} UDP  {port,-5} {BannerGrabber.GuessService(port),-14} FECHADA");
                            Console.ResetColor();
                        }
                }
            }
            catch { }
            finally
            {
                _ctx.Semaphore.Release();
                _ctx.IncrementProgress(_opts.Quiet);
            }
        }

        private static byte[] GetProbe(int port) => port switch
        {
            53  => new byte[]
            {
                0x00,0x01,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                0x07,0x76,0x65,0x72,0x73,0x69,0x6f,0x6e,0x04,0x62,0x69,0x6e,
                0x64,0x00,0x00,0x10,0x00,0x03
            },
            161 => new byte[]
            {
                0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,
                0x63,0xa0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,
                0x30,0x0e,0x30,0x0c,0x06,0x08,0x43,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x05,0x00
            },
            123 => new byte[]
            {
                0x1b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            },
            _   => Array.Empty<byte>()
        };
    }
}
