using System.Net;
using System.Net.Sockets;
using PortScannerMonster.Grabbers;
using PortScannerMonster.Models;

namespace PortScannerMonster.Core
{
    public class TcpScanner
    {
        private readonly ScanOptions   _opts;
        private readonly ScanContext   _ctx;
        private readonly BannerGrabber _grabber = new();

        public TcpScanner(ScanOptions opts, ScanContext ctx)
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

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(_ctx.CancellationToken);
                timeoutCts.CancelAfter(_opts.Timeout);

                using var client    = new TcpClient();
                string portStatus   = "filtered";

                try
                {
                    await client.ConnectAsync(ip, port, timeoutCts.Token);
                    if (client.Connected) portStatus = "open";
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
                {
                    portStatus = "closed";
                }
                catch (OperationCanceledException) when (!_ctx.CancellationToken.IsCancellationRequested)
                {
                    portStatus = "filtered";
                }
                catch (OperationCanceledException) { return; }

                if (portStatus == "open")
                {
                    string banner  = await _grabber.GrabAsync(client, port, ip.ToString());
                    string service = BannerGrabber.GuessService(port);
                    string version = BannerGrabber.ExtractVersion(banner);

                    _ctx.Results.Add(new ScanResult
                    {
                        IP = ip.ToString(), Port = port, Protocol = "TCP",
                        Status = "open", Banner = banner, ServiceGuess = service
                    });

                    if (!_opts.Quiet)
                        lock (_ctx.ConsoleLock)
                        {
                            ScanContext.ClearLine();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.Write($"[+] {ip,-15} TCP  {port,-5} {service,-14} ABERTA");
                            if (!string.IsNullOrEmpty(version))
                            { Console.ForegroundColor = ConsoleColor.Cyan;    Console.Write($" | {version}"); }
                            else if (!string.IsNullOrEmpty(banner))
                            { Console.ForegroundColor = ConsoleColor.DarkGray; Console.Write($" | {banner.Trim()}"); }
                            Console.WriteLine();
                            Console.ResetColor();
                        }
                }
                else if (_opts.Verbose && !_opts.Quiet)
                    lock (_ctx.ConsoleLock)
                    {
                        ScanContext.ClearLine();
                        Console.ForegroundColor = portStatus == "closed" ? ConsoleColor.DarkRed : ConsoleColor.DarkGray;
                        Console.WriteLine($"[-] {ip,-15} TCP  {port,-5} {BannerGrabber.GuessService(port),-14} {portStatus.ToUpper()}");
                        Console.ResetColor();
                    }
            }
            catch { }
            finally
            {
                _ctx.Semaphore.Release();
                _ctx.IncrementProgress(_opts.Quiet);
            }
        }
    }
}
