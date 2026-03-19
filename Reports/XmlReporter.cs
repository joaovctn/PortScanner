using System.Text;
using System.Xml;
using PortScannerMonster.Grabbers;
using PortScannerMonster.Models;

namespace PortScannerMonster.Reports
{
    public static class XmlReporter
    {
        public static void Generate(string outputFile, List<ScanResult> results, string osFingerprint, double elapsed)
        {
            try
            {
                string path  = Path.ChangeExtension(outputFile, ".xml");
                long startTs = DateTimeOffset.Now.ToUnixTimeSeconds();

                var settings = new XmlWriterSettings { Indent = true, Encoding = Encoding.UTF8 };
                using var w  = XmlWriter.Create(path, settings);

                w.WriteStartDocument();
                w.WriteDocType("nmaprun", null, null, null);
                w.WriteStartElement("nmaprun");
                w.WriteAttributeString("scanner", "portscanner");
                w.WriteAttributeString("version", "8.0");
                w.WriteAttributeString("start", startTs.ToString());
                w.WriteAttributeString("startstr", DateTime.Now.ToString("ddd MMM dd HH:mm:ss yyyy"));
                w.WriteAttributeString("xmloutputversion", "1.04");

                w.WriteStartElement("scaninfo");
                w.WriteAttributeString("type", "connect");
                w.WriteAttributeString("protocol", "tcp");
                w.WriteEndElement();

                foreach (var ipGroup in results.Where(r => r.Status == "open").GroupBy(r => r.IP))
                {
                    w.WriteStartElement("host");

                    w.WriteStartElement("status");
                    w.WriteAttributeString("state", "up");
                    w.WriteAttributeString("reason", "ping");
                    w.WriteEndElement();

                    w.WriteStartElement("address");
                    w.WriteAttributeString("addr", ipGroup.Key);
                    w.WriteAttributeString("addrtype", "ipv4");
                    w.WriteEndElement();

                    string hostname = ipGroup.First().Hostname;
                    if (!string.IsNullOrEmpty(hostname))
                    {
                        w.WriteStartElement("hostnames");
                        w.WriteStartElement("hostname");
                        w.WriteAttributeString("name", hostname);
                        w.WriteAttributeString("type", "PTR");
                        w.WriteEndElement();
                        w.WriteEndElement();
                    }

                    w.WriteStartElement("ports");
                    foreach (var r in ipGroup.OrderBy(r => r.Port))
                    {
                        w.WriteStartElement("port");
                        w.WriteAttributeString("protocol", r.Protocol.ToLower());
                        w.WriteAttributeString("portid", r.Port.ToString());

                        w.WriteStartElement("state");
                        w.WriteAttributeString("state", "open");
                        w.WriteAttributeString("reason", "syn-ack");
                        w.WriteEndElement();

                        w.WriteStartElement("service");
                        w.WriteAttributeString("name", r.ServiceGuess.ToLower());
                        string version = BannerGrabber.ExtractVersion(r.Banner);
                        if (!string.IsNullOrEmpty(version))  w.WriteAttributeString("version", version);
                        if (!string.IsNullOrEmpty(r.Banner)) w.WriteAttributeString("extrainfo", r.Banner);
                        w.WriteEndElement();

                        w.WriteEndElement(); // port
                    }
                    w.WriteEndElement(); // ports

                    if (!string.IsNullOrEmpty(osFingerprint))
                    {
                        w.WriteStartElement("os");
                        w.WriteStartElement("osmatch");
                        w.WriteAttributeString("name", osFingerprint);
                        w.WriteAttributeString("accuracy", "70");
                        w.WriteEndElement();
                        w.WriteEndElement();
                    }

                    w.WriteEndElement(); // host
                }

                w.WriteStartElement("runstats");
                w.WriteStartElement("finished");
                w.WriteAttributeString("time", startTs.ToString());
                w.WriteAttributeString("elapsed", elapsed.ToString("F2"));
                w.WriteAttributeString("exit", "success");
                w.WriteEndElement();
                w.WriteStartElement("hosts");
                w.WriteAttributeString("up", results.Select(r => r.IP).Distinct().Count().ToString());
                w.WriteAttributeString("total", results.Select(r => r.IP).Distinct().Count().ToString());
                w.WriteEndElement();
                w.WriteEndElement(); // runstats

                w.WriteEndElement(); // nmaprun

                Console.WriteLine($"[+] XML: {path}");
            }
            catch (Exception ex) { Console.WriteLine($"[!] Erro XML: {ex.Message}"); }
        }
    }
}
