namespace PortScannerMonster.Models
{
    public class ScanResult
    {
        public string IP           { get; set; } = "";
        public int    Port         { get; set; }
        public string Protocol     { get; set; } = "TCP";
        public string Status       { get; set; } = "open";   // open | closed | filtered
        public string Banner       { get; set; } = "";
        public string ServiceGuess { get; set; } = "";
        public string Hostname     { get; set; } = "";
        public string DefaultCreds { get; set; } = "";
    }
}
