using PortScannerMonster.Models;

Console.Title = "C# Port Scanner v8.0";

if (args.Length == 0 || args.Contains("-h") || args.Contains("--help"))
{
    ScanOptions.ShowHelp();
    Console.WriteLine("\nPressione qualquer tecla para fechar...");
    Console.ReadKey();
    return;
}

var options = ScanOptions.Parse(args);
await new PortScannerMonster.Core.PortScanner(options).RunAsync();
