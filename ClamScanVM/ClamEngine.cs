using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using nClam;

using NLog;

namespace ClamScanVM;
internal class ClamEngine : IVirusEngine
{
    private ClamClient? client;
    private readonly NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

    public List<string> AcceptedOptions()
    {
        return new List<string>() { "Server", "Port" };
    }

    public async Task Initialize(List<KeyValuePair<string, string>> options)
    {
        var server = String.Empty;
        var port = 0;
        foreach(var kvp in options)
        {
            switch(kvp.Key)
            {
                case "Server":
                    server = kvp.Value;
                    break;
                case "Port":
                    port = int.Parse(kvp.Value);
                    break;
                default:
                    continue;
            }
        }

        this.client = new ClamClient(server, port);
        var result = await this.client.GetVersionAsync().ConfigureAwait(false);

        logger.Info($"ClamAV version - {result}");
    }

    public async Task<ScanResult> ScanBuffer(ReadOnlyMemory<byte> buffer)
    {
        if(this.client == null)
        {
            throw new ArgumentException($"Client is not initialized");
        }

        var scanResult = await this.client?.SendAndScanFileAsync(buffer, CancellationToken.None);
        if(scanResult is null)
        {
            return new ScanResult(ScanResultDescription.Error);
        }

        switch (scanResult.Result)
        {
            case ClamScanResults.Clean:
                return new ScanResult(ScanResultDescription.Clean);
            case ClamScanResults.VirusDetected:
                return new ScanResult(ScanResultDescription.ThreatFound, scanResult?.InfectedFiles?[0].VirusName);
            case ClamScanResults.Unknown:
                return new ScanResult(ScanResultDescription.Unknown, scanResult.RawResult);
            case ClamScanResults.Error:
                return new ScanResult(ScanResultDescription.Error, scanResult.RawResult);
            default:
                return new ScanResult(ScanResultDescription.Unknown, scanResult.RawResult);
        }
    }

    public async Task<bool> TestConnection()
    {
        if (this.client == null) { return false; }
        return await this.client.PingAsync().ConfigureAwait(false);
    }

    public async Task UnInitialize()
    {
        if(this.client == null) { return; }
        await this.client.Shutdown(CancellationToken.None).ConfigureAwait(false);
    }
}
