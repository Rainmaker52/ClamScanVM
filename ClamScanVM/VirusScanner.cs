using System.Buffers;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;

using nClam;

using NLog;

namespace ClamScanVM;
internal class VirusScanner
{
    private readonly string vmName;
    private readonly ChannelReader<VMFileBlock> reader;
    private readonly string clamAVAddress;
    private readonly NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

    internal event EventHandler<VirusScanCompletedEventArgs> ScanCompleted;
    internal event EventHandler<VirusFoundEventArgs> VirusFound;

    public VirusScanner(string vmName, ChannelReader<VMFileBlock> reader, string clamServerAddress)
    {
        this.vmName = vmName;
        this.reader = reader;
        this.clamAVAddress = clamServerAddress;
    }

    internal async Task<VirusScanner> Start()
    {
        var scannerThreads = 10;
        List<Task> tasks = new();

        while(scannerThreads-- > 0)
        {
            tasks.Add(Task.Run(() => StartThread()));
        }

        await Task.WhenAll(tasks);

        /*
        var e = new VirusFoundEventArgs()
        {
            FileName = "bla",
            VirusName = "EICAR",
            Offset = 3,
            VMName = this.vmName
        };
        OnVirusFound(e);
        */

        // To allow unsubscription of our event
        return this;
    }

    private async Task StartThread()
    {
        var clamAvClient = new ClamClient(this.clamAVAddress.Split(":")[0], int.Parse(this.clamAVAddress.Split(":")[1]));

        //Send PING command to ClamAV
        if(!await clamAvClient.PingAsync().ConfigureAwait(false))
        {
            throw new ArgumentException("Could not ping ClamAV server!");
        }

        //Get ClamAV engine and virus database version
        var result = await clamAvClient.GetVersionAsync().ConfigureAwait(false);

        logger.Info($"ClamAV version - {result}");

        while(await this.reader.WaitToReadAsync().ConfigureAwait(false))
        {
            var dataToScan = await this.reader.ReadAsync().ConfigureAwait(false);

            try
            {
                var scanResult = await clamAvClient.SendAndScanFileAsync(dataToScan.Content, CancellationToken.None).ConfigureAwait(false);
                switch (scanResult.Result)
                {
                    case ClamScanResults.Clean:
                        // Possible audit action here
                        break;
                    case ClamScanResults.VirusDetected:
                        var e = new VirusFoundEventArgs()
                        {
                            FileName = dataToScan.FileName,
                            VirusName = $"{scanResult.InfectedFiles?[0]?.VirusName} - {scanResult.RawResult}",
                            Offset = dataToScan.BlockNumber,
                            VMName = this.vmName
                        };
                        OnVirusFound(e);
                        break;
                    case ClamScanResults.Error:
                        logger.Warn($"Error returned from virusscanner while scanning {dataToScan.FileName} - Response [{scanResult.RawResult}]");
                        break;
                    case ClamScanResults.Unknown:
                        logger.Warn($"Unknown response when scanning {dataToScan.FileName} - Response [{scanResult.RawResult}]");
                        break;
                    default:
                        throw new UnreachableException();
                }
                logger.Trace($"Scanned file {dataToScan.FileName} block {dataToScan.BlockNumber} from VM {this.vmName} - {scanResult.Result}");
            }
            finally
            {
                ;
            }
        }
    }

    protected virtual void OnScanCompleted(VirusScanCompletedEventArgs e)
    {
        ScanCompleted?.Invoke(this, e);
    }

    protected virtual void OnVirusFound(VirusFoundEventArgs e)
    {
        VirusFound?.Invoke(this, e);
    }
}