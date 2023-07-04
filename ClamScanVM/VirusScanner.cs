using System.Buffers;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;

using nClam;

namespace ClamScanVM;
internal class VirusScanner
{
    private readonly string vmName;
    private readonly ChannelReader<VMFileBlock> reader;
    private readonly string clamAVAddress;

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
        var scannerThreads = 5;
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
            throw new Exception("Could not ping ClamAV server!");
        }

        //Get ClamAV engine and virus database version
        var result = await clamAvClient.GetVersionAsync().ConfigureAwait(false);

        Console.WriteLine($"ClamAV version - {result}");

        while(await this.reader.WaitToReadAsync().ConfigureAwait(false))
        {
            var dataToScan = await this.reader.ReadAsync().ConfigureAwait(false);

            var buffer = ArrayPool<byte>.Shared.Rent(dataToScan.Content.Length);
            try
            {
                // The library only takes byte[].
                // By using ArrayPool rent/release vs ToArray() on the buffer, memory usage was halved.
                dataToScan.Content.CopyTo(buffer);
                var scanResult = await clamAvClient.SendAndScanFileAsync(buffer).ConfigureAwait(false);
                switch (scanResult.Result)
                {
                    case ClamScanResults.Clean:
                        break;
                    case ClamScanResults.VirusDetected:
                        var e = new VirusFoundEventArgs()
                        {
                            FileName = dataToScan.FileName,
                            VirusName = $"{scanResult.InfectedFiles?.First()?.VirusName} - {scanResult.RawResult}",
                            Offset = dataToScan.BlockNumber,
                            VMName = this.vmName
                        };
                        OnVirusFound(e);
                        break;
                    case ClamScanResults.Error:
                        await Console.Out.WriteLineAsync($"Error while scanning {dataToScan.FileName}");
                        break;
                    default:
                        throw new UnreachableException();
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer, false);
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