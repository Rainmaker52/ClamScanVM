using System.Buffers;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;

using nClam;

using NLog;
using System.Linq;

namespace ClamScanVM;
internal class VirusScanner<T> where T : IVirusEngine
{
    private readonly string vmName;
    private readonly ChannelReader<VMFileBlock> reader;
    private readonly List<IVirusEngine> scannerInstances = new();
    private readonly NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();
    private readonly List<VirusScanException> errors = new();

    internal event EventHandler<VirusScanCompletedEventArgs> ScanCompleted;
    internal event EventHandler<VirusFoundEventArgs> VirusFound;

    // To recognize this particular scanner instance
    internal Guid scannerGuid { get; init; } = Guid.NewGuid();

    public VirusScanner(string vmName, ChannelReader<VMFileBlock> reader, Type scannerType, int scannerThreads)
    {
        this.vmName = vmName;
        this.reader = reader;

        while(scannerThreads-- > 0)
        {
            var newInstance = (IVirusEngine)Activator.CreateInstance(scannerType);
            if(newInstance == null)
            {
                logger.Error($"Failed to create instance for type [{scannerType}]");
                continue;
            }
            this.scannerInstances.Add(newInstance);
        }
    }

    internal async Task Start(List<KeyValuePair<string, string>> options)
    {

        var runningTasks = new List<Task>();

        foreach (var instance in this.scannerInstances)
        {
            foreach (var kvp in options.Where(kvp => !instance.AcceptedOptions().Contains(kvp.Key)))
            {
                throw new ArgumentException($"Option {kvp.Key} is not listed as one of {instance.GetType().Name}'s options");
            }

            await instance.Initialize(options);
            if (!await instance.TestConnection())
            {
                logger.Error("Failed to check engine readiness after initialization");
                return;
            }

            var instanceTask = Task.Run(() => this.ListenAndScan(instance));
            runningTasks.Add(instanceTask);
        }

        await Task.WhenAll(runningTasks);
        foreach(var instance in this.scannerInstances)
        {
            await instance.UnInitialize();
        }
    }

    private async Task ListenAndScan(IVirusEngine instance)
    {
        while (await this.reader.WaitToReadAsync())
        {
            try
            {
                var dataToScan = await this.reader.ReadAsync();

                var scanResult = await instance.ScanBuffer(dataToScan.Content).ConfigureAwait(false);
                switch (scanResult.ShortResult)
                {
                    case ScanResultDescription.Clean:
                        // Possible audit action here
                        break;
                    case ScanResultDescription.ThreatFound:
                        var e = new VirusFoundEventArgs()
                        {
                            FileName = dataToScan.FileName,
                            VirusName = scanResult.Payload ?? "(Virus name not returned by scanner)",
                            Offset = dataToScan.BlockNumber,
                            VMName = this.vmName
                        };
                        OnVirusFound(e);
                        break;
                    case ScanResultDescription.Error:
                        logger.Warn($"Error returned from virusscanner while scanning {dataToScan.FileName} - Response [{scanResult.Payload}]");
                        this.errors.Add(new VirusScanException());
                        break;
                    case ScanResultDescription.Unknown:
                        logger.Warn($"Unknown response when scanning {dataToScan.FileName} - Response [{scanResult.Payload}]");
                        break;
                    default:
                        throw new UnreachableException();
                }
                logger.Trace($"Scanned file {dataToScan.FileName} block {dataToScan.BlockNumber} from VM {this.vmName} - {scanResult.ShortResult}");
            }
            catch (ChannelClosedException)
            {
                logger.Warn($"Channel on thread {Environment.CurrentManagedThreadId} was attempting to read while Wait completed");
            }
            finally
            {
                ;
            }
        }
        var completeMsg = new VirusScanCompletedEventArgs()
        {
            CompletedSuccess = true,
            Errors = this.errors,
            Identifyer = this.scannerGuid

        };

        OnScanCompleted(completeMsg);
    }
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

    protected virtual void OnScanCompleted(VirusScanCompletedEventArgs e)
    {
        ScanCompleted?.Invoke(this, e);
    }

    protected virtual void OnVirusFound(VirusFoundEventArgs e)
    {
        VirusFound?.Invoke(this, e);
    }
}