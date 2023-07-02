using System.Buffers;
using System.IO.Pipelines;
using System.Text;

using DiscUtils.Streams;

namespace ClamScanVM;

internal class VirtualMachine : IDisposable
{
    private readonly string virtualMachineName;
    private readonly FileSystemProvider fsProvider;
    private string? vmxFileLocation;
    private readonly Dictionary<string, string> vmxProperties = new();
    internal List<DiscUtils.Vmdk.Disk> disks = new();
    private bool disposedValue;

    private VirtualMachine(string vmName, FileSystemProvider fsProvider)
    {
        this.virtualMachineName = vmName;
        this.fsProvider = fsProvider;
    }

    internal async Task OpenVM()
    {
        await FindVMXFile();
        await LoadVMXProperties();
        await OpenDisks();

        Console.WriteLine($"Found VM at [{this.vmxFileLocation}]. {this.disks.Count} disks opened.");
    }

    private async Task OpenDisks()
    {
        foreach(var key in this.vmxProperties.Keys)
        {
            if ((key.StartsWith("scsi") || key.StartsWith("ide")) && key.EndsWith(".fileName") && this.vmxProperties[key].ToLower().EndsWith(".vmdk"))
            {
                var vmDirectory = Path.GetDirectoryName(this.vmxFileLocation);
                var descriptorFile = Path.Join(vmDirectory, this.vmxProperties[key]);
                using var descriptorStream = this.fsProvider.OpenFile(descriptorFile);
                var descriptor = new DiscUtils.Vmdk.DiskImageFile(descriptorStream, Ownership.Dispose);
                
                
                
                
                await Console.Out.WriteLineAsync($"Opening {descriptorFile}");
                var diskStream = this.fsProvider.OpenFile(descriptorFile);
                var disk = new DiscUtils.Vmdk.Disk(diskStream, Ownership.Dispose);
                this.disks.Add(disk);
            }
        }
    }

    private async Task FindVMXFile()
    {
        foreach (var vmxFile in this.fsProvider.FindVMXFiles())
        {
            try
            {
                var fileStream = this.fsProvider.OpenFile(vmxFile);
                var pipeReader = PipeReader.Create(fileStream);

                do
                {
                    // Cannot use TryRead() when the intiator is called with an existing stream
                    var readResult = await pipeReader.ReadAsync();
                    if (readResult.IsCanceled || readResult.IsCompleted)
                    {
                        break;
                    }

                    var newlinePos = readResult.Buffer.PositionOf((byte)0x0a);
                    // Was newline character found
                    if (newlinePos == null)
                    {
                        // We did not get a full line. Try again
                        pipeReader.AdvanceTo(readResult.Buffer.Start, readResult.Buffer.End);
                        continue;
                    }

                    var fullLine = Encoding.UTF8.GetString(readResult.Buffer.Slice(0, newlinePos.Value));
                    if (fullLine.StartsWith("displayName"))
                    {
                        var displayName = fullLine.Split("=")[1].Trim().Trim('\"');
                        if (displayName.Equals(this.virtualMachineName))
                        {
                            this.vmxFileLocation = vmxFile;
                            break;
                        }

                        // If we passed the displayName, there's no point in reading more from the file
                        pipeReader.Complete();
                        break;
                    }
                    // Advance the pipe to 1 position beyond the current newline
                    pipeReader.AdvanceTo(readResult.Buffer.GetPosition(1, newlinePos.Value));
                } while (true);
            }
            catch (InvalidOperationException)
            {

                throw new VMNotFoundException();
            }
        }
    }
    private async Task LoadVMXProperties()
    {
        try
        {
            var fileStream = this.fsProvider.OpenFile(this.vmxFileLocation);
            var pipeReader = PipeReader.Create(fileStream);

            do
            {
                var readResult = await pipeReader.ReadAsync();
                if (readResult.IsCanceled || readResult.IsCompleted)
                {
                    break;
                }

                var newlinePos = readResult.Buffer.PositionOf((byte)0x0a);
                // Was newline character found
                if (newlinePos == null)
                {
                    // We did not get a full line. Try again
                    pipeReader.AdvanceTo(readResult.Buffer.Start, readResult.Buffer.End);
                    continue;
                }

                var fullLine = Encoding.UTF8.GetString(readResult.Buffer.Slice(0, newlinePos.Value)).Trim();
                if (String.IsNullOrEmpty(fullLine))
                {
                    continue;
                }

                var keyName = fullLine.Split("=")[0].Trim();
                var keyValue = fullLine.Split("=")[1].Trim().Trim('\"');

                if(!this.vmxProperties.TryAdd(keyName, keyValue))
                {
                    await Console.Out.WriteLineAsync($"Failed to write property {keyName}");
                }

                // Advance the pipe to 1 position beyond the current newline
                pipeReader.AdvanceTo(readResult.Buffer.GetPosition(1, newlinePos.Value));
            } while (true);
        }
        catch (InvalidOperationException)
        {

            // End of file reached. Do nothing
        }
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                if(this.disks != null)
                {
                    foreach (var disk in this.disks)
                    {
                        disk?.Dispose();
                    }
                }
                this.fsProvider?.Dispose();
            }

            // TODO: free unmanaged resources (unmanaged objects) and override finalizer
            // TODO: set large fields to null
            disposedValue = true;
        }
    }

    // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
    // ~VirtualMachine()
    // {
    //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
    //     Dispose(disposing: false);
    // }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    internal static async Task<VirtualMachine> FindAndOpen(string vmName, FileSystemProvider fsProvider)
    {
        var vm = new VirtualMachine(vmName, fsProvider);
        await vm.OpenVM();
        return vm;
    }
}