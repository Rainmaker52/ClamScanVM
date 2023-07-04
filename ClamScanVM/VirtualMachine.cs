using System.Buffers;
using System.ComponentModel.DataAnnotations;
using System.IO.Pipelines;
using System.Text;

using DiscUtils;
using DiscUtils.Streams;
using DiscUtils.Xva;

namespace ClamScanVM;

internal class VirtualMachine : IDisposable
{
    private readonly FileSystemProvider fsProvider;
    private string? vmxFileLocation;
    private readonly Dictionary<string, string> vmxProperties = new();
    private readonly NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

    internal List<DiscUtils.VirtualDisk> Disks { get; private set; } = new();
    internal LogicalVolumeInfo[]? Volumes { get; private set; }
    public string Name { get; init; }

    private bool disposedValue;

    private VirtualMachine(string vmName, FileSystemProvider fsProvider)
    {
        this.Name = vmName;
        this.fsProvider = fsProvider;
    }

    internal async Task OpenVM()
    {
        await FindVMXFile();
        await LoadVMXProperties();
        await OpenDisks();
        await DetectVolumes();

        logger.Info($"Found VM at [{this.vmxFileLocation}]. {this.Disks.Count} disks opened.");
    }

    private async Task DetectVolumes()
    {
        var volumeManager = new DiscUtils.VolumeManager();
        volumeManager.AddDisks(this.Disks);
        this.Volumes = volumeManager.GetLogicalVolumes();
    }

    private async Task OpenDisks()
    {
        foreach(var key in this.vmxProperties.Keys)
        {
            if ((key.StartsWith("scsi") || key.StartsWith("ide")) && key.EndsWith(".fileName") && this.vmxProperties[key].ToLower().EndsWith(".vmdk"))
            {
                var vmDirectory = Path.GetDirectoryName(this.vmxFileLocation);
                var descriptorFile = Path.Join(vmDirectory, this.vmxProperties[key]);

                // The only way to use non-monolithic and non-stream optimized VMDKs is by opening them through a custom DiscFileSystem
                // By giving that methods to resolve files, the OpenDisk() can resolve the files from the extents
                // For local files, the built-in would have worked. But due to how NFS client needs to switch for each file opened, I can implement
                // the NFS version more efficient by using multiple clients in parallel

                // Added bonus - if it happens to be a monolithic VMDK file (unlikely with modern vSphere - more likely with Workstation)
                // this method will open the disk regardless. It also works with 2 GB split VMDK files

                // Bottom line - with a custom DiscFileSystem provider, the OpenDisk() call becomes far more reliable.

                var localReadOnlyDisc = new LocalReadOnlyDiscFilesystem();
                var vmdkDisk = DiscUtils.VirtualDisk.OpenDisk(localReadOnlyDisc, descriptorFile, FileAccess.Read);
                await Console.Out.WriteLineAsync($"Opening {descriptorFile}");

                // This is the complete combined SparseStream, extents etc have been resolved
                this.Disks.Add(vmdkDisk);
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


                // Read the VMX file and compare the displayName of the VM
                // The GUID may be different at this point compared to the time of backup
                // This may require a bit of tweaking, as the displayName may also have been updated to something like CV_VM01_LiveMount

                do
                {
                    // Cannot use TryRead() when the ctor is called with an existing stream
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
                        if (displayName.Equals(this.Name))
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
                if(this.Disks != null)
                {
                    foreach (var disk in this.Disks)
                    {
                        disk?.Dispose();
                    }
                }
                this.fsProvider?.Dispose();
            }

            // free unmanaged resources (unmanaged objects) and override finalizer
            // set large fields to null
            disposedValue = true;
        }
    }

    // override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
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