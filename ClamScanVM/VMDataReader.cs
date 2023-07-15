using System.Buffers;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Threading.Channels;

using DiscUtils;

using NLog;

namespace ClamScanVM;
internal class VMDataReader
{
    private readonly VirtualMachine virtualMachine;
    private readonly ChannelWriter<VMFileBlock> virusScanner;
    NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();
    private const int blockSize = 25 * 1024 * 1024; // 25 MB / the stream limit on ClamAV Docker

    public VMDataReader(VirtualMachine thisVM, ChannelWriter<VMFileBlock> virusScanWriter)
    {
        this.virtualMachine = thisVM;
        this.virusScanner = virusScanWriter;
    }
    internal async Task Start(int maxVolumes)
    {
        if (virtualMachine.Volumes == null || virtualMachine.Volumes.Length == 0)
        {
            throw new OpenVMException($"VM {virtualMachine.Name} - Did not find any recognizable volumes");
        }

        using var maxSimultaneousVolumes = new SemaphoreSlim(maxVolumes);
        var outstandingTasks = new List<Task>();

        foreach (var volume in virtualMachine.Volumes)
        {
            var readyToRun = await maxSimultaneousVolumes.WaitAsync(0);

            if (!readyToRun && outstandingTasks.Count > 0)
            {
                logger.Info("Maximum volume limit reached. Waiting...");
                var completedTask = await Task.WhenAny(outstandingTasks);
                maxSimultaneousVolumes.Release();
                lock (outstandingTasks)
                {
                    outstandingTasks.Remove(completedTask);
                }
                await maxSimultaneousVolumes.WaitAsync();
            }

            var newTask = Task.Run(() => this.ReadVolumeData(volume));

            lock (outstandingTasks)
            {
                outstandingTasks.Add(newTask);
            }
        }
        await Task.WhenAll(outstandingTasks);
        this.virusScanner.Complete();
    }

    private async Task ReadVolumeData(LogicalVolumeInfo volume)
    {
        using var openFS = volume.Open();
        var filesystemType = DiscUtils.FileSystemManager.DetectFileSystems(openFS);

        IFileSystem? filesystem = null;
        if(filesystemType.Count > 1)
        {
            throw new NotSupportedException("Multiple fileystems found on disk");
        }
        switch (filesystemType[0].Name)
        {
            case "ext":
                filesystem = new DiscUtils.Ext.ExtFileSystem(openFS);
                break;
            case "xfs":
                filesystem = new DiscUtils.Xfs.XfsFileSystem(openFS);
                break;
            case "Btrfs":
            case "btrfs":
                filesystem = new DiscUtils.Btrfs.BtrfsFileSystem(openFS);
                break;
            case "NTFS":
            case "ntfs":
                filesystem = new DiscUtils.Ntfs.NtfsFileSystem(openFS);
                break;
            case "fat":
                filesystem = new DiscUtils.Fat.FatFileSystem(openFS);
                break;
            // Unsupported filesystems which should not fail
            case "Swap":
            case "swap":
                return;
            default:
                throw new NotSupportedException($"Filesystem type {filesystemType[0].Name} not supported");
        }

        var guestDirs = new Stack<string>();
        var isUnixFS = filesystem is IUnixFileSystem;

        // DiscUtils always takes the directory separator from the OS it's running on, not the native filesystem one
        guestDirs.Push(Path.DirectorySeparatorChar.ToString());
        while (guestDirs.TryPop(out var currentDir))
        {
            foreach (var entry in filesystem.GetFileSystemEntries(currentDir))
            {
                var entryAttributes = filesystem.GetAttributes(entry);
                if ((entryAttributes & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    guestDirs.Push(entry);
                    continue;
                } 
                if(isUnixFS && (entryAttributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint)
                {
                    // Ignore directory symlinks on Unix. We'll scan the link target anyway
                    // Unsure about Windows. Leave that in for now
                    continue;
                }

                try
                {
                    using var fileHandle = filesystem.OpenFile(entry, FileMode.Open, FileAccess.Read);
                    var fileReader = PipeReader.Create(
                        fileHandle,
                        new StreamPipeReaderOptions(MemoryPool<byte>.Shared, blockSize, blockSize, true)
                    );

                    var blockNumber = 0U;
                    while(await this.virusScanner.WaitToWriteAsync().ConfigureAwait(false))
                    {
                        var readResult = await fileReader.ReadAsync();
                        if(readResult.IsCanceled || readResult.IsCompleted)
                        {
                            break;
                        }
                        if(readResult.Buffer.Length == 0)
                        {
                            // Empty file, does not need to be sent to AV scanner
                            continue;
                        }
                        
                        // Note: we need to pass .ToArray() and have the runtime make a copy.
                        // Immediately passing the ReadOnlyMemory<byte> will cause the buffer to contain garbage
                        // after the AdvanceTo() - when it comes out of the other end of the pipe.
                        // This is sort of expected ("don't use .Buffer after AdvanceTo()") but one might expect an automatic safety copy. It does not.
                        var request = new VMFileBlock(entry, blockNumber, readResult.Buffer.ToArray());
                        await this.virusScanner.WriteAsync(request).ConfigureAwait(false);
                        fileReader.AdvanceTo(readResult.Buffer.End);
                        blockNumber++;
                    }
                    await fileReader.CompleteAsync().ConfigureAwait(false);
                }
                catch (System.IO.FileNotFoundException)
                {
                    // Unresolvable symlink. Which is not interesting for us anyway, as symlinks don't contain data.
                    ;
                }
                catch(Exception e)
                {
                    logger.Error($"Encountered error [{e.Message}] while processing {entry}");
                }
            }
        }
    }
}