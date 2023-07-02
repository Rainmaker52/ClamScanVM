using DiscUtils;

namespace ClamScanVM;

internal class FileSystemProvider : IDisposable
{
    private readonly string directoryName;
    private readonly List<Stream> openStreams = new();
    private bool disposedValue;

    public FileSystemProvider(string directoryName)
    {
        this.directoryName = directoryName;
    }

    internal IEnumerable<string> FindVMXFiles()
    {
        return Directory.EnumerateFiles(this.directoryName, "*.vmx", SearchOption.AllDirectories);
    }

    internal Stream OpenFile(string fileName)
    {
        var streamOut = new FileStream(fileName, FileMode.Open, FileAccess.Read);

        // The VMDK file itself contains extents on the VMDK "flat" file where the actual data is stored
/*        if (fileName.ToLower().EndsWith(".vmdk"){
            var openedDisk = DiscUtils.Raw.Disk.OpenDisk()

        }
*/
        this.openStreams.Add(streamOut);
        return streamOut;
    }

    internal void CloseFile(Stream stream)
    {
        this.openStreams.Remove(stream);
        stream.Close();
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                if(this.openStreams != null)
                {
                    foreach(var stream in this.openStreams)
                    {
                        stream?.Close();
                    }
                }
            }

            // TODO: free unmanaged resources (unmanaged objects) and override finalizer
            // TODO: set large fields to null
            disposedValue = true;
        }
    }

    // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
    // ~FileSystemProvider()
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
}