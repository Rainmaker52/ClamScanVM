using DiscUtils;

using Microsoft.Win32.SafeHandles;

namespace ClamScanVM;

internal class FileSystemProvider : DiscUtils.FileLocator, IDisposable
{
    private bool disposedValue;
    private string hintPath;

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                // Managed objects
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

    public FileSystemProvider(string hintPath = "")
    {
        this.hintPath = hintPath;
    }

    public override bool Exists(string fileName) 
        => File.Exists(fileName);

    protected override Stream OpenFile(string fileName, FileMode mode, FileAccess access, FileShare share)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        this.hintPath = Path.GetFullPath(fileName);
        return new FileStream(fileName, mode, access, share);
    }

    internal Stream OpenFile(string fileName)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        return this.OpenFile(fileName, FileMode.Open, FileAccess.Read, FileShare.Read);
    }

    public override FileLocator GetRelativeLocator(string path)
        => new FileSystemProvider(Path.GetFullPath(path));

    public override string GetFullPath(string path)
        => Path.GetFullPath(path);

    public override string GetDirectoryFromPath(string path)
        => Path.GetDirectoryName(path) ?? String.Empty;

    public override string GetFileFromPath(string path)
        => Path.GetFileName(path) ?? String.Empty;

    public override DateTime GetLastWriteTimeUtc(string path)
        => File.GetLastWriteTimeUtc(path);

    public override bool HasCommonRoot(FileLocator other)
        => true;

    public override string ResolveRelativePath(string path)
    {
        return Path.Join(this.hintPath, path);
    }

    internal IEnumerable<string> FindVMXFiles()
    {
        return Directory.EnumerateFiles(this.hintPath, "*.vmx", SearchOption.AllDirectories);
    }
}