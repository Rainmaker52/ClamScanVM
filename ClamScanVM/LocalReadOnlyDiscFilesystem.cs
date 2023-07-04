using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using DiscUtils.Streams;

namespace ClamScanVM;
internal class LocalReadOnlyDiscFilesystem : DiscUtils.ReadOnlyDiscFileSystem
{
    public override string FriendlyName => "LocalFileSystem";

    public override long Size => 1 * 1024 * 1024 * 1024;

    public override long UsedSpace => 1 * 1024 * 1024;

    public override long AvailableSpace => this.Size - this.UsedSpace;

    public override bool DirectoryExists(string path)
    {
        return Directory.Exists(path);
    }

    public override bool FileExists(string path)
    {
        return File.Exists(path);
    }

    public override FileAttributes GetAttributes(string path)
    {
        return File.GetAttributes(path);
    }

    public override DateTime GetCreationTimeUtc(string path)
    {
        return File.GetCreationTimeUtc(path);
    }

    public override IEnumerable<string> GetDirectories(string path, string searchPattern, SearchOption searchOption)
    {
        return Directory.EnumerateDirectories(path, searchPattern, searchOption);
    }

    public override long GetFileLength(string path)
    {
        return new FileInfo(path).Length;
    }

    public override IEnumerable<string> GetFiles(string path, string searchPattern, SearchOption searchOption)
    {
        return Directory.EnumerateFiles(path, searchPattern, searchOption);
    }

    public override IEnumerable<string> GetFileSystemEntries(string path)
    {
        return Directory.EnumerateFileSystemEntries(path);
    }

    public override IEnumerable<string> GetFileSystemEntries(string path, string searchPattern)
    {
        return Directory.EnumerateFileSystemEntries(path, searchPattern);
    }

    public override DateTime GetLastAccessTimeUtc(string path)
    {
        return File.GetLastAccessTimeUtc(path);
    }

    public override DateTime GetLastWriteTimeUtc(string path)
    {
        return File.GetLastWriteTimeUtc(path);
    }

    public override SparseStream OpenFile(string path, FileMode mode, FileAccess access)
    {
        var fStream = new FileStream(path, mode, access);
        var sStream = SparseStream.FromStream(fStream, Ownership.Dispose);
        return SparseStream.ReadOnly(sStream, Ownership.Dispose);
    }

}
