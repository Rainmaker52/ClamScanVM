using System;

namespace ClamScanVM;
internal interface IFileProvider
{
    internal IEnumerable<Stream> disks { get; set; }
    internal Stream OpenDisk();

    
}
