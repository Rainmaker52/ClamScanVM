namespace ClamScanVM;

internal class VirusFoundEventArgs : EventArgs
{
    internal string VMName { get; set; }
    internal string FileName { get; set; }
    internal string VirusName { get; set; }
    internal ulong Offset { get; set; }
}