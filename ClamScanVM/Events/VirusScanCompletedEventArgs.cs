namespace ClamScanVM;

internal class VirusScanCompletedEventArgs : EventArgs
{
    internal bool CompletedSuccess { get; set; }
    internal List<VirusScanException> Errors { get; set; }
}