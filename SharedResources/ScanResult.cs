namespace ClamScanVM;

public enum ScanResultDescription : byte
{
    Unknown = 0,
    Clean = 1,
    ThreatFound = 2,
    Error = 3
}

public record ScanResult(ScanResultDescription ShortResult, string VMName, string FileName, ulong BlockNumber, string? Payload = null);