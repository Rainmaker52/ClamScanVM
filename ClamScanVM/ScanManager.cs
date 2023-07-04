namespace ClamScanVM;

internal static class ScanManager
{
    public static void ScanCompleted(object sender, VirusScanCompletedEventArgs e)
    {
        Console.WriteLine($"Scan complete! State is {e.CompletedSuccess}");
    }

    public static void VirusFound(object sender, VirusFoundEventArgs e)
    {
        Console.WriteLine($"Virus Found! VM is {e.VMName} - Virus found {e.VirusName}");
    }


}