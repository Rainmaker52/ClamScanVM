using NLog;

namespace ClamScanVM;

internal static class ScanManager
{
    private static readonly NLog.Logger logger = LogManager.GetCurrentClassLogger();
    public static void ScanCompleted(object sender, VirusScanCompletedEventArgs e)
    {
        logger.Info($"Scan complete! State is {e.CompletedSuccess}");
    }

    public static void VirusFound(object sender, VirusFoundEventArgs e)
    {
        logger.Fatal("***********************************************************");
        logger.Fatal($"*Virus Found! VM is {e.VMName} - Virus found {e.VirusName}*");
        logger.Fatal("***********************************************************");
    }


}