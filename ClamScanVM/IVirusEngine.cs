namespace ClamScanVM;
public interface IVirusEngine
{
    public abstract List<string> AcceptedOptions();
    public abstract Task Initialize(List<KeyValuePair<string, string>> options);
    public abstract Task UnInitialize();
    public abstract Task<bool> TestConnection();
    public abstract Task<ScanResult> ScanBuffer(ReadOnlyMemory<byte> buffer);
}
