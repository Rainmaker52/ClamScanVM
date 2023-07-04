using System.Runtime.Serialization;

namespace ClamScanVM;

public class VirusScanException : Exception
{
    public string FileName { get; private set; }
    public VirusScanException()
    {
    }

    public VirusScanException(string fileName, string message) : base(message)
    {
        this.FileName = fileName;
    }

    public VirusScanException(string? message) : base(message)
    {
    }

    public VirusScanException(string? message, Exception? innerException) : base(message, innerException)
    {
    }

    protected VirusScanException(SerializationInfo info, StreamingContext context) : base(info, context)
    {
    }
}