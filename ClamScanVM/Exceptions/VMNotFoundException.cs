using System.Runtime.Serialization;

namespace ClamScanVM;
[Serializable]
public class VMNotFoundException : Exception
{
    public VMNotFoundException()
    {
    }

    public VMNotFoundException(string? message) : base(message)
    {
    }

    public VMNotFoundException(string? message, Exception? innerException) : base(message, innerException)
    {
    }

    protected VMNotFoundException(SerializationInfo info, StreamingContext context) : base(info, context)
    {
    }
}