using System.Runtime.Serialization;

namespace ClamScanVM;
[Serializable]
public class OpenVMException : Exception
{
    public OpenVMException()
    {
    }

    public OpenVMException(string? message) : base(message)
    {
    }

    public OpenVMException(string? message, Exception? innerException) : base(message, innerException)
    {
    }

    protected OpenVMException(SerializationInfo info, StreamingContext context) : base(info, context)
    {
    }
}