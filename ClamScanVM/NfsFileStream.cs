using System.Buffers;

using NFSLibrary;

namespace ClamScanVM;

internal sealed class NfsFileStream : Stream
{
    private readonly string fileName;
    private readonly NfsClient nfsClient;

    public NfsFileStream(string fileName, NfsClient filesystem)
    {
        this.fileName = fileName;
        this.nfsClient = filesystem;
    }

    public override bool CanRead => true;

    public override bool CanSeek => true;

    public override bool CanWrite => false;

    public override long Length => this.nfsClient.GetItemAttributes(this.fileName).Size;

    public override long Position { get; set; }

    public override void Flush()
    {
        throw new NotImplementedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var tempBuffer = ArrayPool<byte>.Shared.Rent(count);
        try
        {
            var dataRead = this.nfsClient.Read(this.fileName, this.Position, count, ref tempBuffer);
            Buffer.BlockCopy(tempBuffer, 0, buffer, offset, (int)dataRead);
            this.Position += dataRead;

            return (int)dataRead;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(tempBuffer, true);
        }
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        switch (origin)
        {
            case SeekOrigin.Begin:
                this.Position = offset;
                break;
            case SeekOrigin.End:
                this.Position = this.Length - offset;
                break;
            case SeekOrigin.Current:
                this.Position += offset;
                break;
            default:
                throw new NotImplementedException();
        }
        return this.Position;
    }

    public override void SetLength(long value)
    {
        throw new NotImplementedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotImplementedException();
    }
}
