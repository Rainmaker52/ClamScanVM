using System.Threading.Channels;

namespace ClamScanVM;
internal class MimeChecker
{
    private readonly ChannelReader<VMFileBlock> reader;
    private readonly ChannelWriter<VMFileBlock> writer;

    public MimeChecker(ChannelReader<VMFileBlock> reader, ChannelWriter<VMFileBlock> writer)
    {
        this.reader = reader;
        this.writer = writer;
    }

    internal async Task Start()
    {
        while (await this.reader.WaitToReadAsync())
        {
            var fileBlock = await this.reader.ReadAsync();



            if(await this.writer.WaitToWriteAsync())
            {
                await this.writer.WriteAsync(fileBlock);
            }
        }
        this.writer.Complete();
    }
}