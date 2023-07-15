using System.Threading.Channels;

namespace PipeTester;

internal class Program
{
    static async Task Main(string[] args)
    {
        var runningTasks = new List<Task>();
        var channel = Channel.CreateBounded<int>(
            new BoundedChannelOptions(10)
            {
                AllowSynchronousContinuations = true,
                FullMode = BoundedChannelFullMode.Wait
            });

        var writer = new IntWriter(channel.Writer);
        var reader = new IntReader(channel.Reader);

        runningTasks.Add(reader.Start());
        runningTasks.Add(writer.Start());
        await Task.WhenAll(runningTasks);
    }
}

internal class IntReader
{
    private readonly ChannelReader<int> reader;

    public IntReader(ChannelReader<int> reader)
    {
        this.reader = reader;
    }
    internal async Task Start()
    {
        var countedItems = 0;
        while (await this.reader.WaitToReadAsync())
        {
            var thisItem = await this.reader.ReadAsync();
            if(thisItem % 100 == 0)
            {
                await Console.Out.WriteLineAsync($"At item {thisItem}");
            }
            await Task.Delay(50);
            countedItems++;
        }

        await Console.Out.WriteLineAsync($"Counted items from reader {countedItems}");
    }
}

internal class IntWriter
{
    private readonly ChannelWriter<int> writer;

    public IntWriter(ChannelWriter<int> writer)
    {
        this.writer = writer;
    }

    internal async Task Start()
    {
        var countedItems = 0;

        for(var i = 0; i < 1000; i++)
        {
            await this.writer.WaitToWriteAsync();
            await this.writer.WriteAsync(i);
            countedItems++;
        }
        this.writer.Complete();

        await Console.Out.WriteLineAsync($"Items {countedItems} from writer");
    }
}