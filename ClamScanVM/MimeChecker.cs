using System.Collections.Immutable;
using System.Threading.Channels;

using MimeDetective;
using MimeDetective.Storage;

namespace ClamScanVM;


/*
 * Note: Mime-Detective has an "Exhaustive" pack, which is free for personal / non-commercial use
 * but requires a license for commercial use.
 * 
 * To make sure this program can be used in both capacities, the Mime-Detective here uses the "default"
 * pack, which is free to use for all purposes (MIT licensed).
 * 
 * This means this program will only be able to access "common" MIME types, instead of the 14.000+ (!)
 * types in the "exhaustive" pack. I'm not convinced this is needed though - for our purposes, it's
 * sufficient to know whether a file is an executable or compressed archive. Library (DLL / so) would be interesting,
 * but apparantly is in none of the packs.
 * 
 * There may be better libraries out there. This one is well maintained and populair, which is why it
 * was chosen.
 * 
 */

internal class MimeChecker
{
    private readonly ChannelReader<VMFileBlock> reader;
    private readonly ChannelWriter<VMFileBlock> writer;
    private readonly ContentInspector inspector;
    private readonly NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

    public MimeChecker(ChannelReader<VMFileBlock> reader, ChannelWriter<VMFileBlock> writer)
    {
        this.reader = reader;
        this.writer = writer;

        this.inspector = new ContentInspectorBuilder()
        {
            Definitions = MimeDetective.Definitions.Default.All(),
            Parallel = false
        }.Build();
    }

    internal async Task Start()
    {
        // Whether we should scan the incoming block or passthrough to the AV scanner
        var sendToAV = true;
        var previousFile = String.Empty;

        while (await this.reader.WaitToReadAsync())
        {
            var fileBlock = await this.reader.ReadAsync();

            // Is this a subsequent block of a file we've already seen?
            if(fileBlock.FileName != previousFile)
            {
                sendToAV = true;
                previousFile = fileBlock.FileName;
            }

            // Only scan the first block of a file
            if(fileBlock.BlockNumber == 0)
            {
                var result = this.inspector.Inspect(fileBlock.Content.Span.ToImmutableArray());
                if (result.Any())
                {
                    var resultMime = result[0].Definition.File;
                    logger.Trace($"File {fileBlock.FileName} has MIME type {resultMime.MimeType}. {result[0].Points} certainty");

                    // Insert logic to determine whether this should be scanned here
                    sendToAV = true;
                }
                else
                {
                    // Unknown MIME type. Should not be sent to AV
                    sendToAV = false;
                }
            }

            if (sendToAV && await this.writer.WaitToWriteAsync())
            {
                await this.writer.WriteAsync(fileBlock);
            }
        }
        this.writer.Complete();
    }
}