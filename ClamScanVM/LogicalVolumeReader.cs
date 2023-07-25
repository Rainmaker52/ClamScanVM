using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

using DiscUtils;

namespace ClamScanVM;
internal class LogicalVolumeReader : IPropagatorBlock<IAsyncEnumerable<LogicalVolumeInfo>, IAsyncEnumerable<VMFileBlock>>, IDisposable
{
    private bool disposedValue;
    private ITargetBlock<IAsyncEnumerable<VMFileBlock>> targetBlock;

    public Task Completion => throw new NotImplementedException();

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                // TODO: dispose managed state (managed objects)
            }

            // TODO: free unmanaged resources (unmanaged objects) and override finalizer
            // TODO: set large fields to null
            disposedValue = true;
        }
    }

    // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
    // ~LogicalVolumeReader()
    // {
    //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
    //     Dispose(disposing: false);
    // }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    public IAsyncEnumerable<VMFileBlock>? ConsumeMessage(DataflowMessageHeader messageHeader, ITargetBlock<IAsyncEnumerable<VMFileBlock>> target, out bool messageConsumed)
    {
        throw new NotImplementedException();
    }

    public IDisposable LinkTo(ITargetBlock<IAsyncEnumerable<VMFileBlock>> target, DataflowLinkOptions linkOptions)
    {
        this.targetBlock = target;
        return this;
    }

    public void ReleaseReservation(DataflowMessageHeader messageHeader, ITargetBlock<IAsyncEnumerable<VMFileBlock>> target)
    {
        throw new NotImplementedException();
    }

    public bool ReserveMessage(DataflowMessageHeader messageHeader, ITargetBlock<IAsyncEnumerable<VMFileBlock>> target)
    {
        throw new NotImplementedException();
    }

    public DataflowMessageStatus OfferMessage(DataflowMessageHeader messageHeader, IAsyncEnumerable<LogicalVolumeInfo> messageValue, ISourceBlock<IAsyncEnumerable<LogicalVolumeInfo>>? source, bool consumeToAccept)
    {
        throw new NotImplementedException();
    }

    public void Complete()
    {
        this.targetBlock.Complete(); 
    }

    public void Fault(Exception exception)
    {
        throw new NotImplementedException();
    }

}