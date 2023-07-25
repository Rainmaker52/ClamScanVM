using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

using DiscUtils;

namespace ClamScanVM;

internal class VMActor : IPropagatorBlock<VMActorParameters, VirtualMachine>, IDisposable
{
    private static readonly NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();
    private ITargetBlock<VirtualMachine> targetBlock;
    private bool disposedValue;

    public Task Completion => targetBlock.Completion;

    public void Complete()
    {
        this.targetBlock.Complete();
    }

    public VirtualMachine? ConsumeMessage(DataflowMessageHeader messageHeader, ITargetBlock<VirtualMachine> target, out bool messageConsumed)
    {
        throw new NotImplementedException();
    }

    public void Fault(Exception exception)
    {
        throw new NotImplementedException();
    }

    public IDisposable LinkTo(ITargetBlock<VirtualMachine> target, DataflowLinkOptions linkOptions)
    {
        this.targetBlock = target;
        return this;

    }

    public DataflowMessageStatus OfferMessage(DataflowMessageHeader messageHeader, VMActorParameters messageValue, ISourceBlock<VMActorParameters>? source, bool consumeToAccept)
    {
        Console.WriteLine($"Received {messageValue} from block [{source}] with ID {messageHeader.Id}. Consume is set to {consumeToAccept}");
        var myVM = VirtualMachine.FindAndOpen(messageValue.vmName, new FileSystemProvider(messageValue.baseDirectory)).Result;
        logger.Info($"Processing {messageHeader.Id}");
        return this.targetBlock.OfferMessage(messageHeader, myVM, this, false);
    }

    public void ReleaseReservation(DataflowMessageHeader messageHeader, ITargetBlock<VirtualMachine> target)
    {
        throw new NotImplementedException();
    }

    public bool ReserveMessage(DataflowMessageHeader messageHeader, ITargetBlock<VirtualMachine> target)
    {
        throw new NotImplementedException();
    }

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
    // ~VMActor()
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
}
