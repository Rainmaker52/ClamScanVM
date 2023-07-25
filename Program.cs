using System;
using System.Buffers;
using System.CommandLine;
using DiscUtils.Complete;
using NLog;
using System.Threading.Channels;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Tasks.Dataflow;
using DiscUtils;

class Program
{
    static async Task<int> Main(string[] args)
    {
        var command = new RootCommand
        {
            new Option<string>("--nfs-export"),
            new Option<string>("--cs-api-endpoint"),
            new Option<string>("--clamav-server"),
            new Option<bool>("--ignore-certificate-errors")
        };

        command.Description = "Your program's description here";

        command.Handler = CommandHandler.Create(async (string nfsExport, string csAPIEndpoint, string clamAVServer, bool ignoreCertificateErrors) =>
        {
            return await MainAsync(nfsExport, csAPIEndpoint, clamAVServer, ignoreCertificateErrors);
        });

        return await command.InvokeAsync(args);
    }

    private static async Task<int> MainAsync(string nfsExport, string csAPIEndpoint, string clamAVServer, bool ignoreCertificateErrors)
    {
        Logger.SetupGlobalLoggingPreferences();

        NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

        var totalRuntimeStopwatch = Stopwatch.StartNew();

        SetupHelper.SetupComplete();

        string baseDirectory = @"C:\Temp\VMDKScan";
        string[] vmNames = { "LVMLinux", "Windows XP Professional", "Rocky9", "StandardLinux" };

        var scannerEngine = typeof(AMSIEngine);
        var scannerOptions = String.Empty;

        var simultaneousVMs = 10;
        var simultaneousVolumesPerVM = 1;
        var scanThreadsPerVM = 10;

        var enableMimeCheck = true;

        var avEngineOptions = new List<KeyValuePair<string, string>>();

        // Scanner options are global
        foreach (var option in scannerOptions.Split(';'))
        {
            if (option == "")
            {
                continue;
            }
            var k = option.Split('=')[0];
            var v = option.Split("=")[1];

            avEngineOptions.Add(KeyValuePair.Create(k, v));
        }

        // Create the Dataflow pipeline
        var linkOptions = new DataflowLinkOptions() { PropagateCompletion = true };
        var vmFinderFunc = new Func<string, IEnumerable<LogicalVolumeInfo>>(name =>
        {
            var thisVM = VirtualMachine.FindAndOpen(name, new FileSystemProvider(baseDirectory)).Result;
            return thisVM.Volumes;
        });
        var fileReaderTransform = new TransformBlock<LogicalVolumeInfo, VMFileBlock>(logicalvolume => null);
        var fileScannerTransform = new TransformBlock<VMFileBlock, VMFileBlock>(fileBlock => null);
        var fileWriterAction = new ActionBlock<VMFileBlock>(fileBlock =>
        {
            if (fileBlock != null)
            {
                Console.WriteLine(fileBlock.LogicalVolume.VolumeName + ":" + fileBlock.FilePath);
            }
        });

        var vmFinder = new TransformBlock<string, IEnumerable<LogicalVolumeInfo>>(vmFinderFunc);

        vmFinder.LinkTo(fileReaderTransform, linkOptions);
        fileReaderTransform.LinkTo(fileScannerTransform, linkOptions);
        fileScannerTransform.LinkTo(fileWriterAction, linkOptions);

        foreach (var vm in vmNames)
        {
            vmFinder.Post(vm);
        }

        vmFinder.Complete();

        await fileWriterAction.Completion;

        return 0;
    }
}

