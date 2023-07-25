﻿using System;
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
using ClamScanVM;
using System.CommandLine.Invocation;

namespace ClamScanVM;

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

        var disposableTracker = new List<IDisposable>();

        // Create the Dataflow pipeline
        var linkOptions = new DataflowLinkOptions() { PropagateCompletion = true };
        var vmFinderFunc = new Func<string, IEnumerable<LogicalVolumeInfo>>(name =>
        {
            var thisVM = VirtualMachine.FindAndOpen(name, new FileSystemProvider(baseDirectory)).Result;
            return thisVM.Volumes;
        });
        var resultSinkFunc = new Action<ScanResult>((scanResult) =>
        {
            switch (scanResult.ShortResult)
            {
                case ScanResultDescription.Clean:
                    // Possible audit action here
                    break;
                case ScanResultDescription.ThreatFound:
                    var e = new VirusFoundEventArgs()
                    {
                        FileName = dataToScan.FileName,
                        VirusName = scanResult.Payload ?? "(Virus name not returned by scanner)",
                        Offset = dataToScan.BlockNumber,
                        VMName = this.vmName
                    };
                    OnVirusFound(e);
                    break;
                case ScanResultDescription.Error:
                    logger.Warn($"Error returned from virusscanner while scanning {dataToScan.FileName} - Response [{scanResult.Payload}]");
                    this.errors.Add(new VirusScanException());
                    break;
                case ScanResultDescription.Unknown:
                    logger.Warn($"Unknown response when scanning {dataToScan.FileName} - Response [{scanResult.Payload}]");
                    break;
                default:
                    throw new UnreachableException();
            }
        });


        var volumeFinder = new TransformManyBlock<string, LogicalVolumeInfo>(vmFinderFunc);


        foreach (var vm in vmNames)
        {
            volumeFinder.Post(vm);
        }

        volumeFinder.Complete();

        await resultSink.Completion;

        return 0;
    }
}

