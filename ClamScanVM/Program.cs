using System;
using System.Buffers;
using System.CommandLine;

using DiscUtils.Complete;

using NLog;

using System.Threading.Channels;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace ClamScanVM;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var returnCode = 0;
        var rootCommand = new RootCommand(
            "Scans Virtual Machine files for viruses using ClamAV directly from a local filesystem or NFS mount" +
            "Ideally, the servers should be shutdown, but this is not required");

        var export = new Option<string>(
            aliases: new[] { "--nfsmount", "-m" },
            description: "The NFS Server and share the 3DFS server is exporting");
        rootCommand.AddOption(export);

        var csAPI = new Option<string>(
            aliases: new[] { "--commserve", "-cs" },
            description: "The API endpoint. Use the form https://webconsole.domain.com/api/ or http://webserver.domain.com:81/SearchSvc/CVWebService.svc/. Note that the HTTPS certificate must be trusted");
        rootCommand.AddOption(csAPI);

        var clamAPI = new Option<string>(
            aliases: new[] { "--clamserver" },
            getDefaultValue:
                () =>
                {
                    // Unfortunately, ClamAV on Windows does not support Unix Domain sockets, even though the OS may (Windows 2019+)
                    // When starting the daemon, no socket file is created.
                    if (OperatingSystem.IsWindows())
                        return "localhost:3311";
                    else
                        return "/var/run/clamav/clamd.socket";
                },
            description: "The ClamAV server endpoint");

        rootCommand.AddOption(clamAPI);

        var ignoreCertError = new Option<bool>(
            aliases: new[] { "--ignore-certificate-errors" },
            getDefaultValue: () => false,
            description: "Whether or not to ignore certificate errors towards the Commvault API");
        rootCommand.AddOption(ignoreCertError);

        var cvUser = new Option<string>(
            aliases: new[] { "--username" },
            getDefaultValue: () => "admin",
            description: "The username to authenticate to the Commvault API");
        rootCommand.AddOption(cvUser);

        var cvPassword = new Option<string>(
            aliases: new[] { "--password" },
            description: "The password to authenticate to the Commvault API");
        rootCommand.AddOption(cvPassword);

        rootCommand.SetHandler((context) =>
            MainAsync
            (
                context.ParseResult.GetValueForOption(export)!,
                context.ParseResult.GetValueForOption(csAPI)!,
                context.ParseResult.GetValueForOption(clamAPI)!,
                context.ParseResult.GetValueForOption(ignoreCertError)
            ));

        return await rootCommand.InvokeAsync(args);
    }

    private static async Task<int> MainAsync(string nfsExport, string csAPIEndpoint, string clamAVServer, bool ignoreCertificateErrors)
    {
        Logger.SetupGlobalLoggingPreferences();

        NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

        var totalRuntimeStopwatch = Stopwatch.StartNew();

        SetupHelper.SetupComplete();


        // These should be commandline options ----
        string baseDirectory = @"C:\Temp\VMDKScan";
        //string[] vmNames = { "LVMLinux", "Windows XP Professional", "Rocky9", "StandardLinux"};
        //string[] vmNames = { "Rocky9", "LVMLinux", "Rocky9", "Rocky9", "Rocky9" };
        string[] vmNames = { "Rocky9" };
        //string[] vmNames = { "Windows XP Professional" };
        logger.Info("Base directory is {0}", baseDirectory);

        var scannerEngine = typeof(AMSIEngine);
        var scannerOptions = String.Empty;

        //var scannerEngine = typeof(ClamEngine);
        //var scannerOptions = "Server=127.0.0.1;Port=3260";

        var simultaneousVMs = 10;
        var simultaneousVolumesPerVM = 1;
        var scanThreadsPerVM = 10;

        var enableMimeCheck = true;

        // End these should be commandline options

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


        List<Task> runningTasks = new();
        ConcurrentDictionary<int, VirusScanner<IVirusEngine>> scannerInstances = new();
        using var maxTasks = new SemaphoreSlim(simultaneousVMs);

        foreach(var vm in vmNames)
        {
            var hasPermissionToRun = await maxTasks.WaitAsync(0);

            if (!hasPermissionToRun && runningTasks.Count > 0)
            {
                logger.Info($"Maximum number of VMs running [{runningTasks.Count}]. Waiting for one to complete");
                var completedTask = await Task.WhenAny(runningTasks);

                maxTasks.Release();
                lock (runningTasks)
                {
                    runningTasks.Remove(completedTask);
                }
                scannerInstances.Remove(completedTask.Id, out var completedObject);
                if(completedObject != null)
                {
                    completedObject.VirusFound -= ScanManager.VirusFound;
                    completedObject.ScanCompleted -= ScanManager.ScanCompleted;
                }
                else
                {
                    logger.Warn($"Possible memory leak detected");
                }

                await maxTasks.WaitAsync();
            }


            // This determines the maximum amount of memory used.
            // The producer (datareader) can keep producing, while the consumer (VirusScanner) is behind
            // up to these number of object. Every object is a maximum of 2 MB.
            // So a value of 1024 means there could be a max of 2 GB of memory used while the scanner is catching up.
            var communicationChannel = Channel.CreateBounded<VMFileBlock>(
                new BoundedChannelOptions(1024)
                {
                    SingleReader = false,
                    SingleWriter = false,
                    FullMode = BoundedChannelFullMode.Wait
                });


            VirusScanner<IVirusEngine> scanner;
            MimeChecker? mimeChecker = null;
            if (enableMimeCheck)
            {
                var intermediateCommChannel = Channel.CreateBounded<VMFileBlock>(
                    new BoundedChannelOptions(1024)
                    {
                        SingleReader = false,
                        SingleWriter = false,
                        FullMode = BoundedChannelFullMode.Wait
                    });

                mimeChecker = new MimeChecker(communicationChannel.Reader, intermediateCommChannel.Writer);
                scanner = new VirusScanner<IVirusEngine>(vm, intermediateCommChannel.Reader, scannerEngine, scanThreadsPerVM);
            }
            else
            {
                scanner = new VirusScanner<IVirusEngine>(vm, communicationChannel.Reader, scannerEngine, scanThreadsPerVM);
            }

            using var fsProvider = new FileSystemProvider(baseDirectory);

            var thisVM = await VirtualMachine.FindAndOpen(vm, fsProvider);
            var dataReader = new VMDataReader(thisVM, communicationChannel.Writer);

            scanner.ScanCompleted += ScanManager.ScanCompleted;
            scanner.VirusFound += ScanManager.VirusFound;

            var newTask = Task.Run(async () =>
            {
                var subTasks = new List<Task>
                {
                    dataReader.Start(simultaneousVolumesPerVM),
                    scanner.Start(avEngineOptions)
                };
                if(mimeChecker is not null)
                {
                    subTasks.Add(mimeChecker.Start());
                }

                await Task.WhenAll(subTasks);
            });
            
            lock (runningTasks)
            {
                runningTasks.Add(newTask);
            }

            scannerInstances.TryAdd(newTask.Id, scanner);
        }

        await Task.WhenAll(runningTasks);
        foreach(var instance in scannerInstances)
        {
            instance.Value.VirusFound -= ScanManager.VirusFound;
            instance.Value.ScanCompleted -= ScanManager.ScanCompleted;
        }

        logger.Info($"Full runtime of {vmNames.Length} VMs {totalRuntimeStopwatch.Elapsed}");
        return 0;
    }
}
