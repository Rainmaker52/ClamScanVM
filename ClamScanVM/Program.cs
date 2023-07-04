using System;
using System.Buffers;
using System.CommandLine;

using DiscUtils.Complete;

using NLog;

using System.Threading.Channels;
using System.Diagnostics;

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
            description: "The ClamAV server endpoint",
            getDefaultValue:
                () =>
                {
                    // Unfortunately, ClamAV on Windows does not support Unix Domain sockets, even though the OS may (Windows 2019+)
                    // When starting the daemon, no socket file is created.
                    if (OperatingSystem.IsWindows())
                        return "tcp://localhost:3311";
                    else
                        return "/var/run/clamav/clamd.socket";
                });

        rootCommand.AddOption(clamAPI);

        var ignoreCertError = new Option<bool>(
            aliases: new[] { "--ignore-certificate-errors" },
            description: "Whether or not to ignore certificate errors towards the Commvault API",
            getDefaultValue: () => false);
        rootCommand.AddOption(ignoreCertError);

        var cvUser = new Option<string>(
            aliases: new[] { "--username" },
            description: "The username to authenticate to the Commvault API",
            getDefaultValue: () => "admin");
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

        returnCode = await rootCommand.InvokeAsync(args);
        return returnCode;
    }

    private static async Task<int> MainAsync(string nfsExport, string csAPIEndpoint, string clamAVServer, bool ignoreCertificateErrors)
    {
        Logger.SetupGlobalLoggingPreferences();

        NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

        var totalRuntimeStopwatch = Stopwatch.StartNew();

        SetupHelper.SetupComplete();

        string baseDirectory = @"C:\Temp\VMDKScan";
        //string[] vmNames = { "LVMLinux", "Windows XP Professional", "Rocky9", "StandardLinux"};
        //string[] vmNames = { "LVMLinux" };
        string[] vmNames = { "Windows XP Professional" };
        clamAVServer = "localhost:3260";
        logger.Info("Base directory is {0}", baseDirectory);

        List<Task<(Task<VirusScanner> Scanner, Task<VMDataReader> DataReader)>> allTasks = new();

        using var maxTasks = new SemaphoreSlim(1);

        foreach(var vm in vmNames)
        {
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

            using var fsProvider = new FileSystemProvider(baseDirectory);

            var hasPermissionToRun = await maxTasks.WaitAsync(0);

            if (!hasPermissionToRun && allTasks.Count > 0)
            {
                logger.Info($"Maximum number of threads running {allTasks.Count}. Waiting for one to complete");
                var completedTask = await Task.WhenAny(allTasks);
                var intermediateTask = await completedTask;
                var completedScanner = await intermediateTask.Scanner;

                completedScanner.VirusFound -= ScanManager.VirusFound;
                completedScanner.ScanCompleted -= ScanManager.ScanCompleted;
                maxTasks.Release();
                lock (allTasks)
                {
                    allTasks.Remove(completedTask);
                }
                await maxTasks.WaitAsync();
            }

            var newTask = Task.Run(async () =>
            {
                var thisVM = await VirtualMachine.FindAndOpen(vm, fsProvider);
                var dataReader = new VMDataReader(thisVM, communicationChannel.Writer);
                var scanner = new VirusScanner(thisVM.Name, communicationChannel.Reader, clamAVServer);

                scanner.ScanCompleted += ScanManager.ScanCompleted;
                scanner.VirusFound += ScanManager.VirusFound;

                return (scanner.Start(), dataReader.Start());
            });
            lock (allTasks)
            {
                allTasks.Add(newTask);
            }
        }

        var tupleTasks = await Task.WhenAll(allTasks);
        var tasks1 = new List<Task<VirusScanner>>();
        var tasks2 = new List<Task<VMDataReader>>();

        foreach(var t in tupleTasks)
        {
            tasks1.Add(t.Scanner);
            tasks2.Add(t.DataReader);
        }
        await Task.WhenAll(tasks1);
        await Task.WhenAll(tasks2);
       
        logger.Info($"Full runtime of {vmNames.Length} VMs {totalRuntimeStopwatch.Elapsed}");
        return 0;
    }
}
