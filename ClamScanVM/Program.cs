using System;
using System.Buffers;
using System.CommandLine;
using System.Net;
using System.Text;

using DiscUtils;
using DiscUtils.Complete;
using DiscUtils.Nfs;
using DiscUtils.Streams;

using NLog;

using NFSLibrary;
using System.Threading.Channels;
using System.Collections.Concurrent;

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
        SetupHelper.SetupComplete();

        string baseDirectory = @"C:\Temp\VMDKScan";
        string[] vmNames = { "Windows XP Professional", "Rocky9", "StandardLinux", "LVMLinux", "Rocky9", "StandardLinux", "Rocky9", "Rocky9", "Rocky9" };
        clamAVServer = "localhost:3260";
        
        List<Task<(Task<VirusScanner> Scanner, Task<VMDataReader> DataReader)>> allTasks = new();

        var maxTasks = new SemaphoreSlim(5);

        foreach(var vm in vmNames)
        {
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
                await Console.Out.WriteLineAsync($"Maximum number of threads running {allTasks.Count}. Waiting for one to complete");
                var completedTask = await Task.WhenAny(allTasks);
                var intermediateTask = await completedTask;
                var completedScanner = await intermediateTask.Scanner;

                completedScanner.VirusFound -= ScanManager.VirusFound;
                completedScanner.ScanCompleted -= ScanManager.ScanCompleted;
                maxTasks.Release();
                allTasks.Remove(completedTask);
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
            allTasks.Add(newTask);
        }

        await Task.WhenAll(allTasks);

        return 0;

        string nfsServer = "rocky9.mshome.net";
        string exportName = "/srv/nfs";
        //string[] VMDKPaths = new[] { "Disk.vhd" };
        string[] VMDKPaths = new[] { "Debian 11 with spaces in name.vmdk", "Debian 11 with spaces in name - Copy.vmdk" };

        var nfsClient = new NfsClient(NfsClient.NfsVersion.V3);
        var ipAddr = Dns.GetHostAddresses(nfsServer);
        nfsClient.Connect(ipAddr[0]);
        var exports = nfsClient.GetExportedDevices();
        foreach(var export in exports)
        {
            nfsClient.MountDevice(export);
            var searchDirs = new Stack<string>();
            searchDirs.Push(".");
            while(searchDirs.TryPop(out var currentDirectory))
            {
                var itemsInDir = nfsClient.GetItemList(currentDirectory);
                foreach(var item in itemsInDir)
                {
                    Console.WriteLine($"{currentDirectory}/{item}");
                    if (nfsClient.GetItemAttributes(item)?.NFSType == NFSLibrary.Protocols.Commons.NFSItemTypes.NFDIR)
                    {
                        searchDirs.Push($"{item}");
                        continue;
                    }
                    if (VMDKPaths.Contains(item))
                    {
                        var nfsFileStream = new NfsFileStream(item, nfsClient);

                        using var disk = new DiscUtils.Vmdk.Disk(nfsFileStream, Ownership.Dispose);
                        Console.WriteLine(disk.DiskClass);
                        var volmgr = new VolumeManager();
                        _ = volmgr.AddDisk(disk);
                        var pVols = volmgr.GetLogicalVolumes();
                        foreach(var vol in pVols)
                        {
                            var openFS = vol.Open();
                            var filesystemType = DiscUtils.FileSystemManager.DetectFileSystems(openFS);

                            IFileSystem? filesystem = null;
                            switch (filesystemType[0].Name)
                            {
                                case "ext":
                                    filesystem = new DiscUtils.Ext.ExtFileSystem(openFS);
                                    break;
                                case "ntfs":
                                    filesystem = new DiscUtils.Ntfs.NtfsFileSystem(openFS);
                                    break;
                                // Unsupported filesystems which should not fail
                                case "Swap":
                                case "swap":
                                    continue;
                                default:
                                    throw new NotSupportedException($"Filesystem type {filesystemType[0].Name} not supported");

                            }

                            var guestDirs = new Stack<string>();
                            guestDirs.Push("/");
                            while (guestDirs.TryPop(out var currentDir))
                            {
                                foreach (var dir in filesystem.GetDirectories(currentDir))
                                {
                                    guestDirs.Push($"{dir}");
                                    Console.WriteLine($"Newly added: {dir}");
                                }
                                foreach(var file in filesystem.GetFiles(currentDir))
                                {
                                    Console.WriteLine(file);
                                }
                            }
                        }
                    }
                }
            }
        }

        return 0;
        
        foreach (var export in exports)
        {
            Console.WriteLine($"Found export {export}");
            var mount = new DiscUtils.Nfs.NfsFileSystem(nfsServer, "/srv/nfs");

            Console.WriteLine("Mounted!");
            var items = mount.GetFiles(".");

            Console.WriteLine("Retrieved files");

            foreach (var item in items)
            {
                if (!VMDKPaths.Contains(item))
                    continue;

                // Found an item to process

                // Internally, the NFS-Client copies between buffers.
                // If I pass it a stream, it would copy byte[] buffers with size of "blocksize"

                Console.WriteLine($"Processing item {item}");

                //var vDisk = new DiscUtils.Vmdk.DiskImageFile(s, DiscUtils.Streams.Ownership.None);


                var fstream = new FileStream("C:\\Users\\Dannie Obbink\\Downloads\\Debian 11 Server (64bit).vmdk", FileMode.Open, FileAccess.Read);
                var d = new DiscUtils.Vmdk.Disk(fstream, Ownership.Dispose);



                // Ensure Ownership is set to "Dispose". Otherwise, the entire stream is 
                //var d = new DiscUtils.Vmdk.Disk(s, Ownership.Dispose);


                Console.WriteLine("Disk allocated");
                foreach(var partition in d.Partitions.Partitions)
                {


                    Console.WriteLine(partition);
                    var partitionStream = partition.Open();
                    var volmgvolumeManager = new DiscUtils.VolumeManager();
                    //volumeManager.AddDisk()
                    var fs = DiscUtils.FileSystemManager.DetectFileSystems(partitionStream);
                    foreach(var filesystem in fs)
                    {
                        Console.WriteLine(filesystem.Name);
                    }
                }

                








                //Console.WriteLine(d.Partitions.Partitions);


                d.Dispose();
                //vDisk.Dispose();
            }

        }

        //var nfsMount = new NfsFileSystem(nfsServer, exportName);
        //Console.WriteLine(nfsMount.FileExists(VMDKPaths[0]));

        Console.ReadLine();





        return 0;

        /*
        const string connectionString = "tcp://winserver2022:3310";
        const string eicarAvTest = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        //Create a client
        var clamAvClient = ClamAvClient.Create(new Uri(connectionString));

        //Send PING command to ClamAV
        await clamAvClient.PingAsync().ConfigureAwait(false);

        //Get ClamAV engine and virus database version
        var result = await clamAvClient.GetVersionAsync().ConfigureAwait(false);

        Console.WriteLine(
            $"ClamAV version - {result.ProgramVersion} , virus database version {result.VirusDbVersion}");

        await using (var memoryStream = new MemoryStream(Encoding.UTF8.GetBytes(eicarAvTest)))
        {
            //Send a stream to ClamAV scan
            var res = await clamAvClient.ScanDataAsync(memoryStream).ConfigureAwait(false);

            Console.WriteLine($"Scan result : Infected - {res.Infected} , Virus name {res.VirusName}");
        }
        return 0;

        */
    }
}
