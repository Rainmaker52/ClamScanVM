using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using NLog;

namespace ClamScanVM;
internal static class Logger
{
    internal static void SetupGlobalLoggingPreferences(bool includeConsoleOutput = false, LogLevel? minimumLogLevel = null, string logDirectory = @"C:\Temp\Logs\")
    {
        var config = new NLog.Config.LoggingConfiguration();

        if(minimumLogLevel  != null )
        {
            minimumLogLevel = LogLevel.Info;
        }

        const string logLayout = "${longdate}|${threadid:padding=-3}|${level:uppercase=true:padding=-5}|${message}";

#if DEBUG
        includeConsoleOutput = true;
        minimumLogLevel = LogLevel.Trace;
#endif

        if (includeConsoleOutput)
        {
            var consoleLogger = new NLog.Targets.ConsoleTarget("console");
            consoleLogger.Layout = logLayout;
            config.AddRule(minimumLogLevel, LogLevel.Fatal, consoleLogger);
        }

        var currentTime = DateTime.UtcNow.ToString("s");
        string fullLogPath = Path.Join(logDirectory, currentTime).Replace(':', '_');

        if (!Path.Exists(fullLogPath))
        {
            Directory.CreateDirectory(fullLogPath);
        }

        var fileTarget = new NLog.Targets.FileTarget("file");
        fileTarget.FileName = $$$"""{{{fullLogPath}}}/${level}.log""";
        fileTarget.Layout = logLayout;
        config.AddRule(minimumLogLevel, LogLevel.Fatal, fileTarget);

        NLog.LogManager.Configuration = config;
    }
}
