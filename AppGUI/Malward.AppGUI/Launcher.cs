using System;
using System.Runtime.CompilerServices;
using System.Threading;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public static class Launcher
{
    private static Mutex? _mutex;

    [STAThread]
    public static int Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException +=
            (_, e) => CrashLog.Write("AppDomain", e.ExceptionObject as Exception);

        if (!Startup.IsHeadlessCommand(args))
        {
            _mutex = new Mutex(initiallyOwned: true, Startup.MutexName, out bool created);
            if (!created)
            {
                Startup.ForwardScanRequest(args);
                try { Startup.ActivateExistingInstance(); } catch { }
                return 0;
            }
        }

        Startup.EnsureProgramDataWritable();

        try
        {
            if (Startup.WebModeRequested()) return RunHeadless();
            return RunWindowed(args);
        }
        finally
        {
            try { _mutex?.ReleaseMutex(); } catch { }
            _mutex?.Dispose();
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int RunHeadless()
    {
        var pompa = new PumpUiThread();
        Ui.Use(pompa);

        AppHost? host = null;
        pompa.Post(() =>
        {
            try
            {
                host = new AppHost();
                _ = host.ShellLoadedAsync();
            }
            catch (Exception ex) { CrashLog.Write("headless-start", ex, null); }
        });

        ThreadPool.QueueUserWorkItem(_ => Startup.AutoRegisterShellMenuOnce());

        pompa.Run();

        return 0;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int RunWindowed(string[] args)
    {
        var app = new App();
        app.InitializeComponent();
        return app.Run();
    }
}
