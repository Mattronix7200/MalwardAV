using System;
using System.Diagnostics;
using System.Threading;
using System.Windows;
using Malward.AppGUI.Services;
using WpfApplication = System.Windows.Application;

namespace Malward.AppGUI;

public partial class App : WpfApplication
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        Ui.Use(new WpfUiThread(Dispatcher));

        DispatcherUnhandledException += (_, ex) => { LogCrash("Dispatcher", ex.Exception); ex.Handled = true; };

        try { StartUi(); }
        catch (Exception ex) { Debug.WriteLine($"[App] window create failed: {ex.Message}"); }

        System.Threading.Tasks.Task.Run(Malward.AppGUI.Services.Startup.AutoRegisterShellMenuOnce);
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static void StartUi() => new ShellWindow(new AppHost()).Show();

    internal static void LogCrash(string tag, Exception? ex, string? note = null)
        => CrashLog.Write(tag, ex, note);
}
