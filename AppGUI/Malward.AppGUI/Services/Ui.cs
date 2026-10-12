using System;
using System.Threading;
using System.Threading.Tasks;

namespace Malward.AppGUI.Services;

public interface IUiThread
{
    bool HasAccess { get; }
    void Send(Action work);
    T Send<T>(Func<T> work);
    void Post(Action work);
    Task RunAsync(Action work);
    Task<T> RunAsync<T>(Func<T> work);
    void Schedule(TimeSpan delay, TimeSpan interval, Action tick, out IDisposable handle);
}

public static class Ui
{
    private static IUiThread? _current;

    public static IUiThread Current =>
        _current ?? throw new InvalidOperationException("Wątek interfejsu nie został ustawiony.");

    public static bool IsSet => _current != null;

    public static void Use(IUiThread thread) => _current = thread;

    public static bool HasAccess => _current?.HasAccess ?? true;

    public static void Send(Action work) => Current.Send(work);
    public static T Send<T>(Func<T> work) => Current.Send(work);
    public static void Post(Action work) => Current.Post(work);
    public static Task RunAsync(Action work) => Current.RunAsync(work);
    public static Task<T> RunAsync<T>(Func<T> work) => Current.RunAsync(work);
}

public sealed class UiTimer : IDisposable
{
    private IDisposable? _handle;
    private int _running;

    public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(1);
    public bool IsEnabled { get; private set; }
    public event EventHandler? Tick;

    public void Start()
    {
        Stop();
        if (Interval <= TimeSpan.Zero) Interval = TimeSpan.FromMilliseconds(1);
        IsEnabled = true;
        Ui.Current.Schedule(Interval, Interval, Fire, out var h);
        _handle = h;
    }

    public void Stop()
    {
        IsEnabled = false;
        var h = Interlocked.Exchange(ref _handle, null);
        try { h?.Dispose(); } catch { }
    }

    private void Fire()
    {
        if (!IsEnabled) return;
        if (Interlocked.Exchange(ref _running, 1) == 1) return;
        try { Tick?.Invoke(this, EventArgs.Empty); }
        catch { }
        finally { Volatile.Write(ref _running, 0); }
    }

    public void Dispose() => Stop();
}
