using System;
using System.Threading.Tasks;
using System.Windows.Threading;

namespace Malward.AppGUI.Services;

public sealed class WpfUiThread : IUiThread
{
    private readonly Dispatcher _dispatcher;

    public WpfUiThread(Dispatcher dispatcher) => _dispatcher = dispatcher;

    public bool HasAccess => _dispatcher.CheckAccess();

    public void Send(Action work)
    {
        if (_dispatcher.CheckAccess()) work();
        else _dispatcher.Invoke(work);
    }

    public T Send<T>(Func<T> work)
        => _dispatcher.CheckAccess() ? work() : _dispatcher.Invoke(work);

    public void Post(Action work) => _dispatcher.BeginInvoke(work);

    public Task RunAsync(Action work) => _dispatcher.InvokeAsync(work).Task;

    public Task<T> RunAsync<T>(Func<T> work) => _dispatcher.InvokeAsync(work).Task;

    public void Schedule(TimeSpan delay, TimeSpan interval, Action tick, out IDisposable handle)
    {
        var t = new DispatcherTimer(DispatcherPriority.Background, _dispatcher)
        {
            Interval = interval <= TimeSpan.Zero ? TimeSpan.FromMilliseconds(1) : interval,
        };
        t.Tick += (_, _) => tick();
        t.Start();
        handle = new Zatrzymywacz(t);
    }

    private sealed class Zatrzymywacz : IDisposable
    {
        private readonly DispatcherTimer _t;
        public Zatrzymywacz(DispatcherTimer t) => _t = t;
        public void Dispose() { try { _t.Stop(); } catch { } }
    }
}
