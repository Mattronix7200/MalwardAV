using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace Malward.AppGUI.Services;

public sealed class PumpUiThread : IUiThread
{
    private readonly BlockingCollection<Action> _queue = new(new ConcurrentQueue<Action>());
    private readonly int _threadId;
    private volatile bool _stopped;

    public PumpUiThread() => _threadId = Environment.CurrentManagedThreadId;

    public bool HasAccess => Environment.CurrentManagedThreadId == _threadId;

    public void Run(CancellationToken ct = default)
    {
        try
        {
            foreach (var work in _queue.GetConsumingEnumerable(ct))
            {
                try { work(); }
                catch (Exception ex) { CrashLog.Write("ui-pump", ex, null); }
            }
        }
        catch (OperationCanceledException) { }
        catch (InvalidOperationException) { }
    }

    public void Shutdown()
    {
        _stopped = true;
        try { _queue.CompleteAdding(); } catch { }
    }

    private void Enqueue(Action work)
    {
        if (_stopped) return;
        try { _queue.Add(work); } catch { }
    }

    public void Send(Action work)
    {
        if (HasAccess) { work(); return; }
        using var done = new ManualResetEventSlim(false);
        Exception? blad = null;
        Enqueue(() =>
        {
            try { work(); }
            catch (Exception ex) { blad = ex; }
            finally { try { done.Set(); } catch { } }
        });
        done.Wait();
        if (blad != null) throw blad;
    }

    public T Send<T>(Func<T> work)
    {
        if (HasAccess) return work();
        T wynik = default!;
        Send(() => { wynik = work(); });
        return wynik;
    }

    public void Post(Action work) => Enqueue(work);

    public Task RunAsync(Action work)
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Enqueue(() =>
        {
            try { work(); tcs.TrySetResult(); }
            catch (Exception ex) { tcs.TrySetException(ex); }
        });
        return tcs.Task;
    }

    public Task<T> RunAsync<T>(Func<T> work)
    {
        var tcs = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        Enqueue(() =>
        {
            try { tcs.TrySetResult(work()); }
            catch (Exception ex) { tcs.TrySetException(ex); }
        });
        return tcs.Task;
    }

    public void Schedule(TimeSpan delay, TimeSpan interval, Action tick, out IDisposable handle)
    {
        var t = new System.Threading.Timer(_ => Enqueue(tick), null, delay, interval);
        handle = t;
    }
}
