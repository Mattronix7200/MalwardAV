using System.Diagnostics;

namespace Malward.Engine.Util;

public sealed class CpuGovernor
{
    private readonly Process _proc = Process.GetCurrentProcess();
    private readonly int _cores = Math.Max(1, Environment.ProcessorCount);
    private readonly object _gate = new();

    private readonly double _target;
    private TimeSpan _lastCpuTime;
    private long _lastTick;
    private volatile int _sleepMs;

    public CpuGovernor(int targetPercent)
    {
        _target = Math.Clamp(targetPercent, 5, 100) / 100.0;
        _lastCpuTime = _proc.TotalProcessorTime;
        _lastTick = Environment.TickCount64;
    }

    public bool Active => _target < 0.99;

    public int SuggestedThreads
    {
        get
        {
            int n = (int)Math.Round(_cores * _target);
            return Math.Max(1, Math.Min(_cores, n));
        }
    }

    public double LastUsage { get; private set; }

    public void Throttle()
    {
        if (!Active) return;

        Sample();

        int sleep = _sleepMs;
        if (sleep > 0) Thread.Sleep(sleep);
    }

    private void Sample()
    {
        long now = Environment.TickCount64;
        if (now - Volatile.Read(ref _lastTick) < 250) return;

        lock (_gate)
        {
            long dt = now - _lastTick;
            if (dt < 250) return;

            TimeSpan cpu;
            try { _proc.Refresh(); cpu = _proc.TotalProcessorTime; }
            catch { return; }

            double used = (cpu - _lastCpuTime).TotalMilliseconds;
            _lastCpuTime = cpu;
            _lastTick = now;

            double share = used / (dt * _cores);
            LastUsage = share;

            int sleep = _sleepMs;
            if (share > _target * 1.05) sleep = Math.Min(120, sleep + 2 + (int)((share - _target) * 60));
            else if (share < _target * 0.85) sleep = Math.Max(0, sleep - 2);

            _sleepMs = sleep;
        }
    }
}
