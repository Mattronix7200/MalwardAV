using System.Text;

namespace Malward.Engine.Util;

public static class ConsoleRouter
{
    private static readonly AsyncLocal<Scoped?> Current = new();
    private static readonly object InstallLock = new();
    private static TextWriter? _fallback;
    private static Router? _router;

    public static IDisposable Scope(TextWriter target)
    {
        Install();
        var scope = new Scoped(TextWriter.Synchronized(target), Current.Value);
        Current.Value = scope;
        return scope;
    }

    private static void Install()
    {
        if (_router != null) return;
        lock (InstallLock)
        {
            if (_router != null) return;
            _fallback = Console.Out;
            _router = new Router();
            Console.SetOut(_router);
        }
    }

    private static TextWriter Sink()
    {
        var scope = Current.Value;
        while (scope != null && !scope.Open) scope = scope.Previous;
        return scope?.Target ?? _fallback ?? TextWriter.Null;
    }

    private sealed class Scoped : IDisposable
    {
        public Scoped(TextWriter target, Scoped? previous)
        {
            Target = target;
            Previous = previous;
        }

        public TextWriter Target { get; }
        public Scoped? Previous { get; }
        public bool Open { get; private set; } = true;

        public void Dispose()
        {
            Open = false;
            if (ReferenceEquals(Current.Value, this)) Current.Value = Previous;
        }
    }

    private sealed class Router : TextWriter
    {
        public override Encoding Encoding => _fallback?.Encoding ?? Encoding.UTF8;
        public override IFormatProvider FormatProvider => _fallback?.FormatProvider ?? base.FormatProvider;

        public override void Write(char value) { try { Sink().Write(value); } catch { } }
        public override void Write(string? value) { try { Sink().Write(value); } catch { } }
        public override void Write(char[] buffer, int index, int count) { try { Sink().Write(buffer, index, count); } catch { } }
        public override void WriteLine() { try { Sink().WriteLine(); } catch { } }
        public override void WriteLine(string? value) { try { Sink().WriteLine(value); } catch { } }
        public override void Flush() { try { Sink().Flush(); } catch { } }
    }
}
