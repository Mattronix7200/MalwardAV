namespace Malward.ConsoleShell;

public sealed class ErrorScope : IDisposable
{
    private readonly TextWriter _previous;

    public ErrorScope(TextWriter target)
    {
        _previous = Console.Error;
        Console.SetError(target);
    }

    public TextWriter Previous => _previous;

    public void Dispose() => Console.SetError(_previous);
}
