namespace Malward.ConsoleShell;

/// <summary>Sends everything the engine writes to stderr somewhere else for the duration of a
/// redrawn screen, and puts the real stderr back no matter how the block is left.</summary>
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
