using System.Text;

namespace Malward.NetworkScanner;

// Mirrors to disk exactly what the proxy hands the browser, byte for byte, after everything the
// pipeline did to it. A synthetic client proves what the engine produces for a synthetic request;
// only this shows what a real browser was actually given.
public sealed class CaptureStream : Stream
{
    private readonly Stream _inner;
    private readonly FileStream? _sink;
    private readonly FileStream? _asked;

    public CaptureStream(Stream inner, string host, string directory)
    {
        _inner = inner;
        try
        {
            Directory.CreateDirectory(directory);
            var name = host;
            foreach (var bad in Path.GetInvalidFileNameChars()) name = name.Replace(bad, '_');
            var stamp = DateTime.Now.ToString("HHmmss_fff");
            _sink = File.Create(Path.Combine(directory, $"{name}.{stamp}.reply.bin"));
            _asked = File.Create(Path.Combine(directory, $"{name}.{stamp}.request.bin"));
        }
        catch { _sink = null; _asked = null; }
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        Mirror(buffer.AsSpan(offset, count));
        _inner.Write(buffer, offset, count);
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,
                                               CancellationToken ct = default)
    {
        Mirror(buffer.Span);
        await _inner.WriteAsync(buffer, ct);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        => WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();

    private void Mirror(ReadOnlySpan<byte> data)
    {
        try { _sink?.Write(data); _sink?.Flush(); } catch { }
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => _inner.CanWrite;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);
    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer,
                                                   CancellationToken ct = default)
    {
        int n = await _inner.ReadAsync(buffer, ct);
        if (n > 0) MirrorRequest(buffer.Span[..n]);
        return n;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count,
                                              CancellationToken ct)
    {
        int n = await _inner.ReadAsync(buffer, offset, count, ct);
        if (n > 0) MirrorRequest(buffer.AsSpan(offset, n));
        return n;
    }

    private void MirrorRequest(ReadOnlySpan<byte> data)
    {
        try { _asked?.Write(data); _asked?.Flush(); } catch { }
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            try { _sink?.Dispose(); } catch { }
            try { _asked?.Dispose(); } catch { }
        }
        base.Dispose(disposing);
    }
}
