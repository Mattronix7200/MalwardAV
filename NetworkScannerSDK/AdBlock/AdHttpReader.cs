using System.Text;

namespace Malward.NetworkScanner.AdBlock;

public enum ChunkedCopyResult { Complete, Overflow, Failed }

public sealed class AdHttpReader
{
    private readonly Stream _stream;
    private byte[] _buffer = new byte[16 * 1024];
    private int _start;
    private int _end;

    public AdHttpReader(Stream stream) => _stream = stream;

    public int Buffered => _end - _start;

    private async Task<bool> FillAsync(CancellationToken ct)
    {
        if (_end == _buffer.Length)
        {
            if (_start > 0)
            {
                Buffer.BlockCopy(_buffer, _start, _buffer, 0, _end - _start);
                _end -= _start;
                _start = 0;
            }
            else
            {
                if (_buffer.Length >= 256 * 1024) return false;
                Array.Resize(ref _buffer, _buffer.Length * 2);
            }
        }
        int read = await _stream.ReadAsync(_buffer.AsMemory(_end, _buffer.Length - _end), ct);
        if (read <= 0) return false;
        _end += read;
        return true;
    }

    public async Task<string?> ReadHeadAsync(CancellationToken ct)
    {
        int scanned = 0;
        while (true)
        {
            for (int i = _start + Math.Max(0, scanned - 3); i + 3 < _end; i++)
            {
                if (_buffer[i] == (byte)'\r' && _buffer[i + 1] == (byte)'\n'
                    && _buffer[i + 2] == (byte)'\r' && _buffer[i + 3] == (byte)'\n')
                {
                    int len = i + 4 - _start;
                    var head = Encoding.ASCII.GetString(_buffer, _start, len);
                    _start += len;
                    return head;
                }
            }
            scanned = _end - _start;
            if (!await FillAsync(ct)) return null;
        }
    }

    public async Task<int> ReadAsync(byte[] target, int offset, int count, CancellationToken ct)
    {
        if (_start == _end)
        {
            if (!await FillAsync(ct)) return 0;
        }
        int take = Math.Min(count, _end - _start);
        Buffer.BlockCopy(_buffer, _start, target, offset, take);
        _start += take;
        return take;
    }

    public async Task<bool> CopyExactAsync(Stream? target, long count, CancellationToken ct)
    {
        var tmp = new byte[32 * 1024];
        while (count > 0)
        {
            int want = (int)Math.Min(tmp.Length, count);
            int got = await ReadAsync(tmp, 0, want, ct);
            if (got <= 0) return false;
            if (target != null) await target.WriteAsync(tmp.AsMemory(0, got), ct);
            count -= got;
        }
        return true;
    }

    public async Task<bool> CopyChunkedAsync(Stream? target, CancellationToken ct)
        => await CopyChunkedAsync(target, long.MaxValue, ct) == ChunkedCopyResult.Complete;

    public async Task<ChunkedCopyResult> CopyChunkedAsync(Stream? target, long maxBytes,
                                                          CancellationToken ct)
    {
        long copied = 0;
        while (true)
        {
            if (copied >= maxBytes) return ChunkedCopyResult.Overflow;

            var line = await ReadLineAsync(ct);
            if (line == null) return ChunkedCopyResult.Failed;
            if (target != null) await WriteAsciiAsync(target, line + "\r\n", ct);

            var sizeText = line.Split(';')[0].Trim();
            if (!int.TryParse(sizeText, System.Globalization.NumberStyles.HexNumber, null, out int size))
                return ChunkedCopyResult.Failed;

            if (size == 0)
            {
                while (true)
                {
                    var trailer = await ReadLineAsync(ct);
                    if (trailer == null) return ChunkedCopyResult.Failed;
                    if (target != null) await WriteAsciiAsync(target, trailer + "\r\n", ct);
                    if (trailer.Length == 0) return ChunkedCopyResult.Complete;
                }
            }

            if (!await CopyExactAsync(target, size, ct)) return ChunkedCopyResult.Failed;
            var crlf = await ReadLineAsync(ct);
            if (crlf == null) return ChunkedCopyResult.Failed;
            if (target != null) await WriteAsciiAsync(target, "\r\n", ct);
            copied += size;
        }
    }

    public async Task DrainBufferedAsync(Stream target, CancellationToken ct)
    {
        if (_end <= _start) return;
        await target.WriteAsync(_buffer.AsMemory(_start, _end - _start), ct);
        _start = _end = 0;
    }

    public async Task CopyRestAsync(Stream target, CancellationToken ct)
    {
        var tmp = new byte[32 * 1024];
        while (true)
        {
            int got = await ReadAsync(tmp, 0, tmp.Length, ct);
            if (got <= 0) return;
            await target.WriteAsync(tmp.AsMemory(0, got), ct);
        }
    }

    private async Task<string?> ReadLineAsync(CancellationToken ct)
    {
        var sb = new StringBuilder(16);
        var one = new byte[1];
        while (true)
        {
            int got = await ReadAsync(one, 0, 1, ct);
            if (got <= 0) return null;
            if (one[0] == (byte)'\n') return sb.ToString().TrimEnd('\r');
            sb.Append((char)one[0]);
            if (sb.Length > 8192) return null;
        }
    }

    private static Task WriteAsciiAsync(Stream s, string text, CancellationToken ct)
        => s.WriteAsync(Encoding.ASCII.GetBytes(text), ct).AsTask();
}
