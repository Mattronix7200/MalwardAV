namespace Malward.Engine.Vdeb;

public sealed class ShardCache
{
    private readonly int _cap;
    private readonly LinkedList<(ushort key, byte[] data)> _order = new();
    private readonly Dictionary<ushort, LinkedListNode<(ushort, byte[])>> _map = new();
    private readonly object _lock = new();

    public ShardCache(int capacity) { _cap = Math.Max(1, capacity); }

    public byte[] GetOrLoad(ushort key, Func<byte[]> loader)
    {
        lock (_lock)
        {
            if (_map.TryGetValue(key, out var node))
            {
                _order.Remove(node);
                _order.AddFirst(node);
                return node.Value.Item2;
            }
        }

        var data = loader();

        lock (_lock)
        {
            if (_map.TryGetValue(key, out var existing))
                return existing.Value.Item2;

            var node = new LinkedListNode<(ushort, byte[])>((key, data));
            _order.AddFirst(node);
            _map[key] = node;

            while (_order.Count > _cap)
            {
                var tail = _order.Last!;
                _order.RemoveLast();
                _map.Remove(tail.Value.Item1);
            }
            return data;
        }
    }
}
