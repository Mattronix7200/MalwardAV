using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Malward.ResidentShield;

internal static class JsonText
{
    public static string Compact(JsonNode node)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false }))
            node.WriteTo(writer);
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    public static string Indented(JsonNode node)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
            node.WriteTo(writer);
        return Encoding.UTF8.GetString(buffer.ToArray());
    }
}
