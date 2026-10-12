using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;

namespace Malward.AppGUI.Services;

public static class EventCentre
{
    public sealed record Choice(string Id, string Label, bool Primary = false);

    public sealed record Entry(
        string Id,
        string Kind,
        bool NeedsDecision,
        DateTime WhenUtc,
        string Title,
        string Detection,
        string? Process,
        string? Path,
        string? Detail,
        IReadOnlyList<Choice> Actions,
        IReadOnlyDictionary<string, Action> Answers);

    private static readonly object _lock = new();
    private static readonly List<Entry> _items = new();
    private static long _seq;

    private const int MaxEntries = 200;

    public static event Action? Changed;

    public static Entry Report(string kind, string title, string detection,
                               string? process, string? path, string? detail)
        => AddEntry(kind, false, title, detection, process, path, detail,
                 Array.Empty<Choice>(), new Dictionary<string, Action>());

    public static Entry Ask(string kind, string title, string detection,
                            string? process, string? path, string? detail,
                            IReadOnlyList<Choice> actions,
                            IReadOnlyDictionary<string, Action> answers)
    {
        foreach (var a in actions)
            if (!answers.ContainsKey(a.Id))
                throw new ArgumentException($"Akcja '{a.Id}' nie ma przypisanej odpowiedzi.", nameof(answers));

        (actions, answers) = WithDismissAction(actions, answers);
        return AddEntry(kind, true, title, detection, process, path, detail, actions, answers);
    }

    public const string ForgetAction = "forget";

    private static (IReadOnlyList<Choice>, IReadOnlyDictionary<string, Action>) WithDismissAction(
        IReadOnlyList<Choice> actions, IReadOnlyDictionary<string, Action> answers)
    {
        if (actions.Count != 1 || actions[0].Id == ForgetAction) return (actions, answers);

        var akcje = new List<Choice>(actions) { new(ForgetAction, "Zapomnij") };
        var odpowiedzi = new Dictionary<string, Action>(StringComparer.Ordinal);
        foreach (var kv in answers) odpowiedzi[kv.Key] = kv.Value;
        odpowiedzi[ForgetAction] = static () => { };
        return (akcje, odpowiedzi);
    }

    private static Entry AddEntry(string kind, bool pytanie, string title, string detection,
                               string? process, string? path, string? detail,
                               IReadOnlyList<Choice> actions, IReadOnlyDictionary<string, Action> answers)
    {
        Entry wpis;
        lock (_lock)
        {
            var id = $"{kind}-{DateTime.UtcNow:yyyyMMddHHmmss}-{++_seq}";
            wpis = new Entry(id, kind, pytanie, DateTime.UtcNow,
                             title, detection, process, path, detail, actions, answers);
            _items.Add(wpis);
            if (_items.Count > MaxEntries)
            {
                var doUsuniecia = _items.FirstOrDefault(e => !e.NeedsDecision) ?? _items[0];
                _items.Remove(doUsuniecia);
            }
        }
        Changed?.Invoke();
        return wpis;
    }

    public static IReadOnlyList<Entry> All()
    {
        lock (_lock) return _items.OrderByDescending(e => e.WhenUtc).ToList();
    }

    public static int PendingCount()
    {
        lock (_lock) return _items.Count(e => e.NeedsDecision);
    }

    public static bool Answer(string id, string actionId)
    {
        Entry? wpis;
        lock (_lock)
        {
            wpis = _items.FirstOrDefault(e => e.Id == id);
            if (wpis == null) return false;
            _items.Remove(wpis);
        }
        Changed?.Invoke();
        if (wpis.Answers.TryGetValue(actionId, out var co)) co();
        return true;
    }

    public static void Withdraw(string id)
    {
        lock (_lock)
        {
            var wpis = _items.FirstOrDefault(e => e.Id == id);
            if (wpis == null) return;
            _items.Remove(wpis);
        }
        Changed?.Invoke();
    }

    public static void ClearHandled()
    {
        lock (_lock) _items.RemoveAll(e => !e.NeedsDecision);
        Changed?.Invoke();
    }

    public static JsonArray ToJson()
    {
        var arr = new JsonArray();
        foreach (var e in All())
        {
            var akcje = new JsonArray();
            foreach (var a in e.Actions)
                akcje.Add(new JsonObject { ["id"] = a.Id, ["label"] = a.Label, ["primary"] = a.Primary });
            arr.Add(new JsonObject
            {
                ["id"] = e.Id,
                ["kind"] = e.Kind,
                ["needsDecision"] = e.NeedsDecision,
                ["when"] = e.WhenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                ["title"] = e.Title,
                ["detection"] = e.Detection,
                ["process"] = e.Process,
                ["path"] = e.Path,
                ["detail"] = e.Detail,
                ["actions"] = akcje,
            });
        }
        return arr;
    }
}
