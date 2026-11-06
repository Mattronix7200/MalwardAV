using System;
using System.Collections.Generic;

namespace Malward.AppGUI;

public readonly record struct RemovableSlice(int Done, int Total, int Pct, bool Finished);

public readonly record struct RemovableRollup(int Media, int Done, int Total, int Pct);

public static class RemovableAggregate
{
    public static RemovableRollup Combine(IReadOnlyCollection<RemovableSlice> slices)
    {
        int media = 0, pctMax = 0;
        long done = 0, total = 0;
        foreach (var s in slices)
        {
            if (s.Finished) continue;
            media++;
            done += Math.Max(0, s.Done);
            total += Math.Max(0, s.Total);
            if (s.Pct > pctMax) pctMax = s.Pct;
        }
        if (media == 0) return new RemovableRollup(0, 0, 0, 100);
        int pct = total > 0 ? (int)(100L * done / total) : pctMax;
        if (pct < 0) pct = 0;
        if (pct > 100) pct = 100;
        return new RemovableRollup(media, (int)done, (int)total, pct);
    }
}
