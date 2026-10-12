using System.Globalization;

namespace Malward.BackupEngine;

public static class ScheduleCalc
{
    public static bool IsActive(string schedule)
        => !string.IsNullOrWhiteSpace(schedule) && !schedule.Equals("off", StringComparison.OrdinalIgnoreCase);

    public static DateTime NextFire(string schedule, DateTime? lastFireLocal = null)
    {
        var now = DateTime.Now;
        if (!IsActive(schedule)) return DateTime.MaxValue;

        try
        {
            if (schedule.StartsWith("everyN:", StringComparison.OrdinalIgnoreCase))
            {
                int mins = int.Parse(schedule["everyN:".Length..], CultureInfo.InvariantCulture);
                if (mins < 1) mins = 1;
                var basis = lastFireLocal ?? now;
                var next = basis.AddMinutes(mins);
                return next <= now ? now.AddMinutes(mins) : next;
            }
            if (schedule.StartsWith("dailyAt:", StringComparison.OrdinalIgnoreCase))
            {
                var (h, m) = ParseHm(schedule["dailyAt:".Length..]);
                var target = new DateTime(now.Year, now.Month, now.Day, h, m, 0);
                if (target <= now) target = target.AddDays(1);
                return target;
            }
            if (schedule.StartsWith("weeklyAt:", StringComparison.OrdinalIgnoreCase))
            {
                var rest = schedule["weeklyAt:".Length..];
                int colon = rest.IndexOf(':');
                int dow = int.Parse(rest[..colon], CultureInfo.InvariantCulture);
                var (h, m) = ParseHm(rest[(colon + 1)..]);
                var target = new DateTime(now.Year, now.Month, now.Day, h, m, 0);
                int delta = ((dow % 7) - (int)now.DayOfWeek + 7) % 7;
                target = target.AddDays(delta);
                if (target <= now) target = target.AddDays(7);
                return target;
            }
        }
        catch { }
        return DateTime.MaxValue;
    }

    private static (int H, int M) ParseHm(string hm)
    {
        var parts = hm.Split(':');
        int h = parts.Length > 0 ? int.Parse(parts[0], CultureInfo.InvariantCulture) : 0;
        int m = parts.Length > 1 ? int.Parse(parts[1], CultureInfo.InvariantCulture) : 0;
        return (Math.Clamp(h, 0, 23), Math.Clamp(m, 0, 59));
    }
}

internal sealed class Scheduler
{
    private readonly string _schedule;
    private DateTime _lastFire = DateTime.MinValue;

    public Scheduler(string schedule) => _schedule = schedule;

    public bool IsActive => ScheduleCalc.IsActive(_schedule);

    public bool ShouldFire()
    {
        if (!IsActive) return false;
        var now = DateTime.Now;
        var next = ScheduleCalc.NextFire(_schedule, _lastFire == DateTime.MinValue ? null : _lastFire);
        if (now >= next && now > _lastFire.AddMinutes(1))
        {
            _lastFire = now;
            return true;
        }
        return false;
    }

    public DateTime NextFireTime() => ScheduleCalc.NextFire(_schedule, _lastFire == DateTime.MinValue ? null : _lastFire);
}
