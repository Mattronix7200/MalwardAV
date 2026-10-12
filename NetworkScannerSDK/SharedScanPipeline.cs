namespace Malward.NetworkScanner;

public static class SharedScanPipeline
{
    static SharedScanPipeline()
    {
        Malward.Engine.Core.SharedPipeline.Log ??= (tag, msg) => Log.Warn(tag, msg);
    }

    public static int FailureCount => Malward.Engine.Core.SharedPipeline.FailureCount;

    public static Malward.Engine.Core.ScanPipeline? Get() => Malward.Engine.Core.SharedPipeline.Get();

    public static string? ScanFile(string path) => Malward.Engine.Core.SharedPipeline.ScanFile(path);

    public static Malward.Engine.Core.DetectionResult? Scan(string path)
        => Malward.Engine.Core.SharedPipeline.Scan(path);

    public static Malward.Engine.Repair.RepairOutcome? Repair(Malward.Engine.Core.DetectionResult r)
        => Malward.Engine.Core.SharedPipeline.Repair(r);
}
