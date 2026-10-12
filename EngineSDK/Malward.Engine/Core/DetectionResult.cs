namespace Malward.Engine.Core;

public enum Verdict
{
    Clean,
    Malware,
    Skipped,
    Error,
}

public sealed record ArchiveFinding(string Entry, string Display, string Detection, string Source, bool Direct);

public sealed record DetectionResult(
    string Path,
    string Sha256,
    Verdict Verdict,
    string? Detection,
    string Source,
    long FileSize,
    long ElapsedMs,
    string? Error = null,

    string? ArchiveEntry = null,

    IReadOnlyList<ArchiveFinding>? ArchiveFindings = null
);
