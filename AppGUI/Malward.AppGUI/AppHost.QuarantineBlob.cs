using System;
using System.IO;
using System.Threading.Tasks;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public partial class AppHost
{
    internal readonly record struct ReportBlob(string Path, bool Temporary);

    internal readonly record struct ReportBlobResult(ReportBlob? Blob, string Reason);

    private async Task<ReportBlobResult> QuarantineReportBlobAsync(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return new ReportBlobResult(null, "Zgłoszenie bez identyfikatora elementu.");
        try
        {
            if (ResidentQuarantineStore.IsResidentId(id))
            {
                var dir = Path.Combine(_appDataDir, "quarantine");

                var name = Path.GetFileName(id[ResidentQuarantineStore.IdPrefix.Length..]);
                if (string.IsNullOrEmpty(name))
                    return new ReportBlobResult(null, "Nieprawidłowy identyfikator elementu osłony rezydentnej.");
                var full = Path.Combine(dir, name);
                return File.Exists(full)
                    ? new ReportBlobResult(new ReportBlob(full, Temporary: false), "")
                    : new ReportBlobResult(null, $"Brak pliku kontenera: {name}");
            }

            if (!Guid.TryParse(id, out _))
                return new ReportBlobResult(null, $"Identyfikator nie jest znanym formatem: {id}");
            if (_engine == null)
                return new ReportBlobResult(null, "Silnik jest niedostępny.");

            var tmp = Path.Combine(Path.GetTempPath(),
                                   "malward-fp-" + Guid.NewGuid().ToString("N") + ".quarantine");
            var problem = await _engine.RunQuarantineExportAsync(id, tmp);
            if (problem.Length == 0)
                return new ReportBlobResult(new ReportBlob(tmp, Temporary: true), "");

            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            CrashLog.Write("report", null, $"engine refused to export {id}: {problem}");
            return new ReportBlobResult(null, $"Nie udało się przygotować próbki: {problem}");
        }
        catch (Exception ex)
        {
            CrashLog.Write("report", ex, $"preparing the quarantine container for {id}");
            return new ReportBlobResult(null, $"Nie udało się przygotować próbki: {ex.Message}");
        }
    }
}
