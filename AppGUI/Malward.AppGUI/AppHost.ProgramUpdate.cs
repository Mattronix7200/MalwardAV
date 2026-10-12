using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public partial class AppHost
{
    private ProgramUpdateService? _programUpdates;

    private CancellationTokenSource? _programUpdateCts;

    private ProgramUpdateService ProgramUpdates()
        => _programUpdates ??= new ProgramUpdateService(AppContext.BaseDirectory, _appDataDir);

    private void CleanupFinishedUpdate()
    {
        try { ProgramUpdates().CleanupAfterUpdate(); }
        catch (Exception ex) { CrashLog.Write("Update", ex, "post-update cleanup"); }

        _ = Task.Run(async () =>
        {
            if (!await WaitForUiAsync(TimeSpan.FromSeconds(60))) return;
            try { ReportFailedUpdateOnce(); }
            catch (Exception ex) { CrashLog.Write("Update", ex, "update outcome"); }
            try { ReportSuccessfulUpdateOnce(); }
            catch (Exception ex) { CrashLog.Write("Update", ex, "update outcome (ok)"); }
        });
    }

    private async Task<bool> WaitForUiAsync(TimeSpan limit)
    {
        var koniec = DateTime.UtcNow + limit;
        while (DateTime.UtcNow < koniec)
        {
            if (Ui.Send(() => _uiReady)) return true;
            await Task.Delay(250);
        }
        return false;
    }

    private void ReportSuccessfulUpdateOnce()
    {
        var path = Path.Combine(_appDataDir, "data", "update-done.txt");
        if (!File.Exists(path)) return;

        string wersja;
        try { wersja = File.ReadAllText(path).Trim(); }
        catch { return; }
        try { File.Delete(path); } catch { }

        string running = "";
        try
        {
            running = (System.Diagnostics.FileVersionInfo.GetVersionInfo(Environment.ProcessPath ?? "")
                .ProductVersion ?? "").Split('+')[0].Trim();
        }
        catch { }
        if (wersja.Length > 0 && running.Length > 0 && !string.Equals(wersja, running, StringComparison.Ordinal))
            CrashLog.Write("Update", null, $"update-done.txt={wersja}, but running version={running} — copying may have been interrupted");

        string msg = wersja.Length > 0
            ? $"Zaktualizowano program do wersji {wersja}."
            : "Aktualizacja programu została zainstalowana.";
        Ui.Post(() =>
        {
            PostToJs("toast", new { level = "ok", msg });
            PostToJs("engine.log", new { level = "info", msg });
        });
    }

    private void ReportFailedUpdateOnce()
    {
        var path = Path.Combine(_appDataDir, "data", "update-outcome.txt");
        if (!File.Exists(path)) return;

        string tresc;
        try { tresc = File.ReadAllText(path).Trim(); }
        catch { return; }

        try { File.Delete(path); } catch { }
        if (tresc.Length == 0) return;

        var log = Path.Combine(_appDataDir, "logs", "update.log");
        Ui.Post(() =>
        {
            PostToJs("update.failed", new
            {
                title = "Aktualizacja nie została zainstalowana w całości",
                detail = tresc,
                log,
            });
            PostToJs("engine.log", new
            {
                level = "error",
                msg = $"Aktualizacja programu nie powiodła się. {tresc.Split('\n')[0]} " +
                      $"Szczegóły: {log}",
            });
        });
    }

    private async Task InstallProgramUpdateAsync()
    {
        try
        {
            var svc = ProgramUpdates();

            var check = await svc.CheckAsync();
            if (!check.Available || check.Release == null)
            {
                PostToJs("program.update.result", new { ok = false, message = "Brak nowszej wersji do zainstalowania." });
                return;
            }

            _programUpdateCts?.Dispose();
            _programUpdateCts = new CancellationTokenSource();

            var (ok, result) = await svc.PrepareAsync(check.Release,
                p => PostToJs("program.update.progress", new { phase = p.Phase, done = p.Done, total = p.Total, message = p.Message }),
                _programUpdateCts.Token);

            if (!ok)
            {
                PostToJs("program.update.result", new
                {
                    ok = false,
                    message = result,

                    resumable = svc.HasPartialDownload(check.Release),
                });
                return;
            }

            bool go = await Ui.RunAsync(() => ConfirmUpdate(check.Release.Version));
            if (!go)
            {
                PostToJs("program.update.result", new { ok = false, message = "Instalacja odłożona. Pobrane pliki są gotowe." });
                return;
            }

            var (started, message) = svc.LaunchInstaller(result);
            PostToJs("program.update.result", new { ok = started, message });
            if (!started) return;

            await Task.Delay(1200);
            await Ui.RunAsync(() =>
            {
                try { Shell.Shutdown(); }
                catch { Environment.Exit(0); }
            });
        }
        catch (OperationCanceledException)
        {
            PostToJs("program.update.result", new
            {
                ok = false,
                message = "Pobieranie przerwane. Kolejna próba wznowi je od miejsca zatrzymania.",
                resumable = true,
            });
        }
        catch (Exception ex)
        {
            CrashLog.Write("Update", ex, "installing the program update");
            PostToJs("program.update.result", new { ok = false, message = ex.Message });
        }
        finally
        {
            _programUpdateCts?.Dispose();
            _programUpdateCts = null;
        }
    }

    private void CancelProgramUpdate()
    {
        try { _programUpdateCts?.Cancel(); } catch { }
    }

    private bool ConfirmUpdate(string version)
    {
        try
        {
            return Shell.Confirm(
                $"Aktualizacja do wersji {version} jest pobrana i sprawdzona.\n\n" +
                "Instalacja zamknie program i na chwilę zatrzyma ochronę, po czym uruchomi ją ponownie. " +
                "Ustawienia, bazy danych i kwarantanna zostaną zachowane.\n\n" +
                "Zainstalować teraz?",
                "Malward — aktualizacja programu");
        }
        catch { return false; }
    }
}
