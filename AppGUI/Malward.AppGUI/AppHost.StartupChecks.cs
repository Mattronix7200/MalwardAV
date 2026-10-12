using System;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Windows;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public partial class AppHost
{
    private bool MustAbortStartForEnvironment(string engineDir)
    {
        try
        {
            if (!BrakBazDefinicji(engineDir)) return false;

            if (ClockIsWrong(engineDir))
            {
                StartupError(Loc.T(
                    "Nie można połączyć z serwerem aktualizacji z powodu błędnego czasu " +
                    "systemowego na twoim komputerze.\n\n" +
                    "Upewnij się czy czas jest prawidłowy i spróbuj ponownie.\n\n" +
                    "Zamykam program."));
                return true;
            }

            if (!SerwerOsiagalny())
            {
                StartupError(Loc.T(
                    "Nie można połączyć z serwerem aktualizacji z powodu braku połączenia " +
                    "z internetem.\n\n" +
                    "Sprawdź połączenie sieciowe i spróbuj ponownie.\n\n" +
                    "Zamykam program."));
                return true;
            }
        }
        catch (Exception ex)
        {
            CrashLog.Write("startup-checks", ex, "environment check");
        }
        return false;
    }

    private void StartupError(string tresc)
    {
        Shell.Alert(tresc, Loc.T("Malward — Błąd aplikacji"));
        Shell.Shutdown();
    }

    private bool BrakBazDefinicji(string engineDir)
    {
        bool Jest(string nazwa) =>
            FileHasContent(Path.Combine(_appDataDir, "data", nazwa))
            || FileHasContent(Path.Combine(engineDir, "_bases", "engine", nazwa))
            || FileHasContent(Path.Combine(engineDir, "data", nazwa));
        return !Jest("vps.vdeb");
    }

    private static bool FileHasContent(string sciezka)
    {
        try { return File.Exists(sciezka) && new FileInfo(sciezka).Length > 0; }
        catch { return false; }
    }

    private static bool ClockIsWrong(string engineDir)
    {
        var teraz = DateTime.UtcNow;
        if (teraz.Year < 2020) return true;

        try
        {
            var pliki = Directory.EnumerateFiles(engineDir, "*.dll", SearchOption.TopDirectoryOnly)
                                 .Concat(Directory.EnumerateFiles(engineDir, "*.exe", SearchOption.TopDirectoryOnly))
                                 .Take(400);
            DateTime najnowszy = DateTime.MinValue;
            foreach (var f in pliki)
            {
                try
                {
                    var t = File.GetLastWriteTimeUtc(f);
                    if (t > najnowszy) najnowszy = t;
                }
                catch { }
            }
            if (najnowszy == DateTime.MinValue) return false;
            return teraz < najnowszy - TimeSpan.FromDays(1);
        }
        catch { return false; }
    }

    private bool SerwerOsiagalny()
    {
        try
        {
            var s = new Malward.Engine.Config.Settings();
            var host = s.ServerIp;
            int port = s.ServerPort;
            if (string.IsNullOrWhiteSpace(host) || port <= 0) return true;

            using var klient = new TcpClient();
            var proba = klient.BeginConnect(host, port, null, null);
            if (!proba.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(6))) return false;
            klient.EndConnect(proba);
            return klient.Connected;
        }
        catch { return false; }
    }
}
