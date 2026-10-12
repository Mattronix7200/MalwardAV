using Malward.Engine.Config;

namespace Malward.Engine;

public static class EngineHost
{
    private static readonly object Gate = new();

    public static int RunScan(string[] args, TextWriter output, CancellationToken ct = default)
        => Run(args, output, (a, s) => Program.CmdScan(a, s, ct));

    public static int RunScanMemory(string[] args, TextWriter output, CancellationToken ct = default)
        => Run(args, output, (a, s) => Program.CmdScanMemory(a, s, ct));

    public static int RunSubmitDetection(string[] args, TextWriter output, CancellationToken ct = default)
        => Run(args, output, (a, s) => Program.CmdSubmitDetection(a, s));

    private static readonly TimeSpan GateWait = TimeSpan.FromSeconds(20);

    private static int Run(string[] args, TextWriter output, Func<string[], Settings, int> command)
    {
        if (!Monitor.TryEnter(Gate, GateWait))
        {
            try { output.WriteLine("ERROR\tmsg=Poprzednie skanowanie jeszcze się kończy. Spróbuj ponownie za chwilę."); }
            catch { }
            return 3;
        }
        try
        {
            var prevMachine = Environment.GetEnvironmentVariable("MALWARD_MACHINE_OUTPUT");
            try
            {
                Environment.SetEnvironmentVariable("MALWARD_MACHINE_OUTPUT", "1");

                using (Util.ConsoleRouter.Scope(output))
                {
                    var settings = Settings.Load();
                    return command(args, settings);
                }
            }
            catch (Exception ex)
            {
                try { output.WriteLine($"ERROR\tmsg={ex.Message}"); } catch { }
                return 2;
            }
            finally
            {
                Environment.SetEnvironmentVariable("MALWARD_MACHINE_OUTPUT", prevMachine);
            }
        }
        finally { Monitor.Exit(Gate); }
    }
}
