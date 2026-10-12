namespace Malward.NetworkScanner;

internal static class BlockPageRenderer
{
    private static readonly Lazy<string> LogoDataUri = new(() =>
    {
        try
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            using var s = asm.GetManifestResourceStream("Malward.NetworkScanner.logo.png");
            if (s == null) return "";
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            return "data:image/png;base64," + Convert.ToBase64String(ms.ToArray());
        }
        catch { return ""; }
    });

    private const string ErrorIconSvg =
        "<svg viewBox=\"0 0 24 24\" width=\"38\" height=\"38\" fill=\"none\" " +
        "stroke=\"currentColor\" stroke-width=\"2.2\" stroke-linecap=\"round\" " +
        "stroke-linejoin=\"round\" aria-hidden=\"true\">" +
        "<path d=\"M10.29 3.86 L1.82 18 a2 2 0 0 0 1.71 3 h16.94 a2 2 0 0 0 1.71 -3 L13.71 3.86 a2 2 0 0 0 -3.42 0 z\"/>" +
        "<line x1=\"12\" y1=\"9\" x2=\"12\" y2=\"13\"/>" +
        "<line x1=\"12\" y1=\"17\" x2=\"12.01\" y2=\"17\"/></svg>";

    private const string ShieldSvg =
        "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" " +
        "stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">" +
        "<path d=\"M12 3 L20 6 V11 C20 16 16.5 19.5 12 21 C7.5 19.5 4 16 4 11 V6 Z\"/>" +
        "<path d=\"M8 14 L8 9 L12 12 L16 9 L16 14\"/></svg>";

    private static readonly string FaviconDataUri = "data:image/svg+xml;utf8," +
        Uri.EscapeDataString(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\" " +
            "fill=\"#c42b2b\" stroke=\"#fff\" stroke-width=\"1.5\" stroke-linejoin=\"round\">" +
            "<path d=\"M10.29 3.86 L1.82 18 a2 2 0 0 0 1.71 3 h16.94 a2 2 0 0 0 1.71 -3 L13.71 3.86 a2 2 0 0 0 -3.42 0 z\"/>" +
            "<rect x=\"11.2\" y=\"9\" width=\"1.6\" height=\"5\" fill=\"#fff\" stroke=\"none\"/>" +
            "<circle cx=\"12\" cy=\"16.5\" r=\"1\" fill=\"#fff\" stroke=\"none\"/></svg>");

    private static string LogoTag(int sizePx) =>
        string.IsNullOrEmpty(LogoDataUri.Value)
            ? ShieldSvg.Replace("<svg viewBox", $"<svg width=\"{sizePx}\" height=\"{sizePx}\" viewBox")
            : $"<img src=\"{LogoDataUri.Value}\" width=\"{sizePx}\" height=\"{sizePx}\" alt=\"Malward\" style=\"display:block\">";

    public static string Render(string host, string? detection, string? source)
    {
        string safeHost = Escape(host);
        string srcLabel = source switch
        {
            "live"  => Malward.Engine.Util.Loc.T("Wykryto na żywo przez serwer Malward"),
            "cloud" => Malward.Engine.Util.Loc.T("Skaner w chmurze"),
            "local" => Malward.Engine.Util.Loc.T("Wykryto przez lokalną bazę reputacji"),
            _       => Malward.Engine.Util.Loc.T("Wykryto przez osłonę sieciową Malward"),
        };
        string detLabel = string.IsNullOrEmpty(detection)
            ? Escape(DnsProxy.BuildDetectionName(safeHost))
            : Escape(detection!);

        var nowLocal = DateTime.Now;
        string ts = nowLocal.ToString("yyyy-MM-dd HH:mm:ss");
        string tsIso = nowLocal.ToString("yyyy-MM-ddTHH:mm:sszzz");

        string footerLogo = LogoTag(24);

        return RenderShell(
            title: Malward.Engine.Util.Loc.T("Malward — strona zablokowana"),
            bodyHtml: $@"
  <main class=""card"" role=""alert"">
    <div class=""head"">
      <div class=""icon"" aria-hidden=""true"">{ErrorIconSvg}</div>
      <div class=""title"">
        <h1>{Malward.Engine.Util.Loc.T("Strona zablokowana")}</h1>
        <p>{Malward.Engine.Util.Loc.T("Osłona sieciowa Malward zablokowała dostęp do tej witryny.")}</p>
      </div>
    </div>
    <div class=""body"">
      <div class=""row""><div class=""lbl"">{Malward.Engine.Util.Loc.T("Adres URL")}</div><div class=""val"">{safeHost}</div></div>
      <div class=""row""><div class=""lbl"">{Malward.Engine.Util.Loc.T("Detekcja")}</div><div class=""val det"">{detLabel}</div></div>
      <div class=""row""><div class=""lbl"">{Malward.Engine.Util.Loc.T("Źródło")}</div><div class=""val"">{Escape(srcLabel)}</div></div>
      <div class=""note"">
        {Malward.Engine.Util.Loc.T("Strona została zaklasyfikowana jako szkodliwa lub niezaufana. Otwarcie jej może prowadzić do wyłudzenia danych, pobrania złośliwego pliku albo śledzenia użytkownika. Jeśli masz pewność, że to fałszywy alarm, dodaj domenę ręcznie w aplikacji Malward → Ochrona → Ustawienia osłony sieciowej.")}
      </div>
      <div class=""actions"">
        <button class=""btn-back"" type=""button"" onclick=""history.length&gt;1?history.back():window.close()"">
          ← {Malward.Engine.Util.Loc.T("Zabierz mnie stąd")}
        </button>
      </div>
      <div class=""foot"">
        <div class=""brand"">{footerLogo}<span class=""brand-text"">Malward<sup class=""brand-tm"">®</sup> Community Edition</span></div>
        <span>{Malward.Engine.Util.Loc.T("Wygenerowano")}: <time class=""ts"" datetime=""{Escape(tsIso)}"">{Escape(ts)}</time></span>
      </div>
    </div>
  </main>");
    }

    public static string RenderAdded(string domain, bool ok)
    {
        string safeHost = Escape(domain);
        string headerColor = ok ? "#1f7a35" : "#a31e1e";
        string headerTitle = ok ? "Dodano do wyjątków" : "Nie udało się dodać do wyjątków";
        string message = ok
            ? $"Domena <strong>{safeHost}</strong> została dodana do listy wyjątków osłony sieciowej i jest <strong>aktywna natychmiast</strong>. " +
              "Odśwież stronę w przeglądarce — powinna już działać normalnie."
            : $"Nie udało się zapisać wpisu <strong>{safeHost}</strong> w pliku konfiguracji. " +
              "Spróbuj dodać domenę ręcznie w aplikacji Malward → Ochrona → Ustawienia osłony.";

        return RenderShell(
            title: ok ? "Malward — dodano wyjątek" : "Malward — błąd",
            headerOverrideColor: headerColor,
            bodyHtml: $@"
  <main class=""card"" role=""status"">
    <div class=""head"" style=""background: linear-gradient(135deg, {headerColor}, color-mix(in srgb, {headerColor} 75%, #000));"">
      <div class=""icon"" aria-hidden=""true"">{(ok ? "✓" : "⚠")}</div>
      <div class=""title"">
        <h1>{headerTitle}</h1>
        <p>{safeHost}</p>
      </div>
    </div>
    <div class=""body"">
      <div class=""note"" style=""background:transparent;border:0;color:var(--text-dim)"">
        {message}
      </div>
    </div>
  </main>");
    }

    private static string RenderShell(string title, string bodyHtml, string? headerOverrideColor = null)
    {
        return $@"<!DOCTYPE html>
<html lang=""pl"">
<head>
<meta charset=""utf-8"">
<title>{Escape(title)}</title>
<meta name=""viewport"" content=""width=device-width, initial-scale=1"">
<link rel=""icon"" type=""image/svg+xml"" href=""{FaviconDataUri}"">
<style>
  :root {{
    color-scheme: light dark;
    --bg-grad-from: #f6f8fc; --bg-grad-to: #e9eef5;
    --card-bg: #ffffff; --card-border: #d6dbe2;
    --text: #1a2030; --text-dim: #4b5563; --text-mute: #6a7280;
    --note-bg: rgba(226,59,59,.06); --note-border: rgba(226,59,59,.22);
    --foot-border: #e2e6ec; --brand-fg: #1a2030;
    --shadow: 0 14px 50px rgba(20,30,50,.12);
    --btn-bg: #c42b2b; --btn-bg-hov: #a31e1e; --btn-fg: #ffffff;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg-grad-from: #1c2330; --bg-grad-to: #0e1116;
      --card-bg: #161b22; --card-border: #2b333e;
      --text: #e9ecf0; --text-dim: #cfd5dc; --text-mute: #6a7280;
      --note-bg: rgba(226,59,59,.08); --note-border: rgba(226,59,59,.25);
      --foot-border: #2b333e; --brand-fg: #cfd5dc;
      --shadow: 0 12px 50px rgba(0,0,0,.4);
      --btn-bg: #d33b3b; --btn-bg-hov: #b62525;
    }}
  }}

  /* FIX (#3): tło rozciągnięte na CAŁĄ wysokość okna — wcześniej `height:100%`
     nie wypełniał viewportu gdy karta była niska; pojawiał się pasek po dole.
     `min-height:100vh` + `background-attachment:fixed` to standardowy idiom dla
     full-page gradientów. */
  html {{ margin: 0; padding: 0; }}
  body {{
    margin: 0; min-height: 100vh;
    background: linear-gradient(160deg, var(--bg-grad-from), var(--bg-grad-to)) fixed;
    display: flex; align-items: center; justify-content: center;
    font-family: 'Segoe UI', system-ui, -apple-system, Roboto, Arial, sans-serif;
    color: var(--text); padding: 24px; box-sizing: border-box;
  }}

  /* FIX (#1): brak zaokrąglonych rogów — `border-radius: 0`. */
  .card {{
    width: 100%; max-width: 660px;
    background: var(--card-bg); border: 1px solid var(--card-border);
    border-radius: 0; box-shadow: var(--shadow); overflow: hidden;
  }}

  /* FIX (#4): w nagłówku ikona błędu (czerwony trójkąt), NIE logo Malward. */
  .head {{
    background: linear-gradient(135deg, #c42b2b, #a31e1e);
    padding: 22px 26px; color: #fff;
    display: flex; align-items: center; gap: 16px;
  }}
  .head .icon {{ color: #fff; flex-shrink: 0; line-height: 0; font-size: 28px; }}
  .head .title {{ flex: 1; }}
  .head h1 {{ margin: 0 0 4px 0; font-size: 22px; font-weight: 700; line-height: 1.2; }}
  .head p  {{ margin: 0; font-size: 13.5px; opacity: .92; }}

  .body {{ padding: 22px 28px 24px; }}
  .row {{ margin-bottom: 14px; }}
  .lbl {{ font-size: 12px; color: var(--text-mute); text-transform: uppercase; letter-spacing: .4px; }}
  .val {{ font-size: 14.5px; font-weight: 600; word-break: break-all; margin-top: 4px; color: var(--text); }}
  .det {{ color: #e23b3b; font-family: 'Segoe UI Mono', Consolas, monospace; font-size: 13.5px; }}

  .note {{
    margin-top: 18px; padding: 12px 14px; border-radius: 0;
    background: var(--note-bg); border: 1px solid var(--note-border);
    font-size: 13px; color: var(--text-dim); line-height: 1.55;
  }}

  /* Akcje pod opisem: PRIMARY (powrót, zielony) + secondary (dodaj wyjątek, czerwony).
     Primary = bezpieczne wyjście; secondary = ryzykowne kontynuowanie. */
  .actions {{
    margin-top: 16px; display: flex; gap: 10px; flex-wrap: wrap; align-items: stretch;
  }}
  .btn-back, .btn-add {{
    display: inline-flex; align-items: center; gap: 6px; flex-wrap: wrap;
    text-decoration: none; padding: 10px 16px; font-size: 13.5px; font-weight: 600;
    cursor: pointer; transition: background 120ms ease;
    font-family: inherit; line-height: 1.2;
  }}
  /* PRIMARY — powrót (zielony jak akcja automatyczna w osłonie rezydentnej) */
  .btn-back {{
    background: #1f7a35; color: #fff; border: 1px solid #1f7a35;
  }}
  .btn-back:hover, .btn-back:focus {{ background: #176028; border-color: #176028; }}
  /* SECONDARY — dodaj wyjątek (czerwony, akcja ryzykowna) */
  .btn-add {{
    background: var(--btn-bg); color: var(--btn-fg); border: 1px solid var(--btn-bg);
  }}
  .btn-add:hover, .btn-add:focus {{ background: var(--btn-bg-hov); border-color: var(--btn-bg-hov); }}
  .btn-add code {{
    background: rgba(0,0,0,.18); padding: 1px 6px; border-radius: 0;
    font-family: 'Segoe UI Mono', Consolas, monospace; font-weight: 500;
  }}

  /* FIX (#3 dolna część): pełne LOGO Malward + napis w stopce. */
  .foot {{
    margin-top: 22px; padding-top: 14px; border-top: 1px solid var(--foot-border);
    font-size: 11.5px; color: var(--text-mute);
    display: flex; justify-content: space-between; align-items: center; gap: 10px;
    flex-wrap: wrap;
  }}
  .brand {{ display: inline-flex; align-items: center; gap: 8px; color: var(--brand-fg); }}
  .brand-text {{ font-weight: 700; font-size: 13px; letter-spacing: .2px; }}
  .brand-tm {{ font-size: 8px; font-weight: 600; vertical-align: super; opacity: .7; margin-left: 1px; }}
  .ts {{ font-family: 'Segoe UI Mono', Consolas, monospace; }}
</style>
</head>
<body>{bodyHtml}
</body>
</html>";
    }

    private static string Escape(string s)
        => (s ?? "").Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
}
