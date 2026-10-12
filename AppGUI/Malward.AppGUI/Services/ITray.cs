using System;
using System.IO;

namespace Malward.AppGUI.Services;

public interface ITray : IDisposable
{
    Action? OnOpen { get; set; }
    Action? OnScan { get; set; }
    Action? OnQuarantine { get; set; }
    Action? OnUpdate { get; set; }
    Action? OnExit { get; set; }
    Action? OnQuickScanBg { get; set; }
    Action? OnUpdateBg { get; set; }
    Action? OnFullScan { get; set; }
    Action? OnCustomScan { get; set; }
    Action? OnBalloonClick { get; set; }
    Action<bool>? OnToggleProtection { get; set; }
    Action<bool>? OnToggleNetworkProtection { get; set; }
    Action<bool>? OnToggleBackup { get; set; }
    Action<bool>? OnToggleSnapshots { get; set; }
    Action<bool>? OnToggleRemovable { get; set; }
    Func<bool>? GetIsDarkTheme { get; set; }

    Action? RestoreOverride { get; set; }
    bool MenuEnabled { get; set; }

    void Restore();
    void SetBusy(BusyKind kind);
    void NotifyBalloon(string title, string message, Action? onClick = null);

    void ApplyBusyFrames(Func<string, byte[]?> assetResolver);
    void ApplyMenuLogo(Func<string, byte[]?> assetResolver);
    void ApplyMenuIcons(Func<string, byte[]?> assetResolver);
    void ApplyHealthIcons(Func<string, byte[]?> assetResolver);

    void SetProtectionState(bool available, bool enabled, bool running);
    void SetNetworkState(bool available, bool enabled, bool running);
    void SetBackupState(bool available, bool on);
    void SetSnapshotsState(bool available, bool on);
    void SetRemovableState(bool available, bool on);
    void SetFooterInfo(string lastUpdate, string version, string dbVersion = "—");
    void SetHealthOverlay(HealthBadge kind);
}
