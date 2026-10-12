using System;

namespace Malward.AppGUI.Services;

public interface IWebViewHost
{
    void CreateWebViewControl();
    IntPtr Hwnd { get; }
    ITray CreateWindowsFormsTray();
    object? WebViewControl { get; }
}
