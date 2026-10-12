using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace Malward.AppGUI.Services;

public static class WindowChromeHelper
{
    [DllImport("user32.dll")]
    private static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReleaseCapture();

    private const int WM_NCLBUTTONDOWN = 0xA1;
    private const int HTCAPTION = 0x2;
    private const int WM_SYSCOMMAND = 0x112;
    private const int SC_MINIMIZE = 0xF020;
    private const int SC_MAXIMIZE = 0xF030;
    private const int SC_RESTORE  = 0xF120;

    public static void StartDrag(Window window)
    {
        try
        {
            ReleaseCapture();
            var hwnd = new WindowInteropHelper(window).Handle;
            SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
        }
        catch {  }
    }

    public static void Minimize(Window window) => window.WindowState = WindowState.Minimized;

    public static void ToggleMaximize(Window window)
    {
        window.WindowState = window.WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;
    }

    public static void Close(Window window) => window.Close();
}
