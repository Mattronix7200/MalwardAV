#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// ─── Pipe ────────────────────────────────────────────────────────────────────
// Named pipe przez który DLL komunikuje się z residentshield.exe.
// Protokół: wysyłamy ścieżkę pliku (UTF-8, zakończoną \n),
//           odbieramy "ALLOW\n" lub "BLOCK\n".
#define SHIELD_PIPE_NAME L"\\\\.\\pipe\\MalwardShieldHook"

// ─── Eksportowane symbole ─────────────────────────────────────────────────────
#ifdef SHIELDHOOK_EXPORTS
#   define HOOK_API __declspec(dllexport)
#else
#   define HOOK_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/// Instaluje hooki IAT w docelowym module (domyślnie ntdll / kernel32).
HOOK_API BOOL InstallHooks();

/// Usuwa hooki i przywraca oryginalne wskaźniki.
HOOK_API BOOL RemoveHooks();

#ifdef __cplusplus
}
#endif
