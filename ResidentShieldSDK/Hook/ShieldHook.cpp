/*
 * ShieldHook.cpp  —  IAT hook DLL dla residentshield.exe
 *
 * Cel: przechwycić CreateProcessW / CreateProcessA i zapytać
 *      residentshield.exe przez named pipe, czy zezwolić na
 *      uruchomienie procesu.
 *
 * Technika: IAT (Import Address Table) patching
 *   1. Znajdź moduł hosta (GetModuleHandle(NULL))
 *   2. Przejdź po IMAGE_IMPORT_DESCRIPTOR
 *   3. Zastąp wpisy dla CreateProcessW / CreateProcessA naszymi funkcjami
 *   4. Przy usuwaniu przywróć oryginalne wskaźniki
 *
 * Kompilacja: MSVC, x64, DLL, bez Detours (tylko Windows SDK)
 */

#define WIN32_LEAN_AND_MEAN
#define SHIELDHOOK_EXPORTS
#include "ShieldHook.h"

#include <Windows.h>
#include <winternl.h>
#include <ImageHlp.h>           // IMAGE_IMPORT_DESCRIPTOR itp.
#include <strsafe.h>
#include <string>
#include <mutex>

#pragma comment(lib, "imagehlp.lib")

// ─── Typy oryginałów ─────────────────────────────────────────────────────────

using FnCreateProcessW = BOOL(WINAPI*)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

using FnCreateProcessA = BOOL(WINAPI*)(
    LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

// ─── Globalne wskaźniki ───────────────────────────────────────────────────────

static FnCreateProcessW g_origCreateProcessW = nullptr;
static FnCreateProcessA g_origCreateProcessA = nullptr;
static std::mutex       g_mutex;

// ─── Named pipe – zapytaj serwis ─────────────────────────────────────────────

/**
 * Wysyła ścieżkę do pipe, odbiera "ALLOW" lub "BLOCK".
 * Zwraca true = zezwól, false = zablokuj (lub błąd pipe → domyślnie zezwól).
 */
static bool AskShield(const wchar_t* imagePath)
{
    if (!imagePath || imagePath[0] == L'\0') return true;

    HANDLE pipe = CreateFileW(
        SHIELD_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr,
        OPEN_EXISTING, 0, nullptr);

    if (pipe == INVALID_HANDLE_VALUE) return true;   // serwis niedostępny → przepuść

    // Konwersja ścieżki do UTF-8 + '\n'
    char utf8[2048] = {};
    WideCharToMultiByte(CP_UTF8, 0, imagePath, -1, utf8, (int)sizeof(utf8) - 2, nullptr, nullptr);
    size_t len = strlen(utf8);
    utf8[len]     = '\n';
    utf8[len + 1] = '\0';

    DWORD written = 0;
    WriteFile(pipe, utf8, (DWORD)(len + 1), &written, nullptr);

    char resp[32] = {};
    DWORD read = 0;
    ReadFile(pipe, resp, (DWORD)sizeof(resp) - 1, &read, nullptr);
    CloseHandle(pipe);

    // Odpowiedź "BLOCK" → zablokuj
    return _strnicmp(resp, "BLOCK", 5) != 0;
}

// ─── Hooked functions ────────────────────────────────────────────────────────

static BOOL WINAPI HookedCreateProcessW(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    const wchar_t* target = lpApplicationName ? lpApplicationName : lpCommandLine;

    if (!AskShield(target))
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    return g_origCreateProcessW(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);
}

static BOOL WINAPI HookedCreateProcessA(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    // Konwersja do Unicode i weryfikacja
    wchar_t wide[2048] = {};
    const char* src = lpApplicationName ? lpApplicationName : lpCommandLine;
    if (src)
        MultiByteToWideChar(CP_ACP, 0, src, -1, wide, (int)(sizeof(wide)/sizeof(wchar_t)) - 1);

    if (!AskShield(wide))
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    return g_origCreateProcessA(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);
}

// ─── IAT patching ─────────────────────────────────────────────────────────────

struct HookEntry
{
    const char* moduleName;   // np. "KERNEL32.DLL"
    const char* procName;     // np. "CreateProcessW"
    void**      origPtr;      // wskaźnik na zmienną przechowującą oryginał
    void*       hookFn;       // nasza funkcja zastępcza
};

static HookEntry g_hooks[] = {
    { "KERNEL32.DLL", "CreateProcessW", (void**)&g_origCreateProcessW, (void*)HookedCreateProcessW },
    { "KERNEL32.DLL", "CreateProcessA", (void**)&g_origCreateProcessA, (void*)HookedCreateProcessA },
};

/**
 * Zastępuje jeden wpis IAT.
 * @param base       baza modułu hosta
 * @param moduleName nazwa biblioteki w IAT (np. "KERNEL32.DLL")
 * @param procName   nazwa funkcji
 * @param newFn      nowa funkcja
 * @param oldFn      [out] oryginalny wskaźnik
 */
static bool PatchIAT(HMODULE base, const char* moduleName,
                     const char* procName, void* newFn, void** oldFn)
{
    auto* dosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* ntHdr = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<BYTE*>(base) + dosHdr->e_lfanew);

    DWORD importRVA = ntHdr->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) return false;

    auto* impDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        reinterpret_cast<BYTE*>(base) + importRVA);

    for (; impDesc->Name != 0; ++impDesc)
    {
        const char* name = reinterpret_cast<const char*>(
            reinterpret_cast<BYTE*>(base) + impDesc->Name);
        if (_stricmp(name, moduleName) != 0) continue;

        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            reinterpret_cast<BYTE*>(base) + impDesc->FirstThunk);

        auto* origThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            reinterpret_cast<BYTE*>(base) + impDesc->OriginalFirstThunk);

        for (; origThunk->u1.AddressOfData != 0; ++origThunk, ++thunk)
        {
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) continue;

            auto* byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                reinterpret_cast<BYTE*>(base) + origThunk->u1.AddressOfData);

            if (_stricmp(byName->Name, procName) != 0) continue;

            // Znaleziono wpis — patch przez VirtualProtect
            void** pFn = reinterpret_cast<void**>(&thunk->u1.Function);
            *oldFn = *pFn;

            DWORD oldProtect = 0;
            if (!VirtualProtect(pFn, sizeof(void*), PAGE_READWRITE, &oldProtect))
                return false;

            *pFn = newFn;
            VirtualProtect(pFn, sizeof(void*), oldProtect, &oldProtect);
            return true;
        }
    }
    return false;
}

// ─── Eksportowane funkcje ─────────────────────────────────────────────────────

HOOK_API BOOL InstallHooks()
{
    std::lock_guard<std::mutex> lk(g_mutex);
    HMODULE base = GetModuleHandleW(nullptr);   // moduł hosta (.exe)
    if (!base) return FALSE;

    int ok = 0;
    for (auto& h : g_hooks)
    {
        if (PatchIAT(base, h.moduleName, h.procName, h.hookFn, h.origPtr))
            ++ok;
    }
    return ok > 0 ? TRUE : FALSE;
}

HOOK_API BOOL RemoveHooks()
{
    std::lock_guard<std::mutex> lk(g_mutex);
    HMODULE base = GetModuleHandleW(nullptr);
    if (!base) return FALSE;

    // Przywróć oryginały (odwrotna kolejność niż instalacja)
    for (auto& h : g_hooks)
    {
        if (*h.origPtr == nullptr) continue;
        void* dummy = nullptr;
        PatchIAT(base, h.moduleName, h.procName, *h.origPtr, &dummy);
        *h.origPtr = nullptr;
    }
    return TRUE;
}

// ─── DllMain ─────────────────────────────────────────────────────────────────

BOOL APIENTRY DllMain(HMODULE /*hModule*/, DWORD reason, LPVOID /*reserved*/)
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
            InstallHooks();
            break;

        case DLL_PROCESS_DETACH:
            RemoveHooks();
            break;
    }
    return TRUE;
}
