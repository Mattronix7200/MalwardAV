<img width="923" height="270" alt="logo" src="https://github.com/user-attachments/assets/5f08ad8c-5e76-4a31-b8c2-2df3d969e5af" />

## 

Program Malward to darmowy skaner antywirusowy tzw. drugiej opinii — działa obok Twojego podstawowego programu ochronnego i wyłapuje to, co mogło mu umknąć. Nie musisz niczego odinstalowywać. Został zaprojektowany tak, aby nie wchodzić w konflikt z innym oprogramowaniem zabezpieczającym. Program jest lekki i skuteczny — silnik skanera korzysta z lokalnych baz sygnatur oraz analizy w chmurze, dzięki czemu obciążenie komputera pozostaje minimalne, a wykrywalność możliwie jak najwyższa.

### Główne moduły ochronne:
* Osłona Rezydentna – ciągły monitoring i analiza zagrożeń w czasie rzeczywistym.
* Osłona sieciowa – blokowanie złośliwych domen i niepożądanego ruchu sieciowego.
* Zintegrowany moduł zapory (bazuje na Windows Firewall) – kontrola połączeń na poziomie procesów.
* Ochrona składników systemu – wykrywanie i blokowanie podejrzanych zachowań systemowych.
* Kopia zapasowa – zabezpieczenie najważniejszych danych użytkownika.

### Ważne informacje o produkcie
Program posiada mechanizmy osłon w czasie rzeczywistym, które można włączyć. Jednakże, osłony te nie są skorelowane z głębszą integracją w systemie, tzw: **sterownik jądra**, dzięki któremu, program miałby bezpośredni dostęp do blokowania zagrożeń w czasie rzeczywistym. Program używa wszystkich dostępnych w systemie metod, które pozwolą zachować możliwie jak najlepsze bezpieczeństwo, choć nie gwarantuje ona pełnej ochrony. Najlepiej korzystać z programu, w połączeniu z innym pakietem zabezpieczającym, np: programem antywirusowym Windows Defender. System analizy w chmurze wykorzystuje skanowanie pliku wysyłanego do naszego serwera analizy, który wykorzystując cztery silniki skanujące- zwiększają pokrycie i detekcję. Przesyłany plik jest analizowany i natychmiastowo usuwany po wykonanej analizie. Dostępna jest wersja programu nie zawierającego mechanizmu osłon, oraz dodatkowych narzędzi, umożliwiając tylko skanowanie na żądanie.


## 

<img width="1056" height="596" alt="app" src="https://github.com/user-attachments/assets/a38a8d46-ccf1-4343-8517-d8b2a4a4f80c" />

## Spis treści

- [Wymagania systemowe](#wymagania-systemowe)
- [Repozytorium](#repozytorium)
- [Licencja](#licencja)
- [Pobieranie](#pobierz)
- [English version](#english-version)

## Wymagania systemowe

| Element | Wymaganie |
|---|---|
| System | Windows 10 lub Windows 11, wyłącznie **64-bitowy** |
| Dysk | **2 GB** |
| Pamięć | 1 GB  |
| Sieć | Połączenie z serwerem aktualizacji |
| Środowisko | **.NET SDK 8.0** |

## Repozytorium

Część plików została **celowo pominięta** — ze względu na bezpieczeństwo kodu i samego produktu.
Program używa **własnego systemu autoryzacji** między klientem a serwerem: klient nie rozmawia
z chmurą „anonimowo", tylko uwierzytelnia każde wywołanie. Opublikowanie materiału klucza albo
szczegółów tego protokołu zniosłoby całą warstwę ochronną, dlatego ich tu nie znajdziesz. W efekcie
kod programu można wyświetlić, budować i modyfikować, ale pełna funkcjonalność będzie dostępna 
tylko po zainstalowaniu programu z poziomu instalatora i wymaga dostępu udzielonego przez autora.

## Kompilacja

```bat
dotnet build EngineSDK\Malward.Engine\Malward.Engine.csproj -c Release
dotnet build AppGUI\Malward.AppGUI\Malward.AppGUI.csproj -c Release
```

Ważne: Kompilacja wymaga plików zasobów, które nie zostały załączone w tym repozytorium!

Pominięte są:

- **`config.vdeb`** — klucz autoryzacji klienta. Bez niego program nie wystartuje; trzeba
  dostarczyć własny.
- **`client-auth.json`, `server-auth.json`, `api-keys.json`** — klucze API usług
  zewnętrznych.
- **Usługa serwerowa (VPS)** — budowanie baz, endpointy aktualizacji i chmura skanująca nie są
  publikowane. Repozytorium zawiera klienta.
- **Bazy sygnatur (`*.vdeb`)** — ze względu na rozmiar (ok. 700 MB) nie znajdują się tutaj.

W efekcie kod można czytać, budować i modyfikować, ale pełna funkcjonalność chmurowa
wymaga dostępu udzielonego przez autora.

## Licencja

Zezwala się na bezpłatny wgląd, pobieranie oraz modyfikowanie niniejszego kodu źródłowego
wyłącznie do celów prywatnych, edukacyjnych i niekomercyjnych.

**Zastrzeżenia i ograniczenia:**

1. Zabrania się sprzedawania, licencjonowania oraz wykorzystywania niniejszego kodu
   (lub jego zmodyfikowanych wersji) w celach komercyjnych bez uprzedniej, pisemnej zgody autora.
2. Zabrania się publikowania zmodyfikowanych wersji pod inną marką/produktem jako własnego
   rozwiązania komercyjnego bez zgody autora.
3. Wszelkie zmodyfikowane wersje udostępniane publicznie muszą zawierać informację o pierwotnym
   autorze oraz być objęte niniejszą licencją.

Oprogramowanie jest dostarczane „takie, jakie jest" (AS IS), bez jakiejkolwiek gwarancji.

## Pobierz

https://github.com/Mattronix7200/MalwardAV/releases/tag/pre-final

## Zrzuty ekranu

<img width="1918" height="920" alt="scn4" src="https://github.com/user-attachments/assets/e950c4fd-e067-4279-9a70-0798d4e7a92b" />
<img width="1918" height="920" alt="scn6" src="https://github.com/user-attachments/assets/749ace1c-372c-4564-8c1a-bbecc0dc5a80" />
<img width="1918" height="920" alt="scn7" src="https://github.com/user-attachments/assets/ce00a243-2703-4f82-aa69-6805dcc47576" />
<img width="1918" height="920" alt="scn13" src="https://github.com/user-attachments/assets/3226df67-ef64-4f31-8304-6b30e27b308c" />


---

<details>
<summary><b>English version</b> — click to expand</summary>

## 

Malward is a free, second-opinion antivirus scanner — it runs alongside your primary security software to catch what might have slipped past it. You don't need to uninstall anything, as it is designed not to conflict with other security solutions. The program is lightweight and effective: the scanner engine utilizes local signature databases and cloud analysis, keeping system resource usage to a minimum while maximizing detection rates.

### Main Protection Modules:
- Real-Time Protection – continuous monitoring and threat analysis in real time.
- Network Protection – blocking malicious domains and unwanted network traffic.
- Integrated Firewall Module (based on Windows Firewall) – process-level connection control.
- System Component Protection – detecting and blocking suspicious system behaviors.
- Backup – securing the user's most critical data.

### Important Product Information
The program features real-time protection mechanisms that can be enabled. However, these protections are not tied to deep system integration, the so-called **kernel driver**, which would grant the program direct access to block threats in real time. The program uses all available system methods to maintain the highest possible level of security, although full protection is not guaranteed. It is best used in combination with another security suite, such as Windows Defender. The cloud analysis system scans files by sending them to our analysis server, which utilizes four scanning engines to increase coverage and detection. The uploaded file is analyzed and immediately deleted after the analysis is complete. A version of the program without protection mechanisms and additional tools is also available, offering on-demand scanning only.

## 

## Table of Contents

- [System Requirements](#system-requirements)
- [Repository](#repository)
- [License](#license)
- [Download](#download)
- [Polish version](#polish-version)

## System Requirements

| Element | Requirement |
|---|---|
| OS | Windows 10 or Windows 11, **64-bit only** |
| Disk | **2 GB** |
| Memory | 1 GB |
| Network | Connection to the update server |
| Environment | **.NET SDK 8.0** |

## Repository

Some files have been **intentionally omitted** for the security of the code and the product itself.
The program uses a **custom authorization system** between the client and the server: the client does not communicate with the cloud "anonymously," but authenticates every call. Publishing the key material or the details of this protocol would remove the entire protective layer, which is why you will not find them here. As a result, the program's code can be viewed, built, and modified, but full functionality will only be available after installing the program via the installer and requires authorization granted by the author.

### Building from source

```bat
dotnet build EngineSDK\Malward.Engine\Malward.Engine.csproj -c Release
dotnet build AppGUI\Malward.AppGUI\Malward.AppGUI.csproj -c Release
```

Warning: Resource files are required to run the compiler. These files are not included in this repository.

Withheld:

- **`config.vdeb`** — the client authorisation key. The program will not start without it; 
- **`client-auth.json`, `server-auth.json`, `api-keys.json`** — third-party API keys.
- **The server (VPS) side** — database building, update endpoints and the cloud scanner are not
  published. This repository contains the client.
- **Signature databases (`*.vdeb`)** — because of their size (about 700 MB) they are not stored
  in the repository; 
- **The signing certificate** and the details of the signing procedure.

In practice: the code can be read, built and modified, but full cloud functionality requires your
own backend or access granted by the author.


## License

Free viewing, downloading, and modification of this source code is permitted exclusively for private, educational, and non-commercial purposes.

**Terms and Restrictions:**

1. Selling, licensing, or using this code (or its modified versions) for commercial purposes without the author's prior written consent is strictly prohibited.
2. Publishing modified versions under a different brand/product as a proprietary commercial solution without the author's consent is strictly prohibited.
3. Any modified versions shared publicly must include a notice acknowledging the original author and must be distributed under this license.

The software is provided "AS IS", without any warranty of any kind.

## Download

https://github.com/Mattronix7200/MalwardAV/releases/tag/pre-final

</details>
