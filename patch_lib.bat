@echo off
REM ─────────────────────────────────────────────────────────────────────────────
REM  BW16 / RTL8720DN — lib_wlan.a patch (SDK 3.2.0 ve uzeri icin guncellendi)
REM
REM  Neden gerekli?
REM    wifi_send_raw_frame, Realtek'in lib_wlan.a dosyasinda "gizli" (local)
REM    sembol olarak tutulur. Bu script, sembolu "global" yaparak Arduino
REM    derleyicisinin fonksiyonu bulmasini saglar.
REM
REM  Kaynak:
REM    https://tesa-klebeband.github.io/making-raw-802-11-frame-injection-possible-on-an-rtl8720dn
REM
REM  KULLANIM:
REM    1. Bu dosyayi cift tiklayin (yonetici hakki gerekmez).
REM    2. Ekranda "BASARILI" yaziyi gorun.
REM    3. Arduino IDE'den projeyi derleyip BW16'ya yukleyin.
REM    4. SDK guncellendikten sonra tekrar calistirmaniz gerekebilir.
REM ─────────────────────────────────────────────────────────────────────────────

SET PKGS=%LOCALAPPDATA%\Arduino15\packages

SET LIB=
SET OBJCOPY=

echo ============================================================
echo  BW16 RTL8720DN - lib_wlan.a Patch Script
echo  SDK surumu otomatik algilaniyor...
echo ============================================================
echo.

REM ── lib_wlan.a ara (tum SDK versiyonlari) ────────────────────────────────────
FOR /D %%P IN ("%PKGS%\realtek\hardware\AmebaD\*") DO (
  IF EXIST "%%P\variants\AmebaD\libs\lib_wlan.a" (
    SET LIB=%%P\variants\AmebaD\libs\lib_wlan.a
    echo [+] lib_wlan.a bulundu:
    echo     %%P\variants\AmebaD\libs\lib_wlan.a
  )
)

REM ── arm-none-eabi-objcopy ara ─────────────────────────────────────────────────
FOR /D %%T IN ("%PKGS%\realtek\tools\arm-none-eabi-gcc\*") DO (
  IF EXIST "%%T\bin\arm-none-eabi-objcopy.exe" (
    SET OBJCOPY=%%T\bin\arm-none-eabi-objcopy.exe
    echo [+] arm-none-eabi-objcopy bulundu:
    echo     %%T\bin\arm-none-eabi-objcopy.exe
  )
)

REM ── Hata kontrolleri ──────────────────────────────────────────────────────────
IF "%LIB%"=="" (
  echo.
  echo [!] HATA: lib_wlan.a bulunamadi.
  echo     Arduino IDE'den "AmebaD" kart paketini yukleyin:
  echo     Araclar ^> Kart ^> Kart Yoneticisi ^> "AmebaD" arayin
  echo.
  pause
  exit /b 1
)

IF "%OBJCOPY%"=="" (
  echo.
  echo [!] HATA: arm-none-eabi-objcopy bulunamadi.
  echo     Kart paketi kurulumunda ARM toolchain otomatik gelir.
  echo     Arduino IDE'den AmebaD SDK'yi yeniden yukleyin.
  echo.
  pause
  exit /b 1
)

REM ── Yedek al ──────────────────────────────────────────────────────────────────
echo.
IF NOT EXIST "%LIB%.bak" (
  echo [*] Orijinal dosya yedekleniyor...
  copy "%LIB%" "%LIB%.bak" >nul
  echo [+] Yedek olusturuldu: lib_wlan.a.bak
) ELSE (
  echo [i] Yedek zaten mevcut, atlanıyor.
)

REM ── Patch uygula ──────────────────────────────────────────────────────────────
echo.
echo [*] wifi_send_raw_frame sembolu global yapiliyor...
"%OBJCOPY%" --globalize-symbol=wifi_send_raw_frame "%LIB%" "%LIB%"

IF %ERRORLEVEL% EQU 0 (
  echo.
  echo ============================================================
  echo  BASARILI! Patch uygulandi.
  echo.
  echo  Siradaki adim:
  echo    Arduino IDE ^> BW16_Security.ino ^> Yukle (Ctrl+U)
  echo ============================================================
) ELSE (
  echo.
  echo [!] HATA: Patch uygulanamadi!
  echo     Yedekten geri yuklemek icin:
  echo     copy "%LIB%.bak" "%LIB%"
)

echo.
pause
