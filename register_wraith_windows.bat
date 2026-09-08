@echo off
title MirageX - Registro de Icono y Asociacion .wraith
cls
echo ====================================================================
echo   MirageX // Asociacion de Archivo .wraith y Registro de Icono
echo ====================================================================
echo.

set "APP_DIR=%~dp0"
set "EXE_PATH=%APP_DIR%miragex.exe"

if not exist "%EXE_PATH%" (
    echo [!] No se encontro miragex.exe en la misma carpeta.
    echo Asegurate de ejecutar este archivo junto a miragex.exe.
    pause
    exit /b 1
)

echo [*] Registrando extension .wraith en Windows Explorer...
reg add "HKCU\Software\Classes\.wraith" /ve /d "MirageX.wraith" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith" /ve /d "WRAITH Encrypted Container" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith\DefaultIcon" /ve /d "\"%EXE_PATH%\",0" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith\shell\open\command" /ve /d "\"%EXE_PATH%\" \"%%1\"" /f >nul

echo [*] Actualizando cache de iconos del explorador...
ie4uinit.exe -show >nul 2>&1

echo.
echo [OK] Asociacion e icono de .wraith registrados con exito en tu usuario!
echo.
pause
