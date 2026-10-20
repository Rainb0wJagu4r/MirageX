@echo off
title MirageX - Registro de Menu Contextual e Icono .wraith
cls
echo ====================================================================
echo   MirageX // Asociacion de Archivo .wraith y Menu Contextual
echo   Icono Oficial: nobug.ico | Cifrado Post-Cuantico ML-KEM + AES-GCM
echo ====================================================================
echo.

set "APP_DIR=%~dp0"
set "EXE_PATH=%APP_DIR%miragex.exe"
set "ICO_PATH=%APP_DIR%nobug.ico"

if not exist "%EXE_PATH%" (
    echo [!] No se encontro miragex.exe en la misma carpeta.
    echo Asegurate de ejecutar este archivo en la carpeta donde esta miragex.exe.
    pause
    exit /b 1
)

if not exist "%ICO_PATH%" (
    set "ICO_PATH=%EXE_PATH%"
)

echo [*] Registrando Menu Contextual: Cifrar con MirageX en archivos y carpetas...
reg add "HKCU\Software\Classes\*\shell\MirageX.Encrypt" /ve /d "Cifrar con MirageX (Post-Quantum)" /f >nul
reg add "HKCU\Software\Classes\*\shell\MirageX.Encrypt" /v "Icon" /d "\"%EXE_PATH%\",0" /f >nul
reg add "HKCU\Software\Classes\*\shell\MirageX.Encrypt\command" /ve /d "\"%EXE_PATH%\" --gui-encrypt \"%%1\"" /f >nul

reg add "HKCU\Software\Classes\Directory\shell\MirageX.Encrypt" /ve /d "Cifrar con MirageX (Post-Quantum)" /f >nul
reg add "HKCU\Software\Classes\Directory\shell\MirageX.Encrypt" /v "Icon" /d "\"%EXE_PATH%\",0" /f >nul
reg add "HKCU\Software\Classes\Directory\shell\MirageX.Encrypt\command" /ve /d "\"%EXE_PATH%\" --gui-encrypt \"%%1\"" /f >nul

echo [*] Registrando Asociacion .wraith con nobug.ico y opciones Descifrar e Inspeccionar...
reg add "HKCU\Software\Classes\.wraith" /ve /d "MirageX.wraith" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith" /ve /d "WRAITH Encrypted Container" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith\DefaultIcon" /ve /d "\"%ICO_PATH%\",0" /f >nul

reg add "HKCU\Software\Classes\MirageX.wraith\shell\open" /ve /d "Descifrar con MirageX (Post-Quantum)" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith\shell\open" /v "Icon" /d "\"%ICO_PATH%\",0" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith\shell\open\command" /ve /d "\"%EXE_PATH%\" --gui-decrypt \"%%1\"" /f >nul

reg add "HKCU\Software\Classes\MirageX.wraith\shell\inspect" /ve /d "Inspeccionar Contenedor WRAITH" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith\shell\inspect" /v "Icon" /d "\"%ICO_PATH%\",0" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith\shell\inspect\command" /ve /d "\"%EXE_PATH%\" --gui-inspect \"%%1\"" /f >nul

echo [*] Actualizando cache de iconos del explorador de Windows...
ie4uinit.exe -show >nul 2>&1

echo.
echo ====================================================================
echo [OK] Menu contextual e icono de MirageX registrados con exito!
echo     - Archivo con clic derecho: 'Cifrar con MirageX (Post-Quantum)'
echo     - Carpeta con clic derecho: 'Cifrar con MirageX (Post-Quantum)'
echo     - Archivo .wraith: 'Descifrar' e 'Inspeccionar' con nobug.ico
echo ====================================================================
echo.
pause
