@echo off
setlocal enableextensions enabledelayedexpansion

rem builds a clean public release, stages only runtime files, and writes the portable zip.
set VERSION=1.3.0
set ROOT=%~dp0..
pushd "%ROOT%"

set BUILD_DIR=%ROOT%\out\build\x64-Release-Final
set STAGE_ROOT=%ROOT%\release
set STAGE_DIR=%STAGE_ROOT%\BinaryLens-Portable-v%VERSION%
set ZIP_PATH=%STAGE_ROOT%\BinaryLens-Portable-v%VERSION%.zip
set QT_DEPLOY=C:\Qt\6.10.2\msvc2022_64\bin\windeployqt.exe

rem keep the public release safe by default.
set STAGE_PRIVATE_CONFIG=1
if /i "%BINARYLENS_INCLUDE_PRIVATE_CONFIG%"=="1" set STAGE_PRIVATE_CONFIG=ON

if not exist "%QT_DEPLOY%" (
    echo windeployqt was not found at: %QT_DEPLOY%
    popd
    exit /b 1
)

if not exist "%STAGE_ROOT%" mkdir "%STAGE_ROOT%"
if errorlevel 1 (
    popd
    exit /b 1
)

rem configure with the explicit release folder and avoid bundling a private config unless requested.
cmake -S . -B "%BUILD_DIR%" -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_PREFIX_PATH="C:\Qt\6.10.2\msvc2022_64" ^
  -DWINDEPLOYQT_PATH="%QT_DEPLOY%" ^
  -DBINARYLENS_STAGE_PRIVATE_RUNTIME_CONFIG=%STAGE_PRIVATE_CONFIG%
if errorlevel 1 (
    popd
    exit /b 1
)

cmake --build "%BUILD_DIR%"
if errorlevel 1 (
    popd
    exit /b 1
)

if exist "%STAGE_DIR%" rmdir /s /q "%STAGE_DIR%"
mkdir "%STAGE_DIR%"
if errorlevel 1 (
    popd
    exit /b 1
)

rem copy the two app binaries first so the stage always starts with the intended entry points.
copy /y "%BUILD_DIR%\BinaryLensQt.exe" "%STAGE_DIR%\BinaryLensQt.exe" >nul || goto :copyfail
copy /y "%BUILD_DIR%\BinaryLensUpdater.exe" "%STAGE_DIR%\BinaryLensUpdater.exe" >nul || goto :copyfail

rem bring over every deployed runtime dll without dragging build metadata into the package.
for %%F in ("%BUILD_DIR%\*.dll") do (
    copy /y "%%~fF" "%STAGE_DIR%\" >nul || goto :copyfail
)

rem keep the folder allowlist explicit so build system leftovers never leak into the portable zip.
for %%D in (config generic iconengines imageformats networkinformation platforms plugins rules styles tls translations) do (
    if exist "%BUILD_DIR%\%%D" (
        xcopy /e /i /y "%BUILD_DIR%\%%D" "%STAGE_DIR%\%%D" >nul || goto :copyfail
    )
)

rem stage a real config only when you opt in through BINARYLENS_INCLUDE_PRIVATE_CONFIG=1.
if /i "%STAGE_PRIVATE_CONFIG%"=="ON" (
    if exist "%BUILD_DIR%\config\config.json" (
        copy /y "%BUILD_DIR%\config\config.json" "%STAGE_DIR%\config\config.json" >nul || goto :copyfail
    )
)

if exist "%ZIP_PATH%" del /f /q "%ZIP_PATH%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -Path '%STAGE_DIR%\*' -DestinationPath '%ZIP_PATH%' -Force"
if errorlevel 1 (
    popd
    exit /b 1
)

echo.
echo portable folder created at:
echo %STAGE_DIR%
echo.
echo portable zip created at:
echo %ZIP_PATH%
echo.
if /i "%STAGE_PRIVATE_CONFIG%"=="ON" (
    echo private config staging: enabled
) else (
    echo private config staging: disabled
)

goto :done

:copyfail
echo failed while staging runtime files.
popd
exit /b 1

:done
popd
endlocal
