@echo off
setlocal enabledelayedexpansion

rem builds a release bundle, deploys qt runtime files, and stages a ready-to-run portable folder.
set ROOT=%~dp0..
pushd "%ROOT%"

set BUILD_DIR=%ROOT%\out\build\x64-Release
set STAGE_DIR=%ROOT%\release\BinaryLens-Portable
set QT_DEPLOY=C:\Qt\6.10.2\msvc2022_64\bin\windeployqt.exe

if not exist "%QT_DEPLOY%" (
    echo windeployqt was not found at: %QT_DEPLOY%
    exit /b 1
)

cmake -S . -B "%BUILD_DIR%" -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 exit /b 1

cmake --build "%BUILD_DIR%" --config Release
if errorlevel 1 exit /b 1

if exist "%STAGE_DIR%" rmdir /s /q "%STAGE_DIR%"
mkdir "%STAGE_DIR%"
if errorlevel 1 exit /b 1

copy /y "%BUILD_DIR%\BinaryLensQt.exe" "%STAGE_DIR%\BinaryLensQt.exe" >nul
if errorlevel 1 exit /b 1

"%QT_DEPLOY%" --release "%STAGE_DIR%\BinaryLensQt.exe"
if errorlevel 1 exit /b 1

mkdir "%STAGE_DIR%\config" 2>nul
copy /y "%ROOT%\BinaryLens\config\config.json" "%STAGE_DIR%\config\config.json" >nul
copy /y "%ROOT%\BinaryLens\config\config.example.json" "%STAGE_DIR%\config\config.example.json" >nul

if exist "%ROOT%\BinaryLens\rules" xcopy /e /i /y "%ROOT%\BinaryLens\rules" "%STAGE_DIR%\rules" >nul
if exist "%ROOT%\BinaryLens\plugins" xcopy /e /i /y "%ROOT%\BinaryLens\plugins" "%STAGE_DIR%\plugins" >nul
if exist "%ROOT%\README.md" copy /y "%ROOT%\README.md" "%STAGE_DIR%\README.md" >nul

echo.
echo portable release created at:
echo %STAGE_DIR%
echo.
echo zip the BinaryLens-Portable folder to publish the portable version.

popd
endlocal
