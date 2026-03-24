; packages the ready-to-run release folder and persists the bundled config into appdata for the installed app.
[Setup]
AppName=BinaryLens
AppVersion=1.1.0
DefaultDirName={autopf}\BinaryLens
DefaultGroupName=BinaryLens
OutputDir=installer_output
OutputBaseFilename=BinaryLens-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "..\release\BinaryLens-Portable\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\release\BinaryLens-Portable\config\config.json"; DestDir: "{userappdata}\BinaryLens"; DestName: "config.json"; Flags: ignoreversion

[Icons]
Name: "{group}\BinaryLens"; Filename: "{app}\BinaryLensQt.exe"
Name: "{autodesktop}\BinaryLens"; Filename: "{app}\BinaryLensQt.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\BinaryLensQt.exe"; Description: "Launch BinaryLens"; Flags: nowait postinstall skipifsilent
