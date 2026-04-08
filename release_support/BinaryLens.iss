; packages the clean portable folder and seeds appdata without overwriting an existing user config.
[Setup]
AppName=BinaryLens
AppVersion=1.3.0
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
Source: "..\release\BinaryLens-Portable-v1.3.0\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\release\BinaryLens-Portable-v1.3.0\config\config.json"; DestDir: "{userappdata}\BinaryLens"; DestName: "config.json"; Flags: onlyifdoesntexist ignoreversion; Check: HasBundledPrivateConfig
Source: "..\release\BinaryLens-Portable-v1.3.0\config\config.example.json"; DestDir: "{userappdata}\BinaryLens"; DestName: "config.json"; Flags: onlyifdoesntexist ignoreversion; Check: not HasBundledPrivateConfig

[Icons]
Name: "{group}\BinaryLens"; Filename: "{app}\BinaryLensQt.exe"
Name: "{autodesktop}\BinaryLens"; Filename: "{app}\BinaryLensQt.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\BinaryLensQt.exe"; Description: "Launch BinaryLens"; Flags: nowait postinstall skipifsilent

[Code]
function HasBundledPrivateConfig: Boolean;
begin
  Result := FileExists(ExpandConstant('{src}\..\release\BinaryLens-Portable-v1.3.0\config\config.json'));
end;
