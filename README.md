# BinaryLens

<p align="right">
  <a href="./README.md">
    <img src="https://img.shields.io/badge/lang-English-1f6feb?style=flat-square" alt="English">
  </a>
  <a href="./README_pt-BR.md">
    <img src="https://img.shields.io/badge/lang-Português--BR-009c3b?style=flat-square" alt="Português (BR)">
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/language-C%2B%2B-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white" alt="C++">
  <img src="https://img.shields.io/badge/ui-Qt%206-41CD52?style=for-the-badge&logo=qt&logoColor=white" alt="Qt 6">
  <img src="https://img.shields.io/badge/build-CMake-064F8C?style=for-the-badge&logo=cmake&logoColor=white" alt="CMake">
  <img src="https://img.shields.io/badge/asm-MASM-6B7280?style=for-the-badge" alt="MASM">
  <img src="https://img.shields.io/badge/status-active%20development-111827?style=for-the-badge" alt="Active development">
</p>


BinaryLens is a Windows desktop triage tool for inspecting suspicious **files, URLs, and IPs**.

It is built in **C++**, uses a **Qt desktop UI**, and includes **assembly-assisted pattern scanning** for lower-level matching work. The goal is to surface useful signals quickly and make follow-up investigation easier.

BinaryLens is not meant to replace a sandbox, an EDR, or full manual reverse engineering. It is a first-pass tool, and also a practical project for people who want to study how this kind of desktop security tooling can be built.

## Project Website

<p align="center">
  <a href="https://binarylens.pages.dev/">
    <img src="https://img.shields.io/badge/PROJECT%20WEBSITE-OPEN-7c3aed?style=for-the-badge" alt="Project Website">
  </a>
</p>

## Download

**Current release:** `v1.2.0`

If you only want to use the app, just click on one of the banners for the version you want.

Release assets:

- `BinaryLens-Setup.exe`
- `BinaryLens-Portable-v1.2.0.zip`

The packaged releases already include the executable and the Qt runtime files required to run BinaryLens. No separate Qt installation is needed.

### Release types

#### Installer
Best option for normal end users.

- install and launch
- no manual Qt setup
- intended to work out of the box

#### Portable
Best option if you want an extract-and-run package.

- extract the `.zip`
- open the folder
- run `BinaryLensQt.exe`

No separate Qt installation is required here either.
<br>
<br>
<p align="center">
  <a href="https://github.com/MrcVnz/BinaryLens/releases/download/v1.2.0/BinaryLens-Portable-v1.2.0.zip">
    <img src="https://img.shields.io/badge/PORTABLE%20VERSION-Download-1f6feb?style=for-the-badge&logo=github" alt="Portable Version">
  </a>
  <a href="https://github.com/MrcVnz/BinaryLens/releases/download/v1.2.0/BinaryLens-Setup.exe">
    <img src="https://img.shields.io/badge/INSTALLER%20VERSION-Download-2ea043?style=for-the-badge&logo=windows" alt="Installer Version">
  </a>
</p>

---

## Demo

Quick look at the current desktop workflow:

<p align="center">
<img src="assets/demo.gif" width="856" alt="BinaryLens demo">
</p>

---

## Who this is for

BinaryLens is mainly aimed at:

- cybersecurity students
- reverse engineering beginners
- malware triage learners
- developers interested in native Windows security tooling
- people who want to study a practical **C++ + Qt + MASM** project

This project makes the most sense for learners who already know basic programming and want to move into Windows-focused security tooling.

## What it does

- scans local files, URLs, and raw IP targets from a desktop UI
- combines multiple analysis signals into a single report
- supports both **file triage** and **URL / IP context triage**
- uses checks such as:
  - hash generation
  - PE parsing
  - import inspection
  - archive inspection
  - embedded payload checks
  - context-aware embedded payload corroboration and signal reliability calibration
  - archive-aware handling so low-level byte motifs do not automatically over-escalate clean containers
  - script abuse indicators
  - YARA-based matching
  - VirusTotal lookups for files, URLs, and raw IP reputation where applicable
- includes assembly-backed pattern scanning for performance-sensitive matching work
- supports report export, IOC export, clipboard copy, and analyst-oriented views

## Typical use cases

You can use BinaryLens to:

- inspect a suspicious file before deeper analysis
- get a quick first-pass view of a URL or IP
- pull provider / ASN / ownership context for raw IP targets
- export reports and IOCs for follow-up work
- study how a native Windows triage tool is structured internally

## Project layout

```text
BinaryLens/
├─ BinaryLens/
│  ├─ asm/
│  ├─ config/
│  ├─ include/
│  ├─ plugins/
│  ├─ rules/
│  └─ src/
│     ├─ analyzers/
│     ├─ asm/
│     ├─ core/
│     ├─ scanners/
│     └─ services/
├─ qt_app/
│  ├─ include/
│  ├─ resources/
│  └─ src/
├─ assets/
├─ release_support/
├─ CMakeLists.txt
└─ .gitignore
```

## Requirements

- Windows 10 or 11
- Visual Studio 2022 or newer with C++ desktop tools
- CMake 3.21+
- Qt 6 (this project was built around **Qt 6.10.2 msvc2022_64**)
- MASM / ml64 (installed with Visual Studio)
- Inno Setup 6 (only if you want to generate the installer yourself)

## Clone the repository

Using Git:

```bash
git clone https://github.com/MrcVnz/BinaryLens.git
cd BinaryLens
```

Or download the project as a ZIP directly from GitHub and extract it locally.

## Building

Open the project root in Visual Studio as a **CMake project**.

If Qt is not installed in the default path used by this repo, set `CMAKE_PREFIX_PATH` to your Qt installation before configuring.

Expected default Qt path:

```text
C:/Qt/6.10.2/msvc2022_64
```

### Build steps

1. Open the root folder in Visual Studio
2. Let CMake configure the project
3. Build the `BinaryLensQt` target
4. Run the generated executable

The project can be configured to call `windeployqt` after build so the Qt runtime is copied next to the executable automatically.

## Release workflow

The repository now includes support files for generating both packaged Windows releases:

- **portable release**
- **installer release**

Useful files:

- `release_support/make_portable_release.bat`
- `release_support/BinaryLens.iss`

Typical flow:

1. build `x64-Release`
2. run `release_support/make_portable_release.bat`
3. test the generated `BinaryLens-Portable` folder
4. zip it for the portable release
5. open `release_support/BinaryLens.iss` in Inno Setup and compile the installer

## VirusTotal configuration

There are two supported ways to use the VirusTotal integration:

### 1. Prebuilt release / packaged executable

For packaged public releases, the app is distributed in a way that the end user does not need to manually set up Qt files.

For source builds, VirusTotal still uses local configuration rules.

### 2. Building from source

If you clone the repository and build BinaryLens yourself, create this file locally:

```text
BinaryLens/config/config.json
```

You can copy the example file below and fill in your own key:

```text
BinaryLens/config/config.example.json
```

Expected format:

```json
{
  "virustotal_api_key": "PASTE_YOUR_VIRUSTOTAL_API_KEY_HERE"
}
```

## Notes

- The current desktop app entry point is the **Qt** frontend.
- The repo should not include build output, deployed Qt DLLs, or personal runtime secrets.
- BinaryLens should be treated as a triage and learning tool, not as a final authority on whether something is malicious.
- Raw IP analysis is intended to provide context and triage guidance, not full internet intelligence enrichment.
- Release binaries can be packaged for normal users, but source builds are still the better path if you want to inspect or modify the project yourself.

## Why the repo is structured this way

This project grew in stages. The core analysis code, the assembly work, and the Qt UI live in separate areas on purpose so the codebase stays easier to reason about.

- `BinaryLens/src/core` holds the analysis flow and verdict logic
- `BinaryLens/src/analyzers` holds feature-specific analysis modules
- `BinaryLens/src/services` covers external-facing helpers such as API usage
- `BinaryLens/src/asm` and `BinaryLens/asm` hold the C++ / MASM bridge and low-level routines
- `qt_app` contains the current desktop interface
- `release_support` contains helper files for release packaging

## Current status

BinaryLens is a personal project. Expect rough edges, experiments, and fast changes.

If you clone it, treat it like a real development repo, not a finished commercial product.

## Creator

GitHub: **MrcVnz**