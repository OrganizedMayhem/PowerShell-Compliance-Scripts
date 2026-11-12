# PowerShell-Compliance-Scripts

[![CI](https://github.com/OrganizedMayhem/PowerShell-Compliance-Scripts/actions/workflows/ci.yml/badge.svg)](https://github.com/OrganizedMayhem/PowerShell-Compliance-Scripts/actions/workflows/ci.yml)

`Compliance.ps1` applies a set of Windows registry settings recommended for HIPAA-related
hardening. The control numbers referenced throughout the script (e.g. `21.83 1387`) are
references to the **Qualys Compliance scanner's** policy/control IDs, so you can cross-check
a Qualys finding against the exact setting this script applies for it.

> **Disclaimer:** This script changes security-relevant registry settings. It is a helper for
> closing specific, known scanner findings — it is **not** a complete HIPAA compliance program,
> and applying it does not by itself make a system "HIPAA compliant." Review the control list
> below, test in a non-production environment, and involve whoever owns compliance sign-off at
> your organization before running this against production systems.

## What it does

1. **Backs up the registry first.** Before changing anything, it exports `HKLM\SYSTEM` and
   `HKLM\SOFTWARE` to timestamped `.reg` files (`<hive>-yyyyMMdd-HHmmss.reg`) under
   `-BackupPath` (default `C:\Backup-Script`).
2. **Applies each control from a data table.** All ~200 settings live in a single `$controls`
   array near the top of the control-definitions region. Each entry is a `[PSCustomObject]`
   with:

    | Property       | Meaning                                                                   |
    | -------------- | ------------------------------------------------------------------------- |
    | `Control`      | Qualys control/QID reference, e.g. `'21.83 1387'`                         |
    | `Description`  | Human-readable name of the setting, plus any notes on acceptable values   |
    | `RegistryPath` | Full registry key path, e.g. `HKLM:\System\CurrentControlSet\Control\Lsa` |
    | `Name`         | The registry value name under that key                                    |
    | `Value`        | The recommended value to set                                              |
    | `Enabled`      | Whether this control is actually applied (see below)                      |

3. **Skips disabled controls.** 47 of the 203 defined controls have `Enabled = $false`. These
   were commented out in the script's original form — typically because no recommended value
   was ever filled in, or because the setting needs environment-specific judgment before being
   applied automatically (e.g. domain account password-change policies). They're kept in the
   data so you can see what Qualys controls are _not_ auto-remediated and review them manually;
   the script will never write them for you.
4. **De-duplicates registry writes.** A few Qualys control IDs happen to map to the exact same
   registry value (e.g. controls `35.2` and `35.4` both require
   `HKLM:\System\CurrentControlSet\Control\Lsa\DisableDomainCreds = 0`). Both control IDs are
   kept in the data for traceability, but the underlying registry key is only written once per
   run.
5. **Reports results.** The script returns one object per unique registry location it touched,
   with `Controls` (all Qualys IDs satisfied by that write), `RegistryPath`, `Name`, `Value`,
   `Status` (`Applied`/`WhatIf`/`Failed` — `WhatIf` means the change was only previewed, nothing
   was actually written), and `Error`.

## Requirements

- Windows, PowerShell 5.1+ (developed/tested against PowerShell 7).
- **Administrator rights.** The script declares `#requires -RunAsAdministrator`; it will
  refuse to run from a non-elevated prompt, even with `-WhatIf`.

## Usage

```powershell
# Preview every change without touching the registry
.\Compliance.ps1 -WhatIf

# Preview with full detail on every control being evaluated
.\Compliance.ps1 -WhatIf -Verbose

# Apply everything (backs up the registry first)
.\Compliance.ps1

# Apply everything but back up to a custom location
.\Compliance.ps1 -BackupPath 'D:\RegistryBackups'

# Apply only specific controls (e.g. to remediate one Qualys finding at a time)
.\Compliance.ps1 -Control '21.83 1387'
.\Compliance.ps1 -Control '21.83 1387','20.17 1172'

# Capture the result objects for your own reporting/audit trail
$results = .\Compliance.ps1
$results | Where-Object Status -eq 'Failed'
$results | Export-Csv .\compliance-run.csv -NoTypeInformation
```

Because `Set-HipaaControl` (the function that does the actual registry write) implements
`SupportsShouldProcess`, both `-WhatIf` and `-Confirm` work as you'd expect anywhere in the
pipeline.

### Parameters

| Parameter     | Default            | Description                                                                                                                         |
| ------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| `-BackupPath` | `C:\Backup-Script` | Directory the pre-change `.reg` backups are written to.                                                                             |
| `-Control`    | _(all enabled)_    | One or more `Control` values to restrict the run to. Useful for remediating a single Qualys finding without touching anything else. |
| `-LogPath`    | _(none)_           | Optional CSV file to write the result objects to, for an audit trail. Skipped under `-WhatIf` since nothing was actually changed.   |

## Adding or changing a control

Find (or add) its entry in the `$controls` array and edit the `RegistryPath`, `Name`, `Value`,
or `Enabled` fields directly — there's no other code to touch. For a brand-new control, copy an
existing line as a template:

```powershell
[PSCustomObject]@{ Control = '99.1 9999'; Description = 'Describe the setting and acceptable values here'; RegistryPath = 'HKLM:\Path\To\Key'; Name = 'ValueName'; Value = 1; Enabled = $true }
```

Setting `Enabled = $false` (and `Value = $null` if you don't yet know the right value) is the
supported way to document a control without applying it.

## Testing

Unit and data-integrity tests live in [`tests/Compliance.Tests.ps1`](tests/Compliance.Tests.ps1)
and run with [Pester](https://pester.dev/) 5+. Windows ships the old Pester 3.4.0 by default, so
install a current version first:

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Force -SkipPublisherCheck -Scope CurrentUser
```

Then run the suite from the repo root:

```powershell
Invoke-Pester -Path .\tests\Compliance.Tests.ps1
```

The suite covers:

- **Control data integrity** — every control has a valid `HKLM:` path and a `Name`; every
  enabled control has a non-null `Value`; no two controls disagree on the value for the same
  registry location; no exact duplicate rows.
- **`Set-HipaaControl` behavior** — creates missing keys, updates existing values, throws on a
  `$null` value, and makes no change at all when called with `-WhatIf`. These run against
  Pester's `TestRegistry:` drive, a throwaway key that Pester creates and tears down itself, so
  no real registry state is ever touched.
- **End-to-end script execution** (`-WhatIf`) — actually invokes `Compliance.ps1`, including the
  `-Control` filter. These tests require an elevated session (the script's `#requires` statement
  enforces that regardless of `-WhatIf`) and are **skipped automatically** when not running as
  Administrator, rather than failing.

## Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and pull request
against `main` (and can be triggered manually via `workflow_dispatch`), on `windows-latest`:

1. Installs Pester 5+ and PSScriptAnalyzer.
2. Runs PSScriptAnalyzer across `Compliance.ps1` and `tests/`, failing the build only on
   `Error`-severity findings (style `Warning`s are surfaced in the log but don't block).
3. Runs the Pester suite and publishes `TestResults.xml` (NUnit format) as a build artifact.
4. Runs `Compliance.ps1 -WhatIf -Verbose` as a smoke test, so a syntax or logic regression in
   the control data shows up immediately. This step checks whether the runner is elevated first
   and skips with a clear message if not, since the script's `#requires -RunAsAdministrator`
   applies even under `-WhatIf`.

## License

See [`LICENSE`](LICENSE) (CC0 1.0 Universal — public domain).

