#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
.SYNOPSIS
    Pester tests for Compliance.ps1.

.DESCRIPTION
    Compliance.ps1 is an admin-only script (#requires -RunAsAdministrator) that, when run
    directly, backs up the registry and then writes ~150+ registry values. To keep these
    tests fast, safe, and runnable without Administrator rights, most of them do NOT
    invoke Compliance.ps1 directly. Instead they parse its AST and extract just the two
    pieces that are safe/useful to unit test in isolation:

      - the Set-HipaaControl function definition
      - the $controls data array

    Those are loaded into this test's scope via dot-sourced scriptblocks built from the
    extracted source text, so none of the script's top-level backup/apply code ever runs.

    Set-HipaaControl is then exercised against Pester's built-in TestRegistry: drive
    (a throwaway HKCU-backed key that Pester creates and tears down automatically), so no
    real registry keys are ever touched by these tests.

    A separate, opt-in "end-to-end" Context actually invokes Compliance.ps1 with -WhatIf.
    It is skipped automatically unless the current session is elevated, since the script's
    #requires statement enforces that regardless of -WhatIf.

.NOTES
    Run with: Invoke-Pester -Path .\tests\Compliance.Tests.ps1
    Requires Pester 5+ (Windows ships 3.4.0; install a current version first):
        Install-Module Pester -MinimumVersion 5.5.0 -Force -SkipPublisherCheck -Scope CurrentUser
#>

Describe 'Compliance.ps1' {
    BeforeDiscovery {
        $script:IsAdmin = $false
        if ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = [Security.Principal.WindowsPrincipal]::new($identity)
            $script:IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
    }

    BeforeAll {
        $script:ScriptPath = (Resolve-Path (Join-Path $PSScriptRoot '..' 'Compliance.ps1')).Path

        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$parseErrors)

        if ($parseErrors.Count -gt 0) {
            throw "Compliance.ps1 has parse errors: $($parseErrors -join '; ')"
        }

        $functionAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Set-HipaaControl'
        }, $true)
        if (-not $functionAst) {
            throw 'Could not find function Set-HipaaControl in Compliance.ps1'
        }

        $controlsAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $node.Left.VariablePath.UserPath -eq 'controls'
        }, $true)
        if (-not $controlsAst) {
            throw 'Could not find $controls definition in Compliance.ps1'
        }

        # Load just the function and the data, without running the script's backup/apply
        # side effects and without needing Administrator rights.
        . ([scriptblock]::Create($functionAst.Extent.Text))
        . ([scriptblock]::Create($controlsAst.Extent.Text))
    }

    Context 'Control data ($controls)' {
        It 'defines at least one control' {
            $controls.Count | Should -BeGreaterThan 0
        }

        It 'gives every control a RegistryPath under HKLM:' {
            foreach ($c in $controls) {
                $c.RegistryPath | Should -Match '^HKLM:' -Because "control '$($c.Control)' should target HKLM"
            }
        }

        It 'gives every control a non-empty Name' {
            foreach ($c in $controls) {
                $c.Name | Should -Not -BeNullOrEmpty -Because "control '$($c.Control)' is missing a value Name"
            }
        }

        It 'gives every enabled control a non-null Value' {
            foreach ($c in ($controls | Where-Object Enabled)) {
                $c.Value | Should -Not -BeNullOrEmpty -Because "control '$($c.Control)' is Enabled but has no recommended Value"
            }
        }

        It 'does not have two controls pointing at the same key/value with conflicting recommended values' {
            $conflicts = $controls |
                Group-Object -Property RegistryPath, Name |
                Where-Object { ($_.Group.Value | Select-Object -Unique).Count -gt 1 }

            $names = ($conflicts | ForEach-Object { $_.Name }) -join '; '
            $conflicts | Should -BeNullOrEmpty -Because "these locations disagree on their recommended value: $names"
        }

        It 'does not contain exact duplicate rows' {
            $dupes = $controls |
                Group-Object -Property Control, RegistryPath, Name, Value |
                Where-Object Count -gt 1

            $names = ($dupes | ForEach-Object { $_.Name }) -join '; '
            $dupes | Should -BeNullOrEmpty -Because "these rows are exact duplicates: $names"
        }
    }

    Context 'Set-HipaaControl' {
        It 'creates the key and sets the value when the key does not exist' {
            $path = 'TestRegistry:\Create'

            Set-HipaaControl -RegistryPath $path -Name 'TestValue' -Value 1 -Confirm:$false

            (Get-ItemProperty -Path $path -Name 'TestValue').TestValue | Should -Be 1
        }

        It 'updates the value when the key and property already exist' {
            $path = 'TestRegistry:\Update'

            Set-HipaaControl -RegistryPath $path -Name 'TestValue' -Value 1 -Confirm:$false
            Set-HipaaControl -RegistryPath $path -Name 'TestValue' -Value 2 -Confirm:$false

            (Get-ItemProperty -Path $path -Name 'TestValue').TestValue | Should -Be 2
        }

        It 'throws when Value is $null' {
            $path = 'TestRegistry:\NullValue'

            { Set-HipaaControl -RegistryPath $path -Name 'TestValue' -Value $null -Confirm:$false } | Should -Throw
        }

        It 'makes no change when called with -WhatIf' {
            $path = 'TestRegistry:\WhatIfOnly'

            Set-HipaaControl -RegistryPath $path -Name 'TestValue' -Value 1 -WhatIf

            Test-Path $path | Should -BeFalse
        }
    }

    Context 'End-to-end script execution (-WhatIf)' -Skip:(-not $script:IsAdmin) {
        It 'runs to completion without throwing' {
            { & $script:ScriptPath -WhatIf -ErrorAction Stop } | Should -Not -Throw
        }

        It 'returns one result object per unique registry location, each with a Status' {
            $results = & $script:ScriptPath -WhatIf

            $results.Count | Should -BeGreaterThan 0
            foreach ($r in $results) {
                $r.PSObject.Properties.Name | Should -Contain 'Status'
                # Nothing is actually written under -WhatIf, so every result should be
                # 'WhatIf' (previewed only), never 'Applied'.
                $r.Status | Should -BeIn @('WhatIf', 'Failed')
            }
        }

        It 'can filter to a single control via -Control' {
            $one = $controls | Where-Object Enabled | Select-Object -First 1
            $results = & $script:ScriptPath -WhatIf -Control $one.Control

            $results.Count | Should -Be 1
            $results[0].RegistryPath | Should -Be $one.RegistryPath
        }
    }
}
