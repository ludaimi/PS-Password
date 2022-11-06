<#
.SYNOPSIS
    Check if the specified password meets password requirements.
.DESCRIPTION
    This function allows to generate a predictable password of any length, the same input must lead to the same output.
.PARAMETER Charset
    The charset to use for generating a password.
.PARAMETER MinimumPasswordLength
    The minimum length of the password to generate.
.PARAMETER MaximumPasswordLength
    The maximum length of the password to generate.
.PARAMETER Seed
    The seed to use for generating the password.
.NOTES
    The function will generate an error if the minimum password length doesn't match the sum of minimum lengths of character from each set.
.OUTPUTS
    System.String. The generated password.
.EXAMPLE
    Get-PseudoRandomPassword -MinimumPasswordLength 10 -MaximumPasswordLength 15 -Seed 0x1234.
    Generates and returns a password of 15 characters (uppercase, lowercase, digits and specials) using the seed 0x1234.
#>
function Test-PasswordRequirements {
    param(
        [string]$Password,
        [UInt32]$MinimumPasswordLength,
        [char[][]]$Sets,
        [UInt32[]]$MinimumLengths,
        [string[]]$ExcludedTokens = @(),
        [bool]$CaseSensitiveTokens = $true
    )

    if ($Password.Length -lt $MinimumPasswordLength) {
        return $false
    }

    # Check complexity requirements
    for($i = 0; $i -lt $Sets.Count; $i++) {
        if (-not (Test-InSet -Set $Sets[$i] -MinimumLength $MinimumLengths[$i] -Password $Password)) {
            return $false
        }
    }

    # Check exclusions
    if ($CaseSensitiveTokens) {
        foreach($ExcludedToken in $ExcludedTokens) {
            if ($Password -clike $ExcludedToken) {
                return $false
            }
        }
    } else {
        foreach($ExcludedToken in $ExcludedTokens) {
            if ($Password -ilike $ExcludedToken) {
                return $false
            }
        }
    }

    return $true
}

function Test-InSet {
    param(
        [char[]]$Set,
        [UInt32]$MinimumLength,
        [string]$Password
    )

    if (-not $MinimumLength) {
        return $true
    }

    [UInt32]$FoundCount = 0
    for($i = 0; $i -lt $Password.Length; $i++) {
        for($j = 0; $j -lt $Set.Count; $j++) {
            if ($Password[$i] -ceq $Set[$j]) {
                $FoundCount++
                if ($FoundCount -ge $MinimumLength) {
                    return $true
                }
            }
        }
    }

    return $false
}

Export-ModuleMember Test-PasswordRequirements
