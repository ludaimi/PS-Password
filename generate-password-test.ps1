Import-Module "./implementations/generate-password.psm1" -Force
Import-Module "./implementations/password-requirements.psm1" -Force

[char[][]]$Sets = @(
    ([byte][char]'a'..[byte][char]'z'),
    ([byte][char]'A'..[byte][char]'Z'),
    ([byte][char]'0'..[byte][char]'9'),
    [char[]]"@_-#~!&"
)

# At least 1 lowercase, 1 uppercase, 1 digit
[UInt32[]]$MinLengths = @(
    1,
    1,
    1,
    0
)

# Lowercase/uppercase have an higher frequency
# Digits have a lower frequency
# Symbols have a very low frequency
[UInt32[]]$Frequencies = @(
    10,
    10,
    5,
    1
)

[string[]]$Exclusions = @(
    "*ab*",
    "*ef*"
)

function Get-Charset {
    param(
        [bool]$WithExclusion = $false
    )

    if ($WithExclusion) {
        return New-PasswordCharset -Sets $Sets -MinLengths $MinLengths -Frequencies $Frequencies -Exclusions $Exclusions -CaseSensitiveExclusions $false
    } else {
        return New-PasswordCharset -Sets $Sets -MinLengths $MinLengths -Frequencies $Frequencies
    }
}

function Get-MassPseudoRandomPassword1 {
    param(
        [UInt32]$Count,
        [bool]$WithExclusion = $false
    )

    $Charset = Get-Charset -WithExclusion $WithExclusion

    # Test with int seed
    [string[]]$Generated = [string[]]::new($Count)
    for([UInt32]$i = 0; $i -lt $Count; $i++) {
        $Generated[$i] = Get-PseudoRandomPassword -Charset $Charset -Seed ([UInt32](0x45 + $i)) -MinimumPasswordLength 8 -MaximumPasswordLength 15
    }

    return $Generated
}

function Get-MassPseudoRandomPassword2 {
    param(
        [UInt32]$Count,
        [bool]$WithExclusion = $false
    )

    $Charset = Get-Charset -WithExclusion $WithExclusion

    # Test with string seed
    [string[]]$Generated = [string[]]::new($Count)
    for([UInt32]$i = 0; $i -lt $Count; $i++) {
        $Generated[$i] = Get-PseudoRandomPassword -Charset $Charset -Seed "pass_$i" -MinimumPasswordLength 8 -MaximumPasswordLength 15
    }

    return $Generated
}

function Get-GeneratedPasswords {
    [string[]]$global:Passwords = @()
    [UInt32]$global:Count = 4000
    Describe "Get-MassPseudoRandomPassword" {
        Context "Password generation" {
            It "Must generate $global:Count passwords using int seeds" {
                $global:Passwords += Get-MassPseudoRandomPassword1 -Count $global:Count
            }
    
            It "Must generate $global:Count passwords using string seeds" {
                $global:Passwords += Get-MassPseudoRandomPassword2 -Count $global:Count
            }
        }

        Context "Generated passwords check" {
            $global:Passwords[0] | Should Be "B55C0tdW2bh"
            $global:Passwords[1999] | Should Be "15PW4E8IcPge"
            $global:Passwords[2000] | Should Be "L2Nej8yG"
            $global:Passwords[3999] | Should Be "PSbcp18@v"
        }
    }

    return $global:Passwords
}

function Get-GeneratedPasswordsWithExclusions {
    [string[]]$global:Passwords = @()
    [UInt32]$global:Count = 1000
    Describe "Get-MassPseudoRandomPassword" {
        Context "Password generation" {
            It "Must generate $global:Count passwords using int seeds" {
                $global:Passwords += Get-MassPseudoRandomPassword1 -Count $global:Count -WithExclusion $true
            }
    
            It "Must generate $global:Count passwords using string seeds" {
                $global:Passwords += Get-MassPseudoRandomPassword2 -Count $global:Count -WithExclusion $true
            }
        }
    }

    return $global:Passwords
}

function Test-Passwords {
    param(
        [string[]]$Passwords
    )

    Describe "Password complexity requirements" {
        Context "Test password requirements" {
            It "Should return true" {
                foreach($Password in $Passwords) {
                    $Result = Test-PasswordRequirements -Password $Password -MinimumPasswordLength 8 -Sets $Sets -MinimumLengths $MinLengths
                    $Result | Should Be $true
                }
            }
    
            It "Should return false" {
                [UInt32]$NumBad = 0
                foreach($Password in $Passwords) {
                    $Result = Test-PasswordRequirements -Password $Password -MinimumPasswordLength 8 -Sets $Sets -MinimumLengths $MinLengths -ExcludedTokens $global:Exclusions -CaseSensitiveTokens $false
                    if (-not $Result) {
                        $NumBad++
                    }
                }

                $NumBad | Should Not Be 0
            }
        }
    }
}

function Test-PasswordsWithExclusions {
    param(
        [string[]]$Passwords
    )

    Describe "Password complexity requirements with exclusions" {
        Context "Test password requirements with exclusions" {
            It "Should return true" {
                foreach($Password in $Passwords) {
                    $Result = Test-PasswordRequirements -Password $Password -MinimumPasswordLength 8 -Sets $Sets -MinimumLengths $MinLengths -ExcludedTokens $global:Exclusions -CaseSensitiveTokens $false
                    $Result | Should Be $true
                }
            }
        }
    }
}

function Test-ComplexityRequirements {
    Describe "Test-PasswordRequirements" {
        Context "Matching sets" {
            It "Should meet password length requirement" {
                Test-PasswordRequirements -Password "abcdefghij" -MinimumPasswordLength 8 | Should Be $true
            }
    
            It "should meet requirements 1" {
                Test-PasswordRequirements -Password "abcd3FGH" -MinimumPasswordLength 8 -Sets $Sets -MinimumLengths $MinLengths | Should Be $true
            }
    
            It "should meet requirements 2" {
                Test-PasswordRequirements -Password "3Vabtest" -MinimumPasswordLength 8 -Sets $Sets -MinimumLengths $MinLengths | Should Be $true
            }
    
            It "should meet requirements with excluded tokens" {
                Test-PasswordRequirements -Password "abcV3abc" -MinimumPasswordLength 8 -Sets $Sets -MinimumLengths $MinLengths -ExcludedTokens "abcd" -CaseSensitiveTokens $false | Should Be $true
            }
        }

        Context "Not matching sets" {
            It "should not meet length requirement" {
                Test-PasswordRequirements -Password "abcdef" -MinimumPasswordLength 8 | Should Be $false
            }
    
            It "should not meet requirements 1" {
                Test-PasswordRequirements -Password "abcdefghijklm" -MinimumPasswordLength 8 -Sets $Sets -MinimumLengths $MinLengths | Should Be $false
            }
    
            It "should not meet requirements 2" {
                Test-PasswordRequirements -Password "aBcdefghijklm" -MinimumPasswordLength 8 -Sets $Sets -MinimumLengths $MinLengths | Should Be $false
            }
    
            It "should not meet requirements 3" {
                Test-PasswordRequirements -Password "abcd3fghijklm" -MinimumPasswordLength 8 -Sets $Sets -MinimumLengths $MinLengths | Should Be $false
            }
    
            It "should not meet requirements with excluded tokens" {
                Test-PasswordRequirements -Password "abcdABCD3ae@" -MinimumPasswordLength 8 -Sets $Sets -MinimumLengths $MinLengths -ExcludedTokens "abcd" -CaseSensitiveTokens $false | Should Be $true
            }
        }
    }
}

Test-ComplexityRequirements

[string[]]$Passwords = Get-GeneratedPasswords
Test-Passwords $Passwords

[string[]]$Passwords = Get-GeneratedPasswordsWithExclusions
Test-PasswordsWithExclusions $Passwords

return $Passwords
