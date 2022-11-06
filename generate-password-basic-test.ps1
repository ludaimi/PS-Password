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

function Get-BasicRandomPassword {
    param(
        [char[]]$Charset,
        [UInt32]$MinimumLength,
        [UInt32]$MaximumLength
    )

    [UInt32]$Length = Get-Random -Minimum ([int]$MinimumLength) -Maximum ([int]($MaximumLength + 1))
    [char[]]$NewPassword = [char[]]::new($Length)
    for($i = 0; $i -lt $Length; $i++) {
        $NewPassword[$i] = $Charset | Get-Random
    }

    return [string]::new($NewPassword)
}

function Get-BasicRandomPasswords {
    param(
        [char[]]$Charset,
        [UInt32]$Count,
        [UInt32]$MinimumLength,
        [UInt32]$MaximumLength
    )

    [string[]]$Passwords = [string[]]::new($Count)
    for($i = 0; $i -lt $Count; $i++) {
        $Passwords[$i] = Get-BasicRandomPassword -Charset $Charset -Count $Count -MinimumLength $MinimumLength -MaximumLength $MaximumLength
    }

    return $Passwords
}

function Test-SimpleGeneration {
    Get-Random -SetSeed 0x12345678 | Out-Null

    $global:Charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@_-"
    Describe "Test-SimpleGeneration" {
        Context "Generate thousands of password" {
            [string[]]$global:Passwords = @()
            [UInt32]$global:Count = 4000
    
            It "Generate $global:Count passwords of 8 characters" {
                $global:Passwords = Get-BasicRandomPasswords -Charset $global:Charset -Count $global:Count -MinimumLength 8 -MaximumLength 8
            }

            It "Check complexity requirements for 8 characters" {
                [UInt32]$NotMeetingCount = 0
                foreach($Password in $global:Passwords) {
                    $Result = Test-PasswordRequirements -Password $Password -MinimumPasswordLength 8 -Sets $Sets -MinimumLengths $MinLengths
                    if (-not $Result) {
                        $NotMeetingCount++
                    }
                }
    
                $NotMeetingCount | Should Not Be 0
                [double]$Probability = [double]$NotMeetingCount / [double]$global:Passwords.Count
                Write-Host "$NotMeetingCount passwords not meeting complexity requirements, which represent a probability of $Probability"
            }
    
            [string[]]$global:Passwords = @()
            It "Generate $global:Count passwords of 16 characters" {
                $global:Passwords = Get-BasicRandomPasswords -Charset $global:Charset -Count $global:Count -MinimumLength 16 -MaximumLength 16
            }

            It "Check complexity requirements for 16 characters" {
                [UInt32]$NotMeetingCount = 0
                foreach($Password in $global:Passwords) {
                    $Result = Test-PasswordRequirements -Password $Password -MinimumPasswordLength 16 -Sets $Sets -MinimumLengths $MinLengths
                    if (-not $Result) {
                        $NotMeetingCount++
                    }
                }
    
                $NotMeetingCount | Should Not Be 0
                [double]$Probability = [double]$NotMeetingCount / [double]$global:Passwords.Count
                Write-Host "$NotMeetingCount passwords not meeting complexity requirements, which represent a probability of $Probability"
            }
        }
    }
}


Test-SimpleGeneration
