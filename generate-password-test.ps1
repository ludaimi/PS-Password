Import-Module "./implementations/generate-password.psm1" -Force

function Get-Charset {
    [char[][]]$Sets = @(
        ([byte][char]'a'..[byte][char]'z'),
        ([byte][char]'A'..[byte][char]'Z'),
        ([byte][char]'0'..[byte][char]'9'),
        [char[]]"@_-#~!&"
    )

    [UInt32[]]$MinLengths = @(
        1,
        1,
        1,
        0
    )

    [UInt32[]]$Frequencies = @(
        10,
        10,
        5,
        1
    )

    return New-PasswordCharset -Sets $Sets -MinLengths $MinLengths -Frequencies $Frequencies
}

function Get-MassPseudoRandomPassword {
    param(
        [UInt32]$Count
    )

    $Charset = Get-Charset

    $Test = Get-PseudoRandomPassword -Charset $Charset -Seed (0x45 + 115) -MinimumPasswordLength 200 -MaximumPasswordLength 200

    # Test with int seed
    [string[]]$Passwords = [string[]]::new($Count)
    for([UInt32]$i = 0; $i -lt ($Count / 2); $i++) {
        $Passwords[$i] = Get-PseudoRandomPassword -Charset $Charset -Seed ([UInt32](0x45 + $i)) -MinimumPasswordLength 30 -MaximumPasswordLength 30
    }

    # Test with string seed
    for([UInt32]$i = ($Count / 2); $i -lt $Count; $i++) {
        $Passwords[$i] = Get-PseudoRandomPassword -Charset $Charset -Seed "pass_$i" -MinimumPasswordLength 30 -MaximumPasswordLength 30
    }

    return $Passwords
}

[string[]]$Passwords = @()
$Elapsed = Measure-Command {
    $Passwords = Get-MassPseudoRandomPassword -Count 1000
}

Write-Host "Passwords were generated in $Elapsed"

return $Passwords
