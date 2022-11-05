# Password generation algorithm

## Introduction

This PowerShell script allows you to generate a pseudo-random password, using a seed parameter. This script can be useful, for example, to generate passwords for many users, then the next day send the user their generated password without having it stored somewhere.

It provides the solution to a common problem : generate a password that meets complexity requirements flawlessly

### Features

Many factors can be tuned for generating a password :
* One or more sets of characters to use (i.e lowercase letters, uppercase letters, digits...)
* For each set, the minimum number of characters to grab
* The frequency of each set (the higher the frequency, the more there will be characters from the set)
* Minimum and maximum password length

### Use cases

* Massive predictable password generation, 
* Windows [password complexity](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements) requirement
  * Mass-create many AD accounts by **always** meeting the password requirements

## Usage

```powershell
# Import the password generation module
Import-Module './generate-password.psm1'

# Declare multiple sets of characters :
[char[][]]$Sets = @(
    ([byte][char]'a'..[byte][char]'z'),
    ([byte][char]'A'..[byte][char]'Z'),
    ([byte][char]'0'..[byte][char]'9'),
    [char[]]"@_-#~!&"
)

# Minimum lengths :
## There should be at least 1 lowercase letter, 1 uppercase letter, and 1 digit
[UInt32[]]$MinLengths = @(
    1,
    1,
    1,
    0
)

# Frequencies for each set
## Lowercase and uppercase letters have bigger probabilities of being present in the password
## Digits have lower probabilities
## Special characters have very low chances of presence in the password
[UInt32[]]$Frequencies = @(
    10,
    10,
    5,
    1
)

$Charset = New-PasswordCharset -Sets $Sets -MinLengths $MinLengths -Frequencies $Frequencies

$Password1 = Get-PseudoRandomPassword -Charset $Charset -Seed "salty1" -MinimumPasswordLength 20 -MaximumPasswordLength 30

$Password2 = Get-PseudoRandomPassword -Charset $Charset -Seed 0xDEADDEAD -MinimumPasswordLength 20 -MaximumPasswordLength 30

Write-Host "Generated password: $Password1"
Write-Host "Generated password: $Password2"
```
