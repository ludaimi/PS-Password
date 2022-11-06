# Password generation algorithm

## Introduction

This PowerShell script can help generating a pseudo-random password, using a seed parameter. This script can be useful, for example, to generate passwords for many users, then the next day, send users their generated password without having passwords stored anywhere.

### A common problem

Let's say you want to generate AD users from a database. To generate their password, you may want to use a char array, and generate random characters from the char array. With >1000 users, how many passwords would not meet [password complexity](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements) requirements? The **New-ADUser** function could fail many times because of that.

The password length could be increased to reduce errors, that still doesn't solve the base problem. But even though you may increase the length up to 16, there will be 2 problems :
- Users could have difficulties to input their generated password, you could end up with *many users asking you to reset their password*.
- Security guidelines may prevent you from storing passwords, which mean that the password generation must be done on the fly : the same input with a seed must return the same output

This problem can be solved by generating a password that contain at least 1 character from one or more sets, which is what this script offers : passwords can be generated in a *deterministic* way that meets security guidelines, and is acceptable for users.

### Features

Password generation can be tuned accordingly :
* One or more sets of characters to use (i.e lowercase letters, uppercase letters, digits, custom array...)
* For each set, the minimum number of characters to grab
* The frequency of each set (the higher the frequency, the more there will be characters from the set)
* Minimum and maximum password length
* Exclude words from the password

### Use cases

* Massive predictable password generation, 
* Windows [password complexity](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements) requirements
  * Mass-create many AD accounts by **always** meeting password requirements

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
