<#
.SYNOPSIS
    Generate a new charset for password generation
.DESCRIPTION
    This method allows to generate a tuned charset for generating a password.
.PARAMETER LettersSet
    Specifies one or more sets of characters to use for generating the password.
.PARAMETER MinLengths
    Specifies the minimum length of characters for each set of characters
.PARAMETER Frequencies
    The probability to have characters in this set, depending on other sets
.OUTPUTS
    PasswordCharset. The charset for generatinng password.
.EXAMPLE
    New-PasswordCharset -Sets @(([byte][char]'a'..[byte][char]'z'), ([byte][char]'A'..[byte][char]'Z')) -MinLengths @(1, 1) -Frequencies @(5, 2)
    Returns a charset that will allow to generate letters between a-z, and A-Z, generated password will have at least 1 character for each set.
    There will be a higher frequency of having lowercase letters.
#>
function New-PasswordCharset {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNull()]
        [char[][]]$Sets = (
            ([byte][char]'a'..[byte][char]'z'),
            ([byte][char]'A'..[byte][char]'Z'),
            ([byte][char]'0'..[byte][char]'9'),
            '@{}()'
        ),

        [Parameter()]
        [ValidateNotNull()]
        [UInt32[]]$MinLengths = (
            1,
            1,
            1,
            1
        ),

        [Parameter()]
        [ValidateNotNull()]
        [UInt32[]]$Frequencies = (
            5,
            5,
            5,
            2
        )
    )

    return [PasswordCharset]::new($Sets, $MinLengths, $Frequencies)
}

<#
.SYNOPSIS
    Generate a pseudo-random password.
.DESCRIPTION
    This function allows to generate a predictable password of any length, the same input must lead to the same output.
.PARAMETER Charset
    The charset to use for generating a password.
.PARAMETER MinimumPasswordLength
    The minimum length of the password to generate.
.PARAMETER MaximumPasswordLength
    The maximum length of the password to generate.
.NOTES
    The function will generate an error if the minimum password length doesn't match the sum of minimum lengths of character from each set.
.PARAMETER Seed
    The seed to use for generating the password.
.OUTPUTS
    System.String. The generated password.
.EXAMPLE
    Get-PseudoRandomPassword -MinimumPasswordLength 10 -MaximumPasswordLength 15 -Seed 0x1234.
    Generates and returns a password of 15 characters (uppercase, lowercase, digits and specials) using the seed 0x1234.
#>
function Get-PseudoRandomPassword {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNull()]
        [PasswordCharset]$Charset = (New-PasswordCharset),

        [Parameter()]
        [ValidateNotNull()]
        [UInt32]$MinimumPasswordLength = 8,

        [Parameter()]
        [ValidateNotNull()]
        [UInt32]$MaximumPasswordLength = 10,

        [Parameter(Mandatory)]
        [ValidateScript({ $_ -is [System.ValueType] -or $_ -is [string]})]
        [ValidateNotNull()]
        [object]$Seed
    )

    # Set the random seed
    New-RandomSeed -Seed $Seed

    [UInt32]$LengthSum = ($Charset.Lengths | Measure-Object -Sum).Sum
    if ($MinimumPasswordLength -lt $LengthSum) {
        throw [System.ArgumentException]::new('Minimum password length is less than the sum of minimum character length for each set')
    }

    # Random password length
    [UInt32]$PasswordLength = Get-Random -Minimum ([int]$MinimumPasswordLength) -Maximum ([int]($MaximumPasswordLength + 1))
    # Generate characters with the given charset
    [char[]]$Characters = Get-RandomCharacters -Charset $Charset -Length $PasswordLength

    return [string]::new($Characters)
}

<#
.SYNOPSIS
    Sets mandatory groups of characters.
#>
function Get-MinimalRandomCharacters {
    param(
        [PasswordCharset]$Charset,
        [char[]]$Characters
    )

    [UInt32]$CurrentLength = 0
    for([UInt32]$i = 0; $i -lt $Charset.Lengths.Count; $i++) {
        [UInt32]$SetLength = $Charset.Lengths[$i]
        [char[]]$Set = $Charset.getSet($i)

        # Avoid using -Count for Get-Random because it doesn't return same characters
        for([UInt32]$j = 0; $j -lt $SetLength; $j++, $CurrentLength++) {
            $Characters[$CurrentLength] = $Set | Get-Random
        }
    }

    return $CurrentLength
}

<#
.SYNOPSIS
    Returns random characters from sets of characters.
#>
function Get-RandomCharacters {
    param(
        [PasswordCharset]$Charset,
        [UInt32]$Length
    )

    [char[]]$Characters = [char[]]::new($Length)
    [Uint32]$CurrentLength = Get-MinimalRandomCharacters -Charset $Charset -Characters $Characters

    for($CurrentLength; $CurrentLength -lt $Length; $CurrentLength++) {
        [UInt32]$Current = Get-Random -Minimum 0 -Maximum ([int]$Charset.getFinalFrequency())
        # Find the set that matches the probability range
        [UInt32]$RandSetIndex = $Charset.getFrequencyIndex($Current)
        [char[]]$Set = $Charset.getSet($RandSetIndex)

        $Characters[$CurrentLength] = $Set | Get-Random
    }

    return $Characters
}

<#
.SYNOPSIS
    Initializes the seed of the random number generator.
.DESCRIPTION
    This function initializes the seed by using either a number or a string.
#>
function New-RandomSeed {
    param(
        [object]$Seed
    )

    if ($Seed -is [System.ValueType]) {
        # Number seed
        $null = Get-Random -SetSeed $Seed
    } elseif ($Seed -is [string]) {
        # String seed
        # Use the string length as the initial seed
        $RandVal = Get-Random -SetSeed $Seed.Length
        # Then procedurally change the seed using the whole string
        for($i = 0; $i -lt $Seed.Length; $i++) {
            $RandVal = Get-Random -SetSeed ($RandVal + $Seed[$i])
        }
    }
}

class PasswordCharset {
    PasswordCharset([char[][]]$Sets, [UInt32[]]$Lengths, [UInt32[]]$Frequencies) {
        if ($Lengths.Count -ne $Sets.Count -or $Frequencies.Count -ne $Sets.Count) {
            throw [System.ArgumentException]::new('Array must have the same count')
        }

        $this.Sets = $Sets
        $this.Lengths = $Lengths

        $this.initRange($Frequencies)
    }

    # Given the frequency, return the index to the matching set
    [UInt32]getFrequencyIndex([UInt32]$Frequency) {
        for([UInt32]$i = 0; $i -lt $this.FrequencyRanges.Count; $i++) {
            if ($Frequency -lt $this.FrequencyRanges[$i]) {
                return $i
            }
        }

        return 0
    }

    # Return all frequencies, normalized with the specified length
    [UInt32[]]getNormalizedFrequencies([UInt32]$Length) {
        [UInt32[]]$NormalizedFrequencies = [UInt32[]]::new($this.Frequencies.Count)
        [UInt32]$HighestFrequency = ($this.Frequencies | Measure-Object -Maximum).Maximum
        [float]$Multiplier = $HighestFrequency / $Length

        for($i = 0; $i -lt $this.Frequencies.Count; $i++) {
            $NormalizedFrequencies[$i] = [UInt32]([float]$this.Frequencies[$i] / $Multiplier)
        }

        return $NormalizedFrequencies
    }

    hidden initRange([UInt32[]]$Frequencies) {
        $SumFrequency = ($Frequencies | Measure-Object -Sum).Sum
        if ($SumFrequency -le 0) {
            throw [System.Exception]::new('The sum of Frequencies must be at least 1')
        }

        $this.Frequencies = $Frequencies
        $this.FrequencyRanges = [UInt32[]]::new($Frequencies.Count)
        $this.FinalFrequency = 0
    
        for($i = 0; $i -lt $Frequencies.Count; $i++) {
            $this.FrequencyRanges[$i] = $Frequencies[$i] + $this.FinalFrequency
            $this.FinalFrequency += $Frequencies[$i]
        }
    }

    # Return the set at index
    [char[]]getSet([UInt32]$Index) {
        return $this.Sets[$Index]
    }

    # Return the number of sets
    [UInt32]getNumSets() {
        return $this.Sets.Count
    }

    # Return the minimum number of characters to use for the specified set
    [UInt32]getSetLength([UInt32]$Index) {
        return $this.Lengths[$index]
    }

    # Return the final frequency
    [UInt32]getFinalFrequency() {
        return $this.FinalFrequency
    }

    hidden [char[][]]$Sets
    hidden [UInt32[]]$Lengths
    hidden [UInt32[]]$FrequencyRanges
    hidden [UInt32[]]$Frequencies
    hidden [UInt32]$FinalFrequency
}

Export-ModuleMember New-PasswordCharset
Export-ModuleMember Get-PseudoRandomPassword
