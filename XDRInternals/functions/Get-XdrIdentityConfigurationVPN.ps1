function Get-XdrIdentityConfigurationVPN {
    <#
    .SYNOPSIS
        Gets the VPN configurations from Defender Identity Settings

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIdentityConfigurationVPN
        Retrieves the data using cached values if available.

    .EXAMPLE
        Get-XdrIdentityConfigurationVPN -Force
        Forces a fresh retrieval, bypassing the cache.

    .OUTPUTS
        Object
        Returns the response as provided by the Microsoft Defender XDR portal API.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }
    process {
        $currentCacheValue = Get-XdrCache -CacheKey "XdrIdentityConfigurationVPN" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Identity Configuration V P N"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrIdentityConfigurationVPN"
        } else {
            Write-Verbose "XDR Identity Configuration V P N cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Identity Configuration V P N"
        try {
            $result = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/api/mtp/vpnConfiguration/" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrIdentityConfigurationVPN" -Value $result -TTLMinutes 30
            return $result
        } catch {
            throw "Failed to retrieve XDR Identity Configuration V P N: $($_.Exception.Message)"
        }
    }

    end {
    }
}