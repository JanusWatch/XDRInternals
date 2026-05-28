function Get-XdrIdentityConfigurationActivation {
    <#
    .SYNOPSIS
        Gets the Activation configurations from Defender Identity Settings

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIdentityConfigurationActivation
        Retrieves the data using cached values if available.

    .EXAMPLE
        Get-XdrIdentityConfigurationActivation -Force
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrIdentityConfigurationActivation" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Identity Configuration Activation"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrIdentityConfigurationActivation"
        } else {
            Write-Verbose "XDR Identity Configuration Activation cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Identity Configuration Activation"
        try {
            $result = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/api/defensor/defensorConfiguration" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrIdentityConfigurationActivation" -Value $result -TTLMinutes 30
            return $result
        } catch {
            throw "Failed to retrieve XDR Identity Configuration Activation: $($_.Exception.Message)"
        }
    }

    end {
    }
}