function Get-XdrIdentityConfigurationAbout {
    <#
    .SYNOPSIS
        Gets the information provided in About in Defender Identity Settings

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIdentityConfigurationAbout
        Retrieves the data using cached values if available.

    .EXAMPLE
        Get-XdrIdentityConfigurationAbout -Force
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrIdentityConfigurationAbout" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Identity Configuration About"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrIdentityConfigurationAbout"
        } else {
            Write-Verbose "XDR Identity Configuration About cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Identity Configuration About"
        try {
            $result = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/api/mtp/applicationData" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrIdentityConfigurationAbout" -Value $result -TTLMinutes 30
            return $result
        } catch {
            throw "Failed to retrieve XDR Identity Configuration About: $($_.Exception.Message)"
        }
    }

    end {
    }
}