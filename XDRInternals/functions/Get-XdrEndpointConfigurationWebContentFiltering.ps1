function Get-XdrEndpointConfigurationWebContentFiltering {
    <#
    .SYNOPSIS
        Gets the WebContentFiltering settings from Defender Endpoints Settings

    .DESCRIPTION
        Gets WebContentFiltering settings from Defender Endpoints Settings
        This function includes caching support with a 30-minute TTL to reduce
        API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointsConfigurationWebContentFiltering
        Retrieves the data using cached values if available.

    .EXAMPLE
        Get-XdrEndpointsConfigurationWebContentFiltering -Force
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrEndpointsConfigurationWebContentFiltering" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Endpoints Configuration Web Content Filtering"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrEndpointsConfigurationWebContentFiltering"
        } else {
            Write-Verbose "XDR Endpoints Configuration Web Content Filtering cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Endpoints Configuration Web Content Filtering"
        try {
            $result = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/userRequests/webcategory/policies" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrEndpointsConfigurationWebContentFiltering" -Value $result -TTLMinutes 30
            return $result
        } catch {
            throw "Failed to retrieve XDR Endpoints Configuration Web Content Filtering: $($_.Exception.Message)"
        }
    }

    end {
    }
}