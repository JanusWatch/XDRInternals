function Get-XdrEndpointConfigurationProcessMemoryIndicators {
    <#
    .SYNOPSIS
        Gets the Process Memory Indicators from Defender Endpoint Settings

    .DESCRIPTION
        Gets the Process Memory Indicators from Defender Endpoint Settings
        This function includes caching support with a 30-minute TTL to reduce
        API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointConfigurationProcessMemoryIndicators
        Retrieves the data using cached values if available.

    .EXAMPLE
        Get-XdrEndpointConfigurationProcessMemoryIndicators -Force
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrEndpointConfigurationProcessMemoryIndicators" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Endpoint Configuration Process Memory Indicators"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrEndpointConfigurationProcessMemoryIndicators"
        } else {
            Write-Verbose "XDR Endpoint Configuration Process Memory Indicators cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Endpoint Configuration Process Memory Indicators"
        try {
            $result = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/autoIr/acl/filters?type=memory_content" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrEndpointConfigurationProcessMemoryIndicators" -Value $result -TTLMinutes 30
            return $result
        } catch {
            throw "Failed to retrieve XDR Endpoint Configuration Process Memory Indicators: $($_.Exception.Message)"
        }
    }

    end {
    }
}