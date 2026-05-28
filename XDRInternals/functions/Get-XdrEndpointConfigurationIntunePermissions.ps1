function Get-XdrEndpointConfigurationIntunePermissions {
    <#
    .SYNOPSIS
        Gets the Intune Permissions set in Defender Endpoint Settings 

    .DESCRIPTION
        Gets the Intune Permissions set in Defender Endpoint Settings
        This function includes caching support with a 30-minute TTL to reduce
        API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointConfigurationIntunePermissions
        Retrieves the data using cached values if available.

    .EXAMPLE
        Get-XdrEndpointConfigurationIntunePermissions -Force
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrEndpointConfigurationIntunePermissions" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Endpoint Configuration Intune Permissions"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrEndpointConfigurationIntunePermissions"
        } else {
            Write-Verbose "XDR Endpoint Configuration Intune Permissions cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Endpoint Configuration Intune Permissions"
        try {
            $result = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/siamApi/MemPermissions/MemRoleAssignment" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrEndpointConfigurationIntunePermissions" -Value $result -TTLMinutes 30
            return $result
        } catch {
            throw "Failed to retrieve XDR Endpoint Configuration Intune Permissions: $($_.Exception.Message)"
        }
    }

    end {
    }
}