function Get-XdrEndpointConfigurationEnforcementScope {
    <#
    .SYNOPSIS
        Retrieves the combined enforcement scope across domain controllers,
        Defender for Endpoint, and Endpoint Manager from Microsoft Defender XDR.

    .DESCRIPTION
        Gets a unified view of the Microsoft Defender XDR enforcement scope by
        querying three separate endpoints: domain controller coverage totals,
        Microsoft Defender for Endpoint (MDE) status, and Microsoft Endpoint
        Manager (MEM) onboarding status. The combined object exposes each
        source under a named property for downstream inspection or drift
        detection. This function includes caching support with a 30-minute
        TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from all three endpoints.

    .EXAMPLE
        Get-XdrEnforcementScope
        Retrieves the combined enforcement scope using cached values if available.

    .EXAMPLE
        Get-XdrEnforcementScope -Force
        Forces a fresh retrieval from all three endpoints, bypassing the cache.

    .EXAMPLE
        (Get-XdrEnforcementScope).DomainControllers
        Retrieves just the domain controller totals portion of the combined result.

    .OUTPUTS
        PSCustomObject
        Returns an object with three properties: DomainControllers, MdeStatus,
        and MemOnboardStatus, each containing the raw response from its
        respective Microsoft Defender XDR portal API endpoint.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrEnforcementScope" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Enforcement Scope"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrEnforcementScope"
        } else {
            Write-Verbose "XDR Enforcement Scope cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Enforcement Scope"
        try {
            Write-Verbose "Calling domain controllers totals endpoint"
            $domainControllers = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/siamApi/domaincontrollers/totals" -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            Write-Verbose "Calling MDE status endpoint"
            $mdeStatus = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/siamApi/mdestatus" -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            Write-Verbose "Calling MEM onboard status endpoint"
            $memOnboardStatus = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/siamApi/memonboardstatus" -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $XdrEnforcementScope = [PSCustomObject]@{
                DomainControllers = $domainControllers
                MdeStatus         = $mdeStatus
                MemOnboardStatus  = $memOnboardStatus
            }

            Set-XdrCache -CacheKey "XdrEnforcementScope" -Value $XdrEnforcementScope -TTLMinutes 30
            return $XdrEnforcementScope
        } catch {
            throw "Failed to retrieve XDR Enforcement Scope: $($_.Exception.Message)"
        }
    }

    end {
    }
}