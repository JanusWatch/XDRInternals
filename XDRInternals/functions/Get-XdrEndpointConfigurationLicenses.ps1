function Get-XdrEndpointConfigurationLicenses {
    <#
    .SYNOPSIS
        Retrieves Entra ID (AAD) license summary information from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the aggregated license summary for Entra ID (Azure AD) from the
        Microsoft Defender XDR portal. This endpoint returns counts and rollups
        of the AAD licenses associated with the tenant, including totals by
        license type and assignment state. This function includes caching
        support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIdentityLicenseSummary
        Retrieves the Entra ID license summary using cached data if available.

    .EXAMPLE
        Get-XdrIdentityLicenseSummary -Force
        Forces a fresh retrieval of the license summary, bypassing the cache.

    .EXAMPLE
        Get-XdrIdentityLicenseSummary | Format-List
        Retrieves the license summary and expands all properties for inspection.

    .OUTPUTS
        Object
        Returns the Entra ID license summary as returned by the Microsoft
        Defender XDR portal API.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrIdentityLicenseSummary" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Identity License Summary"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrIdentityLicenseSummary"
        } else {
            Write-Verbose "XDR Identity License Summary cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Identity License Summary"
        try {
            $XdrIdentityLicenseSummary = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/licenses/mgmt/aadlicenses/sums" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrIdentityLicenseSummary" -Value $XdrIdentityLicenseSummary -TTLMinutes 30
            return $XdrIdentityLicenseSummary
        } catch {
            throw "Failed to retrieve XDR Identity License Summary: $($_.Exception.Message)"
        }
    }

    end {
    }
}