function Get-XdrEndpointConfigurationAutomationUploads {
    <#
    .SYNOPSIS
        Gets the AutomationUploads from Endpoint in Defender Settings

    .DESCRIPTION
        Gets the AutomationUploads from Endpoint in Defender Settings
        This function includes caching support with a 30-minute TTL to reduce
        API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointConfigurationAutomationUploads
        Retrieves the data using cached values if available.

    .EXAMPLE
        Get-XdrEndpointConfigurationAutomationUploads -Force
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrEndpointConfigurationAutomationUploads" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Endpoint Configuration Automation Uploads"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrEndpointConfigurationAutomationUploads"
        } else {
            Write-Verbose "XDR Endpoint Configuration Automation Uploads cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Endpoint Configuration Automation Uploads"
        try {
            $result = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/autoIr/ui/admin/advanced" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrEndpointConfigurationAutomationUploads" -Value $result -TTLMinutes 30
            return $result
        } catch {
            throw "Failed to retrieve XDR Endpoint Configuration Automation Uploads: $($_.Exception.Message)"
        }
    }

    end {
    }
}