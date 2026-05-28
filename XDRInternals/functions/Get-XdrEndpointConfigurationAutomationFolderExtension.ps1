function Get-XdrEndpointConfigurationAutomationFolderExtension {
    <#
    .SYNOPSIS
        Gets the AutomationFolderExtension from Defender Settings Endpoint Configuration

    .DESCRIPTION
        Gets the AutomationFolderExtension from Defender Settings Endpoint Configuration
        This function includes caching support with a 30-minute TTL to reduce
        API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointConfigurationAutomationFolderExtension
        Retrieves the data using cached values if available.

    .EXAMPLE
        Get-XdrEndpointConfigurationAutomationFolderExtension -Force
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrEndpointConfigurationAutomationFolderExtension" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Endpoint Configuration Automation Folder Extension"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrEndpointConfigurationAutomationFolderExtension"
        } else {
            Write-Verbose "XDR Endpoint Configuration Automation Folder Extension cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Endpoint Configuration Automation Folder Extension"
        try {
            $result = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/autoIr/folder_exclusion/all?page_size=99999&type=folder" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrEndpointConfigurationAutomationFolderExtension" -Value $result -TTLMinutes 30
            return $result
        } catch {
            throw "Failed to retrieve XDR Endpoint Configuration Automation Folder Extension: $($_.Exception.Message)"
        }
    }

    end {
    }
}