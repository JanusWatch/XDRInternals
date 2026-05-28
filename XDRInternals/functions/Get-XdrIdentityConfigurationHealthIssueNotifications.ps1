function Get-XdrIdentityConfigurationHealthIssueNotifications {
    <#
    .SYNOPSIS
         Gets the Health Issue Notifications configuration from Defender Identity Settings

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIdentityConfigurationHealthIssueNotifications
        Retrieves the data using cached values if available.

    .EXAMPLE
        Get-XdrIdentityConfigurationHealthIssueNotifications -Force
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrIdentityConfigurationHealthIssueNotifications" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Identity Configuration Health Issue Notifications"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrIdentityConfigurationHealthIssueNotifications"
        } else {
            Write-Verbose "XDR Identity Configuration Health Issue Notifications cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Identity Configuration Health Issue Notifications"
        try {
            $result = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/api/workspace/configuration/scopedHealthNotifications/" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrIdentityConfigurationHealthIssueNotifications" -Value $result -TTLMinutes 30
            return $result
        } catch {
            throw "Failed to retrieve XDR Identity Configuration Health Issue Notifications: $($_.Exception.Message)"
        }
    }

    end {
    }
}