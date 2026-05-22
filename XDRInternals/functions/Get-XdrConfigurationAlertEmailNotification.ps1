function Get-XdrConfigurationAlertEmailNotification {
    <#
    .SYNOPSIS
        Retrieves alert email notification rules from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the list of email notification rules for alerts configured in the
        Microsoft Defender XDR portal. These are the rules that determine which
        recipients receive email notifications when alerts are raised, including
        the configured severities, device group scope, and recipient addresses.
        This function includes caching support with a 30-minute TTL to reduce
        API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrConfigurationAlertEmailNotification
        Retrieves all alert email notification rules using cached data if available.

    .EXAMPLE
        Get-XdrConfigurationAlertEmailNotification -Force
        Forces a fresh retrieval of the alert email notification rules, bypassing the cache.

    .EXAMPLE
        Get-XdrConfigurationAlertEmailNotification | Where-Object { $_.isEnabled }
        Retrieves only the enabled alert email notification rules.

    .OUTPUTS
        Object[]
        Returns an array of alert email notification rule objects as returned by
        the Microsoft Defender XDR portal API.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrAlertEmailNotification" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Alert Email Notifications"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrAlertEmailNotification"
        } else {
            Write-Verbose "XDR Alert Email Notifications cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Alert Email Notifications"
        try {
            $XdrAlertEmailNotifications = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/alertsEmailNotifications/email_notifications" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrAlertEmailNotification" -Value $XdrAlertEmailNotifications -TTLMinutes 30
            return $XdrAlertEmailNotifications
        } catch {
            throw "Failed to retrieve XDR Alert Email Notifications: $($_.Exception.Message)"
        }
    }

    end {
    }
}