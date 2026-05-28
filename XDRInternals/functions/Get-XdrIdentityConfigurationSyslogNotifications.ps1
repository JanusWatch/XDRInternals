function Get-XdrIdentityConfigurationSyslogNotifications {
    <#
    .SYNOPSIS
        Gets the Syslog Notifications Configurations from Defender Identity Settings

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIdentityConfigurationSyslogNotifications
        Retrieves the data using cached values if available.

    .EXAMPLE
        Get-XdrIdentityConfigurationSyslogNotifications -Force
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrIdentityConfigurationSyslogNotifications" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Identity Configuration Syslog Notifications"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrIdentityConfigurationSyslogNotifications"
        } else {
            Write-Verbose "XDR Identity Configuration Syslog Notifications cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Identity Configuration Syslog Notifications"
        try {
            $result = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/api/workspace/configuration/syslog" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrIdentityConfigurationSyslogNotifications" -Value $result -TTLMinutes 30
            return $result
        } catch {
            throw "Failed to retrieve XDR Identity Configuration Syslog Notifications: $($_.Exception.Message)"
        }
    }

    end {
    }
}