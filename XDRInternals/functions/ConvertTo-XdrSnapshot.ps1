function ConvertTo-XdrSnapshot {
    <#
    .SYNOPSIS
        Converts XDR cmdlet output into canonical JSON suitable for drift detection.

    .DESCRIPTION
        Produces stable, comparable JSON by sorting object keys recursively, expanding
        all nested objects to a sufficient depth, and optionally stripping volatile
        fields (timestamps, counters) that change between runs without representing
        actual configuration drift.

    .PARAMETER InputObject
        The object(s) to snapshot. Accepts pipeline input.

    .PARAMETER Depth
        Maximum serialization depth (default 20).

    .PARAMETER ExcludeProperty
        Property names (case-insensitive) to strip from the output at any nesting
        level. Defaults to commonly volatile fields.

    .PARAMETER Compress
        Emit compact JSON (one line) instead of indented. Useful for storage;
        leave off for line-based diffing.

    .EXAMPLE
        Get-XdrConfigurationAlertEmailNotification | ConvertTo-XdrSnapshot |
            Set-Content ".\snapshots\alert-email-notifications.json"

    .EXAMPLE
        # Combined baseline of multiple configurations
        [ordered]@{
            EmailNotifications   = Get-XdrConfigurationAlertEmailNotification
            SuppressionRules     = Get-XdrSuppressionRule
            AlertServiceSettings = Get-XdrConfigurationAlertServiceSetting
        } | ConvertTo-XdrSnapshot | Set-Content ".\baseline.json"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $InputObject,

        [int]$Depth = 20,

        [string[]]$ExcludeProperty = @(
            'lastActivity', 'updateTime', 'lastSeen', 'lastSeenTime',
            'matchingAlertsCount', 'lastUpdateTime', 'lastModified',
            '@odata.etag', 'etag'
        ),

        [switch]$Compress
    )

    begin {
        $collected = [System.Collections.Generic.List[object]]::new()

        function Normalize-Node {
            param($Node, [string[]]$Exclude)
            if ($null -eq $Node) { return $null }
            if ($Node -is [string] -or $Node -is [bool] -or $Node -is [datetime] -or $Node.GetType().IsPrimitive) {
                return $Node
            }
            if ($Node -is [System.Collections.IDictionary]) {
                $ordered = [ordered]@{}
                foreach ($key in ($Node.Keys | Sort-Object)) {
                    if ($Exclude -notcontains $key) {
                        $ordered[$key] = Normalize-Node -Node $Node[$key] -Exclude $Exclude
                    }
                }
                return $ordered
            }
            if ($Node -is [System.Collections.IEnumerable]) {
                return @($Node | ForEach-Object { Normalize-Node -Node $_ -Exclude $Exclude })
            }
            # PSCustomObject and similar
            $ordered = [ordered]@{}
            foreach ($prop in ($Node.PSObject.Properties | Sort-Object Name)) {
                if ($Exclude -notcontains $prop.Name) {
                    $ordered[$prop.Name] = Normalize-Node -Node $prop.Value -Exclude $Exclude
                }
            }
            return $ordered
        }
    }

    process {
        $collected.Add($InputObject)
    }

    end {
        # Unwrap single piped object; preserve array shape otherwise
        $payload = if ($collected.Count -eq 1) { $collected[0] } else { $collected.ToArray() }
        $normalized = Normalize-Node -Node $payload -Exclude $ExcludeProperty
        $normalized | ConvertTo-Json -Depth $Depth -Compress:$Compress
    }
}