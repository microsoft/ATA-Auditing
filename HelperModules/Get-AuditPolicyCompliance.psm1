function Measure-AtaCompliance() {
    param(
        # Version of ATA to be assessed against (i.e. "1.7", "1.8")
        # Default version is 1.8
        [Parameter(Mandatory=$false)]
        [string]
        $AtaVersion="1.8",

        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]
        $AuditPolFile
    )

    <#
     .Description
      ATA v1.8 requires Windows Event IDs:

    #>
    switch ($AtaVersion) {
        "1.7" { Measure-AtaComplianceOneSeven -AuditPolFilePath $AuditPolFile}
        "1.8" { Measure-AtaComplianceOneEight -AuditPolFilePath $AuditPolFile }
        Default {
            Write-Error -Message "Incorrect ATA Version passed. Default value is 1.8. Possible Overrides:`n - 1.7`n- 1.8" -ErrorAction exit
        }
    }
}

function Measure-AtaComplianceOneSeven(){
<#
    .SYNOPSIS
    Used to assess ATA v1.7 implementations

    .PARAMETER AuditPolFile
    Location of AuditPol file

    .NOTES
    Only 4776 is required for ATA v1.7 (Cred Validation)
#>
    param(
        # AuditPol file
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $AuditPolFilePath
    )
    $Csv = Import-Csv -Path $AuditPolFilePath
    $CredVal = $false
    $SecGroupMgmt = $false
    foreach ($Policy in $Csv){
        If ($Policy.Subcategory -eq "Credential Validation"){
            If ($Policy.'Setting Value' -ne 0){
                $CredVal = $true
            }
        }
    }
    $rDetails = New-Object psobject -Property @{
        CredVal = $CredVal
    }
    $highLevel = $null
    If ($CredVal){
        $highLevel = $true
    }
    else {
        $highLevel = $false
    }
    return New-Object psobject -Property @{
        Details = $rDetails
        HighLevel = $highLevel
    }
}

function Measure-AtaComplianceOneEight(){
    <#    
    .DESCRIPTION
    We need:
        - 4776 (Account Logon > Audit Credential Validation)
        - 4728 (Account Management > Audit Security Group Management)
        - 4729 (Account Management > Audit Security Group Management)
        - 4732 (Account Management > Audit Security Group Management)
        - 4733 (Account Management > Audit Security Group Management)
        - 4756 (Account Management > Audit Security Group Management)
        - 4757 (Account Management > Audit Security Group Management)
    
        Need to check policy for GLOBAL setting (i.e. Account Management as well as the specific Sub Gategory)

        That said, need to check:
        - Account Logon (GLOBAL)
        - Account Management (GLOBAL) or Audit Security Group Management (Sub) (business logic is exactly same) Default: Success
        - Credential Validation (Sub) Default: Success
    
    .PARAMETER AuditPolFile
    Location of the shared AuditPol file (output of aggregate auditpol backups from all DCs)
    
    .NOTES
    AuditPol categories/sub-categories
    https://social.technet.microsoft.com/wiki/contents/articles/15232.active-directory-services-audit-document-references.aspx
    
    Audit: Force audit policy subcatgory settings to override audit policy category settings
    https://technet.microsoft.com/en-us/library/dd772710(v=ws.10).aspx

    AD DS Auditing Step-by-Step Guide
    https://technet.microsoft.com/library/cc731607(v=ws.10).aspx
    #>
    param(
        # AuditPol file
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $AuditPolFilePath
    )
    $Csv = Import-Csv -Path $AuditPolFilePath
    $CredVal = $false
    $SecGroupMgmt = $false
    foreach ($Policy in $Csv){
        If ($Policy.Subcategory -eq "Credential Validation"){
            If ($Policy.'Setting Value' -ne 0){
                $CredVal = $true
            }
        }
        ElseIf ($Policy.Subcategory -eq "Security Group Management"){
            If ($Policy.'Setting Value' -ne 0){
                $SecGroupMgmt = $true
            }
        }
        Else{
            #do nothing
        }
    }
    $rDetails = New-Object psobject -Property @{
        CredVal = $CredVal
        SecGroupMgmt = $SecGroupMgmt
    }
    $highLevel = $null
    If ($CredVal-and $SecGroupMgmt){
        $highLevel = $true
    }
    else {
        $highLevel = $false
    }
    return New-Object psobject -Property @{
        Details = $rDetails
        HighLevel = $highLevel
    }
}

function Get-AuditPolSettings()
{
    param(
        # Server FQDN
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $ServerName,

        [Parameter(Mandatory=$true)]
        [string]
        $ResultsFilePath
    )

    #Test Connection and exit if not available
    If((Test-Connection -ComputerName $Servername -Quiet) -eq $false){exit}

    #Invoke-WMI used to not be dependent on PoSH Remoting being enabled
    try{
        Invoke-WmiMethod -ComputerName $Servername -Class Win32_Process -Name Create -ArgumentList "auditpol /backup /file:c:\windows\$($Servername)-Auditpol.csv" | Out-Null
    }
    catch{
        Write-Error $_
        break
    }
    Start-Sleep -Seconds 10
    $AuditPolCSV = Import-Csv \\$Servername\C$\windows\$Servername-Auditpol.csv

    $AuditPolCSV | Export-Csv $ResultsFilePath -Encoding ASCII -NoTypeInformation
    Remove-Item \\$Servername\C$\windows\$Servername-Auditpol.csv
}

function Get-RemoteAdvancedAuditForcePolicy(){
    <#
    .SYNOPSIS
    Check to see if Advanced Audit Settings are Forced
    
    .EXAMPLE
    An example
    
    .NOTES
    Why this matters: 
    https://technet.microsoft.com/en-us/library/dd772710(v=ws.10).aspx
    #>
    param(
        # Server name
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]
        $ServerName
    )
    $HKLM = 2147483650 #HKLM
    $Key = "SYSTEM\CurrentControlSet\Control\Lsa"
    $Value = "scenoapplylegacyauditpolicy"

    
    try{
        $wmi = Get-WmiObject -list "StdRegProv" -Namespace root\default -ComputerName $ServerName
    }
    catch{
        Write-Error $_
        break 
    }
    $wmiResults = $wmi.GetDWORDValue($HKLM, $Key, $Value)
    $auditpolforce = $wmiResults.ReturnValue #1 means on (good), 0 means off (bad); default value is 1 (2008+)

    if ($auditpolforce -eq 0){ $auditpolforce = $false }
    if ($auditpolforce -eq 1){ $auditpolforce = $true }

    return $auditpolforce
}

function Get-RemoteAtaServiceStatus(){
    <#
    .SYNOPSIS
    Checks to see if the computer has the ATA Lieghtweight Gateway (LWGW) installed
    If it does, event forwarding is already complete.  If not, this needs to be manually done via SIEM/WEC
    #>
    param(
        # Server name
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]
        $ServerName
    )
    $Lwgw = (Get-WmiObject Win32_Service -ComputerName $ServerName -Filter "name='ATAGateway'")
    If ($Lwgw){return $true}
    Else { return $false }
}