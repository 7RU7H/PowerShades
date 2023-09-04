param (
    [string]$outputFile = "",
    [string]$domain = ""
)

if ($domain -eq ""){
   Write-Host "Please provide a Domain name -domain <domain>"
   exit
}

if ($outputFile -ne "") {
    $outputFile | Out-File -Force
} else {
    Write-Host "Please provide a  output file -outputFile <file>"
    exit

}

# Get the current execution policy
$executionPolicy = Get-ExecutionPolicy

if ($executionPolicy -eq "Bypass") {
    Write-Host "PowerShell execution policy is set to 'Bypass'."
} else {
    Write-Host "PowerShell execution policy is set to '$executionPolicy'."
    Write-Host "Exiting due to requirement of 'Bypass'"
    exit
}

# Check if the PowerView module is imported
$module = Get-Module -Name PowerView

if ($module) {
    Write-Host "PowerView module is imported."
} else {
    Write-Host "PowerView is not imported."
    Write-Host "Exiting due to requirement of PowerView.."
    exit
}

#"Get-IniContent",
#"Get-PrincipalContext",
#"Get-DomainSPNTicket",
#"Get-PathAcl",
#"Get-DomainDNSRecord",
#"Get-GptTmpl",

# Are implemented implemented

#"Get-DomainGroupMember",
#"Get-DomainGroupMemberDeleted",

#"Find-DomainObjectPropertyOutlier",


$PowerViewFunctionList = @(
        "Get-DomainSearcher",
        "Get-DomainDNSZone $domain",
        "Get-Domain $domain",
        "Get-DomainController",
        "Get-Forest",
        "Get-ForestDomain",
        "Get-ForestGlobalCatalog",
        "Get-ForestSchemaClass",
        "Get-DomainUser",
        "Get-DomainUserEvent",
        "Get-DomainGUIDMap",
        "Get-DomainComputer",
        "Get-DomainObject",
        "Get-DomainObjectAttributeHistory",
        "Get-DomainObjectLinkedAttributeHistory",
        "Get-DomainObjectAcl",
        "Find-InterestingDomainAcl",
        "Get-DomainOU",
        "Get-DomainSite",
        "Get-DomainSubnet",
        "Get-DomainSID",
        "Get-DomainGroup",
        "Get-DomainManagedSecurityGroup",
        "Get-DomainFileServer",
        "Get-DomainDFSShare",
        "Get-GroupsXML",
        "Get-DomainGPO",
        "Get-DomainGPOLocalGroup",
        "Get-DomainGPOUserLocalGroupMapping",
        "Get-DomainGPOComputerLocalGroupMapping",
        "Get-DomainPolicyData",
        "Get-NetLocalGroup",
        "Get-NetLocalGroupMember",
        "Get-NetShare",
        "Get-NetLoggedon",
        "Get-NetSession",
        "Get-RegLoggedOn",
        "Get-NetRDPSession",
        "Get-NetComputerSiteName",
        "Get-WMIRegProxy",
        "Get-WMIRegLastLoggedOn",
        "Get-WMIRegCachedRDPConnection",
        "Get-WMIRegMountedDrive",
        "Get-WMIProcess",1
        "Find-InterestingFile",
        "Find-DomainUserLocation",
        "Find-DomainProcess",
        "Find-DomainUserEvent",
        "Find-DomainShare",
        "Find-InterestingDomainShareFile",
        "Find-LocalAdminAccess",
        "Find-DomainLocalGroupMember",
        "Get-DomainTrust",
        "Get-ForestTrust",
        "Get-DomainForeignUser",
        "Get-DomainForeignGroupMember",
        "Get-DomainTrustMapping",
        "Get-GPODelegation"
)



$colors = @('Red', 'Yellow', 'Green', 'Cyan', 'Blue', 'Magenta')

# Define your ASCII art here
$asciiArt = @"
     _         _         _         _         _         _         _         _         _         _         _
   _( )__    _( )__    _( )__    _( )__    _( )__    _( )__    _( )__    _( )__    _( )__    _( )__    _( )__
 _|     _| _|     _| _|     _| _|     _| _|     _| _|     _| _|     _| _|     _| _|     _| _|     _| _|     _|
(_ P _ (_ (_ O _ (_ (_ W _ (_ (_ E _ (_ (_ R _ (_ (_ S _ (_ (_ H _ (_ (_ A _ (_ (_ D _ (_ (_ E _ (_ (_ S _ (_
  |_( )__|  |_( )__|  |_( )__|  |_( )__|  |_( )__|  |_( )__|  |_( )__|  |_( )__|  |_( )__|  |_( )__|  |_( )__|

==============================================================================================================

A wrapping the shadowing PowerSploit's PowerView in more lesser PowerShell like two sets of sunglasses...
"@

$colorIndex = 0

# Split the ASCII art into lines
$asciiLines = $asciiArt -split "`r`n"

foreach ($line in $asciiLines) {
    foreach ($char in $line.ToCharArray()) {
        $currentColor = $colors[$colorIndex]
        Write-Host $char -ForegroundColor $currentColor -NoNewline
        $colorIndex = ($colorIndex + 1) % $colors.Count
    }
    Write-Host ""
}



foreach ($functionName in $PowerViewFunctionList) {
    # Check if the specified function exists
    if (Test-Path function:\$functionName) {
        # Execute the function
        $output = Invoke-Expression "& $functionName"

        # Output to the console
        Write-Host "Executing $functionName"
        Write-Host $output

        if ($outputFile -ne "") {
            # Append the output to the specified file
            $output | Out-File -Append -FilePath $outputFile
        }

    } else {
        Write-Host "Function $functionName not found in module $moduleName."
    }

}

# Find all the domain objects that are outliners
# Use Get-DomainObject to retrieve all Active Directory objects in the domain
# Loop through the objects and find outliers for the domain property, then find outlines$adObjects = Get-DomainObject -SearchBase $domain
$adzoneOutliers = @()

foreach ($adObject in $adObjects) {
    $objectOutliers = Find-DomainObjectPropertyOutlier -InputObject $adObject -Property domain
    if ($objectOutliers) {
        $adzoneOutliers += $objectOutliers
    }
}

foreach ($outlier in $adzoneOutliers) {
    # Access properties of each outlier object
    $domainValue = $outlier.domain
    Write-Host "Outlier Domain: $domainValue"
    $domainValue | Out-File -Append -FilePath $outputFile
}

$excludedDefaultGroups = @(
    "Domain Users",
    "Domain Guests",
    "Domain Computers",
    "Domain Controllers",
    "Cert Publishers",
    "Backup Operators",
    "Account Operators",
    "Server Operators",
    "Print Operators",
    "Replicator",
    "Remote Desktop Users",
    "DnsUpdateProxy"
)

$customGroups = @()
$highPrivilegeGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators"
)


$permissionList = @("GenericAll", "GenericAll", "WriteOwner", "WriteDADL", "AllExtendedRights", "ForceChangePassword", "Self")
$groups = Get-DomainGroup
foreach ($group in $groups) {
        if ($excludedDefaultGroups -notcontains $group) {
        $customGroups += $group
	for ($permission in $permissionList) { 
	$groupAcl = Get-ObjectAcl -Identity "$group" | ? {$_.ActiveDirectoryRights -eq "$permission"} | select SecurityIdentifier,ActiveDirectoryRights
	Write-Host $groupAcl
	$groupAcl | Out-File -Append -FilePath $outputFile 
} 

# Loop through the groups
# Use Find-DomainObjectPropertyOutlier to analyze the property of the group member (deleted and active)
foreach ($group in $groups) {
    # Check if the group is a Microsoft default group
    if ($excludedDefaultGroups -contains $group.name) {
        continue  # Skip excluded default groups
    }

    # Get members of the group (including deleted members)
    $groupMembers = Get-DomainGroupMember -Identity $group.name -Recurse
    $deletedMembers = Get-DomainGroupMemberDeleted -Identity $group.name -Recurse

    Write-Host "Group Name: $($group.name)"
    Write-Host "Members:"
    foreach ($member in $groupMembers) {
        Write-Host "  $member"
          $member | Out-File -Append -FilePath $outputFile
          $groupMemberDN = $member.DistinguishedName
        Write-Host "DN of Group Member: $groupMemberDN"
          $memberProperties = $member | Get-Member -MemberType Properties
         foreach ($property in $memberProperties) {
                $propertyToAnalyze = $property
                $propertyOutliers = Find-DomainObjectPropertyOutlier -SearchBase $groupMemberDN -Property $propertyToAnalyze
                Write-Host $propertyOutliers
                $propertyOutliers |  Out-File -Append -FilePath $outputFile
                }


    }
    Write-Host "Deleted Members:"
    foreach ($deletedMember in $deletedMembers) {
        Write-Host "  $deletedMember"
         $deletedMember | Out-File -Append -FilePath $outputFile
           $groupMemberDN = $deletedMember.DistinguishedName
        Write-Host "DN of Group Member: $groupMemberDN"
          $memberProperties = $deletedMember | Get-Member -MemberType Properties
         foreach ($property in $memberProperties) {
                $propertyToAnalyze = $property
                $propertyOutliers = Find-DomainObjectPropertyOutlier -SearchBase $groupMemberDN -Property $propertyToAnalyze
                Write-Host $propertyOutliers
                $propertyOutliers |  Out-File -Append -FilePath $outputFile
                }
    }
}

}

if ($outputFile -ne "") {
    Write-Host "Output has been written to $outputFile"
}
exit
