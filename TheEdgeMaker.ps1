<#
TheEdgeMaker allows us to automatically create Azure Edges for use in BloodHound.
See README.md for more information.

Author: @JulioUrena
License: GPL-3.0 license
#>

$global:location = "East US"

Try {
    # Check if NuGet provider is installed
    if (!(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        # Install NuGet provider if not installed
        Install-PackageProvider -Name NuGet -Force
    }

} Catch {
    Write-Error "[-] Error Installing NuGet. Clossing."
    break
}


Try {
    Import-Module -Name AzureAD -ErrorAction Stop -Verbose:$false | Out-Null
}
Catch {
    Write-Output "[+] Azure AD PowerShell Module not found..."
    Write-Output "[+]Installing Azure AD PowerShell Module..."
    Install-Module -Name AzureAD -Force -AllowClobber
}

Try {
    Import-Module -Name Az -ErrorAction Stop -Verbose:$false | Out-Null
}
Catch {
    Write-Output "[+] Az PowerShell Module not found..."
    Write-Output "[+] Installing Az PowerShell Module..."
    Install-Module -Name Az -Force -AllowClobber
}

Try {
    # Connect to Azure
    Connect-AzAccount
    
    $context = Get-AzContext
    $subscriptionId = $context.Subscription.Id
    $tenantId = $context.Tenant.Id
    $accountId = $context.Account.Id
}
Catch {
    Write-Output "[-] Cannot connect to Azure Tentant. Please check your credentials. Exiting!"
    Break
}

Try {
    Write-Verbose "Connecting to Azure AD..."
    Connect-AzureAD -TenantId $tenantId -AccountId $accountId -ErrorAction Stop | Out-Null
}
Catch {
    Write-Output "[-] Cannot connect to Azure AD. Please check your credentials. Exiting!"
    Break
}

# Set the subscription you want to use
Select-AzSubscription -SubscriptionId $subscriptionId

# Get Azure Tenant Details
$tenantDetails = Get-AzTenant -TenantId $tenantId

# Extract the primary domain from the Domains property
$primaryDomain = $tenantDetails.Domains | Select-Object -First 1

# Prompt the user if they want to change the default location
$response = Read-Host "The current location is '$($global:location)'. Do you want to change it? (Y/N)"

# If the user responds with 'Y' or 'y', prompt them for a new location
if ($response.ToLower() -eq 'y') {
    do {
        $newLocation = Read-Host "Enter a new location"
    } until ((Get-AzLocation -Name $newLocation -ErrorAction SilentlyContinue) -ne $null)

    # Update the global location variable with the new value
    $global:location = $newLocation
}

# Output the current location
Write-Host "`n## The current location is '$($global:location)'."

### Create Azure AD Users 
Function Create-AzureADUsers {
  param(
    [int]$NumberOfUsers = 10
  )

  # Common names list
  $names = @("Emily", "Madison", "Avery", "Sophia", "Olivia", "Abigail", "Isabella", "Mia", "Charlotte", "Ava")

  # Common lastnames list
  $lastnames = @("Smith", "Johnson", "Williams", "Jones", "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor")

  # Initialize a list to store the users and passwords
  $userList = @()

  # Loop through the number of users
  Try {
    for ($i = 0; $i -lt $NumberOfUsers; $i++) {

        $selectedName = $names[$i]
        $selectedLastName = $lastnames[$i]

        # Create the user display name
        $displayName = "$selectedName $selectedLastName"

        # Create the user MailNickName
        $MailNickName = "$selectedName.$selectedLastName"

        # Create the user principal name
        $userPrincipalName = "$selectedName.$selectedLastName@$primaryDomain"

        # Check if the user already exists
        if ((Get-AzureADUser -ObjectId $userPrincipalName -ErrorAction SilentlyContinue) -ne $null) {
            Write-Output "[*] AAD Account Already Exists - $displayName"
            continue
        }

        # Create a random password
        $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
        
        if ($selectedName -eq "Isabella") {
            $PasswordProfile.Password = "HacktheboxAcademy01!"
        } else {
            $PasswordProfile.Password = [System.Web.Security.Membership]::GeneratePassword(12, 2)
        }

        $PasswordProfile.ForceChangePasswordNextLogin = $false

        # Create the user in Azure AD
        $user = New-AzureADUser -AccountEnabled $true -DisplayName $displayName -MailNickName $MailNickName -UserPrincipalName $userPrincipalName -PasswordProfile $PasswordProfile      
        
        Write-OutPut "[+] AAD Account Created Successfully - $displayName"

        # Add the user and password to the user list
        $userList += New-Object PSObject -Property @{
            "UserPrincipalName" = $userPrincipalName
            "Password" = $PasswordProfile.Password
        }
        
    }
  }
  Catch {
    Write-Error "[-] Failed to create user: $names[$i]"
  }
  
  # Save the list of users and passwords to a file in the current directory
  try {
    $userList | Export-Csv -Path "user-list.csv" -NoTypeInformation -Force
  } catch {
    Write-Error "[-] Failed to write the file: $_"
  }
}

# Create-AzureADUsers -NumberOfUsers 5
Write-Output "`n## Creating Users"
Create-AzureADUsers

###### Create Resource Groups ######

Function Create-ResourceGroup {
    param(
    [string]$ResourceGroupName
    )
    Try {
        if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
            Write-Output "[*] The resource group '$resourceGroupName' already exists."
        } else {
            New-AzResourceGroup -Name $ResourceGroupName -Location $location
            Write-Output "[+] Resource group '$ResourceGroupName' created successfully in $location."
        }
    }
    Catch {
        Write-Error "[-] Failed to create resource group '$ResourceGroupName' in $location. Error: $_"
    }
}

## Assign Resource Group with Role

Function Assign-ResourceGroupRole {
    param (
        [string]$userPrincipalName,
        [string]$ResourceGroupName,
        [string]$RoleDefinitionName = "Reader"
    )
    # Reader Contributor Owner

    try {
        # Get the Azure Active Directory user
        $user = Get-AzureADUser -Filter "userPrincipalName eq '$userPrincipalName'"

        # Get the Azure role definition
        $role = Get-AzRoleDefinition -Name $RoleDefinitionName

        # Check if the role is already assigned to the user for the specified resource group
        if (Get-AzRoleAssignment -ObjectId $user.ObjectId -Scope "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName" -RoleDefinitionName $RoleDefinitionName -ErrorAction SilentlyContinue) {
            Write-Output "[*] Role '$RoleDefinitionName' is already assigned to $($user.DisplayName) for resource group '$ResourceGroupName'!"
        } else {
            # Assign the role to the user for the specified resource group
            New-AzRoleAssignment -ObjectId $user.ObjectId -RoleDefinitionId $role.Id -Scope "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName"

            Write-Output "[+] Added Role '$RoleDefinitionName' to $($user.DisplayName) for resource group '$ResourceGroupName' successfully!"
        }
    } catch {
        Write-Error "[-] Error while assigning role: $_"
    }
}

###### Create Azure KeyVault ######

# Function to create or update a Key Vault and set the HTBKeyVault secret
function Create-KeyVault {
  param(
    [string]$userPrincipalName,
    [string]$keyVaultName,
    [string]$secretValue,
    [string]$resourceGroupName
  )

  # Get the Azure Active Directory user
  $user = Get-AzureADUser -Filter "userPrincipalName eq '$userPrincipalName'"

  # Check if Key Vault exists
  $keyVault = Get-AzKeyVault -VaultName $keyVaultName
  if ($keyVault) {
    Write-Output "[*] Key Vault '$keyVaultName' already exists."
  } else {
    # Create the Key Vault
    $keyVault = New-AzKeyVault -VaultName $keyVaultName -Location $location -ResourceGroupName $resourceGroupName
    Write-Output "[+] Key Vault '$keyVaultName' created successfully."
  }
  
  # Check if secret exists in the Key Vault
  $secret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name "HTBKeyVault"
  if ($secret) {
    Write-Output "[*] Secret 'HTBKeyVault' already exists in '$keyVaultName'."
  } else {
    # Add a secret to the Key Vault
    $vaultSecret = ConvertTo-SecureString $secretValue -AsPlainText -Force
    Set-AzKeyVaultSecret -VaultName $keyVaultName -Name "HTBKeyVault" -SecretValue $vaultSecret
    Write-Output "[+] Secret 'HTBKeyVault' added to '$keyVaultName' successfully."
  }

    Set-AzKeyVaultAccessPolicy -VaultName $keyVaultName -ObjectId $user.ObjectId -PermissionsToKeys all -PermissionsToSecrets all -PermissionsToCertificates all -PermissionsToStorage all
    Write-Output "[+] Access policy for $($user.DisplayName) has been set successfully."
}

# Create Resource Group 
Write-Output "`n## Creating Resource Group"
Create-ResourceGroup -ResourceGroupName "RG-KeyVault"
Create-ResourceGroup -ResourceGroupName "Developers"

# Call the function to create the Key Vault and add the secret
Write-Output "`n## Creating Key Vault"
Create-KeyVault -keyVaultName "htb-secret" -secretValue "ImHack1nGTooM4ch!" -resourceGroupName "RG-KeyVault" -userPrincipalName Ava.Taylor@$primaryDomain

Write-Output "`n## Assigning Resource Group Role"
Assign-ResourceGroupRole -userPrincipalName Ava.Taylor@$primaryDomain -ResourceGroupName "RG-KeyVault" -RoleDefinitionName Contributor
Assign-ResourceGroupRole -userPrincipalName Ava.Taylor@$primaryDomain -ResourceGroupName Developers -RoleDefinitionName Contributor

$groupnames = @("HR Group", "IT Support", "SysAdmins", "VPN Admin", "Infrastructure", "Managers", "Database", "Site Admins", "Subscription Reader")

## Create Groups
function Create-AzureADGroups {
  param(
    [string[]]$groupNames
  )
  
  foreach ($groupName in $groupNames) {
    # Check if group already exists
    $findGroup = Get-AzureADMSGroup -Filter "displayName eq '$groupName'"
    if (!$findGroup) {
      try {
        # Create the group if it doesn't exist
        $group = New-AzureADMSGroup -DisplayName $groupName -MailEnabled $False -SecurityEnabled $True -MailNickName $groupName.Replace(" ", "") 
        Write-Output "[+] Group $groupName created successfully!"
      } catch {
        Write-Error "[-] Error creating group '$groupName': $_"
      }
    } else {
      Write-Output "[*] Group $groupName already exists."
    }
  }
}

Write-Output "`n## Creating Groups"
Create-AzureADGroups -groupNames $groupnames

function Add-MemberToGroup {
    param(
        [string]$userPrincipalName,
        [string]$groupName
    )

    # Get the Azure AD user
    $user = Get-AzureADUser -Filter "userPrincipalName eq '$userPrincipalName'"
    if (!$user) {
        Write-Error "[-] User '$userPrincipalName' not found in Azure AD"
        return
    }

    # Get the Azure AD group
    $group = Get-AzureADGroup -Filter "displayName eq '$groupName'"
    if (!$group) {
        Write-Error "[-] Group '$groupName' not found in Azure AD"
        return
    }

    # Check if the user is already a member of the group
    $isMember = Get-AzureADGroupMember -ObjectId $group.ObjectId | Where-Object {$_.ObjectType -eq "User"} | Where-Object {$_.UserPrincipalName -eq $user.UserPrincipalName}
    if ($isMember) {
        Write-Output "[*] User '$userPrincipalName' is already a member of group '$groupName'"
        return
    }

    # Add the user to the group
    Add-AzureADGroupMember -ObjectId $group.ObjectId -RefObjectId $user.ObjectId

    Write-Output "[+] User '$userPrincipalName' added to group '$groupName'"
}

Write-Output "`n## Adding Members to Groups"
Add-MemberToGroup -userPrincipalName Abigail.Davis@$primaryDomain -groupName "HR Group"
Add-MemberToGroup -userPrincipalName Charlotte.Moore@$primaryDomain -groupName "SysAdmins"

function Make-GroupOwner {
    param(
        [string]$userPrincipalName,
        [string]$groupName
    )

    Try {
        $group = Get-AzureADMSGroup -Filter "displayName eq '$groupName'"
        $user = Get-AzureADUser -Filter "userPrincipalName eq '$userPrincipalName'"

        # Check if user is already an owner of the group
        $owners = Get-AzureADGroupOwner -ObjectId $group.Id
        $isOwner = $owners.ObjectId -contains $user.ObjectId
        if ($isOwner) {
            Write-Output "[+] User $($user.DisplayName) is already an owner of group $groupName"
            return
        }

        # Add the user as an owner to the group
        Add-AzureADGroupOwner -ObjectId $group.Id -RefObjectId $user.ObjectId
        Write-OutPut "[+] Added user $($user.DisplayName) as owner to group $groupName"
    }
    Catch {
        Write-Error "[-] Error adding user as Group Owner: $_"
    }
}

Write-Output "`n## Making Users Group's Owner"
Make-GroupOwner -userPrincipalName Abigail.Davis@$primaryDomain -groupName "HR Group"
Make-GroupOwner -userPrincipalName Charlotte.Moore@$primaryDomain -groupName "Subscription Reader"

### Add reader rights over the subscription to Subscription Reader
$readerGroup = Get-AzureADGroup -SearchString "Subscription Reader"
$readerRole = Get-AzRoleAssignment -ObjectId $readerGroup.ObjectId -Scope "/subscriptions/$subscriptionId"

# Check if the role assignment exists
if ($readerRole) {
    Write-Output "[*] The role assignment for '$($readerGroup.DisplayName)' already exists."
} else {
    # Assign the Reader role to the Subscription Reader group
    New-AzRoleAssignment -ObjectId $readerGroup.ObjectId -RoleDefinitionName "Reader" -Scope "/subscriptions/$subscriptionId"
    Write-Output "[+] The role assignment for '$($readerGroup.DisplayName)' was added successfully."
}

function Create-AzureVM {
    param (
        [string]$vmName,
        [string]$resourceGroupName,
        [string]$adminUsername,
        [string]$adminPassword
    )

    $vm = Get-AzVM -ResourceGroupName $resourceGroupName -Name $vmName -ErrorAction SilentlyContinue

    if ($vm) {
        Write-Output "[*] VM '$vmName' already exists."
        return
    }

    $vmSizes = Get-AzVMSize -Location $location
    $selectedVMSize = $vmSizes | Where-Object {$_.Name -eq "Standard_B1s"}
    if ($selectedVMSize -eq $null) {
        $selectedVMSize = $vmSizes | Where-Object {$_.Name -eq "Standard_B2s"}
    }
    $selectedSize = $selectedVMSize.Name

    New-AzVm `
    -ResourceGroupName $resourceGroupName `
    -Name $vmName `
    -Size $selectedSize `
    -Location $location `
    -VirtualNetworkName 'myVnet' `
    -SubnetName 'mySubnet' `
    -SecurityGroupName 'myNetworkSecurityGroup' `
    -PublicIpAddressName 'myPublicIpAddress' `
    -OpenPorts 80,3389 `
    -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList $adminUsername, $(ConvertTo-SecureString -String $adminPassword -AsPlainText -Force))

    Write-Output "[+] VM '$vmName' created successfully!"
}

Write-Output "`n## Creating Azure VMs"
Create-AzureVM -vmName "AzVM-01" -resourceGroupName Production -adminUsername webadmin -adminPassword "SuperPassword123!"

Function Add-AzureADUserToRole {
    param (
        [string]$userPrincipalName,
        [string]$servicePrincipalName,
        [string]$roleName
    )
    Try {
        if (![string]::IsNullOrEmpty($userPrincipalName)) {
            # Get the user object
            $node = Get-AzureADUser -ObjectId $userPrincipalName
        } elseif (![string]::IsNullOrEmpty($servicePrincipalName)) {
            # Get the user object
            $node = Get-AzureADServicePrincipal -SearchString $servicePrincipalName
        }

        if ([string]::IsNullOrEmpty($node)) {
            Write-Output "[-] No Object Found. Aborting..."
            break
        }

        $allRoles = Get-AzureADDirectoryRole

        $role = $allRoles | Where-Object { $_.DisplayName -eq $roleName }

        if (!$role) {
            # Get the privileged role definition
            $roletemplate = Get-AzureADDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $roleName }

            # Enable Role
            Enable-AzureADDirectoryRole -RoleTemplateId $roletemplate.ObjectId
            
            # Get the privilege role
            $role = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq $roleName }
        }

        # Check if the user already has the role
        $roleMember = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId | Where-Object { $_.ObjectId -eq $node.ObjectId }

        if ($roleMember) {
            Write-Output "[*] The role '$roleName' is already assigned to $($node.DisplayName). Skipping..."
        }
        else {
            # Assign the role to the user
            Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $node.ObjectId

            Write-Output "[+] Added Role '$roleName' to $($node.DisplayName) successfully!"
        }
    }  
    catch {
        Write-Error "[-] Error while assigning role: $_"
    }
}

# This Role is like GA
# Add-AzureADUserToRole -userPrincipalName Charlotte.Moore@$primaryDomain -roleName "Privileged Role Administrator"

Write-Output "`n## Add Role to Users"
Add-AzureADUserToRole -userPrincipalName Emily.Smith@$primaryDomain -roleName "User Administrator"
Add-AzureADUserToRole -userPrincipalName Isabella.Miller@$primaryDomain -roleName "Password Administrator"

function Create-ServicePrincipalWithOwner {
    param (
        [Parameter(Mandatory=$true)][string]$servicePrincipalName,
        [Parameter(Mandatory=$true)][string]$userPrincipalName
    )

    # Check if the Service Principal already exists
    $sp = Get-AzADServicePrincipal -DisplayName $servicePrincipalName -ErrorAction SilentlyContinue
    if ($sp) {
        Write-Output "[*] Service Principal '$servicePrincipalName' already exists!"
    }
    else {
        # Create the Service Principal
        $sp = New-AzADServicePrincipal -DisplayName $servicePrincipalName
        Write-Output "[+] Service Principal '$servicePrincipalName' created successfully!"
    }

    # Check if the User is already Owner of the Service Principal
    $owner = Get-AzureADServicePrincipalOwner -ObjectId $sp.Id -All $true | Where-Object { $_.UserPrincipalName -eq $userPrincipalName }
    if ($owner) {
        Write-Output "[*] User '$userPrincipalName' is already Owner of Service Principal '$servicePrincipalName'!"
    }
    else {
        # Get the User Object
        $user = Get-AzureADUser -Filter "userPrincipalName eq '$userPrincipalName'"

        # Assign the User as Owner of the Service Principal
        Add-AzureADServicePrincipalOwner -ObjectId $sp.Id -RefObjectId $user.ObjectId

        Write-Output "[+] User '$userPrincipalName' added as Owner of Service Principal '$servicePrincipalName' successfully!"
    }
}

Write-Output "`n## Creating Service Principals"
Create-ServicePrincipalWithOwner -servicePrincipalName "Web2.0" -userPrincipalName "Mia.Wilson@$primaryDomain" 

Add-AzureADUserToRole -servicePrincipalName "Web2.0" -roleName "Application Administrator"
# Add-AzureADUserToRole -servicePrincipalName "Web2.0" -roleName "Privileged Role Administrator"

Function Add-AzRoleToVM {
    param (
        [string]$userPrincipalName,
        [string]$servicePrincipalName,
        [string]$vmResourceGroup,
        [string]$roleName,
        [string]$vmName
    )

    Try {
        if (![string]::IsNullOrEmpty($userPrincipalName)) {
            # Get the user object
            $node = Get-AzureADUser -ObjectId $userPrincipalName
        } elseif (![string]::IsNullOrEmpty($servicePrincipalName)) {
            # Get the user object
            $node = Get-AzureADServicePrincipal -SearchString $servicePrincipalName
        }

        if ([string]::IsNullOrEmpty($node)) {
            Write-Output "[-] No Object Found. Aborting..."
            break
        }

        # Get the virtual machine resource 
        $vm = Get-AzVM -Name $vmName
        $vmResourceId = $vm.Id

        # Set the owner role for the user on the virtual machine
        $currentRole = Get-AzRoleAssignment -ObjectId $node.ObjectId -RoleDefinitionName $roleName -Scope "/subscriptions/$subscriptionId/resourceGroups/$vmResourceGroup/providers/Microsoft.Compute/virtualMachines/$vmName"

        if ($currentRole) {
            Write-Output "[*] The role assignment for '$($readerGroup.DisplayName)' already exists."
        } else {
            # Assign the role to the AzVM
            New-AzRoleAssignment -ObjectId $node.ObjectId -RoleDefinitionName $roleName -Scope "/subscriptions/$subscriptionId/resourceGroups/$vmResourceGroup/providers/Microsoft.Compute/virtualMachines/$vmName"
            Write-Output "[+] Added Role '$roleName' to $($node.DisplayName) for VM '$vmName' successfully!"
        }
    }  
    Catch {
        Write-Error "[-] Error while assigning role: $_"
    }
}

Write-Output "`n## Adding Role to User for Azure VMs"
Add-AzRoleToVM -userPrincipalName "Madison.Johnson@$primaryDomain" -roleName Owner -vmResourceGroup Production -vmName "AzVM-01"
