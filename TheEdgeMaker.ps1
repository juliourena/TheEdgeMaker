<#
TheEdgeMaker allows us to automatically create Azure Edges for use in BloodHound.
See README.md for more information.

Author: @JulioUrena
License: GPL-3.0 license
#>

$global:location = "East US"

Try {
    Import-Module -Name AzureAD -ErrorAction Stop -Verbose:$false | Out-Null
}
Catch {
    Write-Verbose "Azure AD PowerShell Module not found..."
    Write-Verbose "Installing Azure AD PowerShell Module..."
    Install-Module -Name AzureAD -Force -AllowClobber -Force
}

Try {
    Import-Module -Name Az -ErrorAction Stop -Verbose:$false | Out-Null
}
Catch {
    Write-Verbose "Az PowerShell Module not found..."
    Write-Verbose "Installing Az PowerShell Module..."
    Install-Module -Name Az -Force -AllowClobber -Force
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
    Write-Verbose "Cannot connect to Azure Tentant. Please check your credentials. Exiting!"
    Break
}

Try {
    Write-Verbose "Connecting to Azure AD..."
    Connect-AzureAD -TenantId $tenantId -AccountId $accountId -ErrorAction Stop | Out-Null
}
Catch {
    Write-Verbose "Cannot connect to Azure AD. Please check your credentials. Exiting!"
    Break
}

# Set the subscription you want to use
Select-AzSubscription -SubscriptionId $subscriptionId

# Get Azure Tenant Details
$tenantDetails = Get-AzTenant -TenantId $tenantId

# Extract the primary domain from the Domains property
$primaryDomain = $tenantDetails.Domains | Select-Object -First 1

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

        # Create a random password
        $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
        $PasswordProfile.Password = "HacktheboxAcademy01!"
        $PasswordProfile.ForceChangePasswordNextLogin = $false

        # Create the user in Azure AD
        $user = New-AzureADUser `
                -AccountEnabled $true `
                -DisplayName $displayName `
                -MailNickName $MailNickName`
                -UserPrincipalName $userPrincipalName `
                -PasswordProfile $PasswordProfile
        
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
    $userList | Export-Csv -Path "user-list.csv" -NoTypeInformation
  } catch {
    Write-Error "[-] Failed to write the file: $_"
  }
}

# Create-AzureADUsers -NumberOfUsers 5

Create-AzureADUsers

###### Create Resource Groups ######

Function Create-ResourceGroup {
    param(
    [string]$ResourceGroupName
    )
    Try {
        if (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue) {
            Write-Output "[-] The resource group '$resourceGroupName' already exists."
        } else {
            New-AzureRmResourceGroup -Name $ResourceGroupName -Location $location
            Write-Output "[+] Resource group '$ResourceGroupName' created successfully in $location."
        }
    }
    Catch {
        Write-Error "[-] Failed to create resource group '$ResourceGroupName' in $location. Error: $_"
    }
}

###### Create Azure KeyVault ######

# Function to create a Key Vault
function Create-KeyVault {
  param(
    [string]$keyVaultName,
    [string]$secretValue,
    [string]$resourceGroupName
  )

  # Check if Key Vault exists
  $keyVault = Get-AzKeyVault -VaultName $keyVaultName
  if (!$keyVault) {
    # Create the Key Vault
    $keyVault = New-AzKeyVault -VaultName $keyVaultName -Location $location -ResourceGroupName $resourceGroupName
  }
  
  $vaultSecret = ConvertTo-SecureString $secretValue -AsPlainText -Force

  # Add a secret to the Key Vault
  Set-AzKeyVaultSecret -VaultName $keyVaultName -Name "HTBKeyVault" -SecretValue $vaultSecret

  # Return the Key Vault object
  return $keyVault
}

# Create Resource Group 
Create-ResourceGroup -ResourceGroupName "RG-KeyVault"

# Call the function to create the Key Vault and add the secret
$keyVaultInfo = Create-KeyVault -keyVaultName "htb-secret" -secretValue "ImHack1nGTooM4ch!" -resourceGroupName "RG-KeyVault"
Write-Output "[+] KeyVault $($keyVaultInfo[0].VaultName) created successfully."

# Set Read Privileges to Ava.Taylor for the KeyVault
Set-AzKeyVaultAccessPolicy -UserPrincipalName Ava.Taylor@$primaryDomain -VaultName $keyVaultInfo[0].VaultName -PermissionsToKeys all -PermissionsToSecrets all -PermissionsToCertificates all -PermissionsToStorage all -PassThru

# Add user as reader Resource Group KeyVault
Assign-ResourceGroupRole -userPrincipalName Ava.Taylor@$primaryDomain -ResourceGroupName "RG-KeyVault" -RoleDefinitionName Contributor


## Create Groups

$groupnames = @("HR Group", "IT Support", "SysAdmins", "VPN Admin", "Infrastructure", "Managers", "Database", "Site Admins", "Subscription Reader")

function Create-AzureADGroups {
  param(
    [string[]]$groupNames
  )
  
    foreach ($groupName in $groupNames) {
        $findGroup = Get-AzureADMSGroup -Filter "displayName eq '$groupName'"
        if (!$findGroup) {
            Try {
                $group = New-AzureADMSGroup -DisplayName $groupName -MailEnabled $False -SecurityEnabled $True -MailNickName $groupName.Replace(" ", "") 
                Write-Output "[+] Group $groupName created successfully!"
            }
            Catch {
                Write-Error "[-] Error creating group $groupName $_"
            }
        }
    }
}

Create-AzureADGroups -groupNames $groupnames

Function Add-MemberToGroup {
    param(
    [string[]]$userPrincipalName,
    [string[]]$groupName
    )

    $user = Get-AzureADUser -Filter "userPrincipalName eq '$userPrincipalName'"

    # Get the group object for "HR Group"
    $group = Get-AzureADGroup -Filter "displayName eq '$groupName'"

    # Assign the role "Group Member Manager" to the user for the "HR Group" group
    Add-AzureADGroupMember -ObjectId $group.ObjectId -RefObjectId $user.ObjectId
    Write-Output "[+] Added user: $($user.DisplayName) to group: $groupName successfully!"
}

Add-MemberToGroup -userPrincipalName Abigail.Davis@$primaryDomain -groupName "HR Group"
Add-MemberToGroup -userPrincipalName Charlotte.Moore@$primaryDomain -groupName "SysAdmins"

Function Make-GroupOwner {
    param(
    [string[]]$userPrincipalName,
    [string[]]$groupName
    )
    Try {
        $group = Get-AzureADMSGroup -Filter "displayName eq '$groupName'"
        $user = Get-AzureADUser -Filter "userPrincipalName eq '$userPrincipalName'"

        # Add the user as an owner to the group
        Add-AzureADGroupOwner -ObjectId $group.Id -RefObjectId (Get-AzureADUser -Filter "userPrincipalName eq '$userPrincipalName'").ObjectId
        Write-OutPut "[+] Added user $($user.DisplayName) as owner to group $groupName"
    }
    Catch {
        Write-Error "[-] Error adding user as Group Owner $_"
    }
    
}

Make-GroupOwner -userPrincipalName Abigail.Davis@$primaryDomain -groupName "HR Group"
Make-GroupOwner -userPrincipalName Charlotte.Moore@$primaryDomain -groupName "Subscription Reader"

### Add reader rights over the subscription to Subscription Reader
New-AzRoleAssignment -ObjectId $(Get-AzureADGroup -SearchString "Subscription Reader").ObjectId -RoleDefinitionName "Reader" -Scope "/subscriptions/$subscriptionId"

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

        # Assign the role to the user for the specified resource group
        New-AzRoleAssignment -ObjectId $user.ObjectId -RoleDefinitionId $role.Id -Scope "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName"

        Write-Output "[+] Added Role '$RoleDefinitionName' to $($user.DisplayName) successfully!"
    } catch {
        Write-Error "[-] Error while assigning role: $_"
    }
}

Create-ResourceGroup -ResourceGroupName "Developers"
Assign-ResourceGroupRole -userPrincipalName Ava.Taylor@$primaryDomain -ResourceGroupName Developers -RoleDefinitionName Contributor

Function Create-AzureVM {
    param (
        [string]$vmName,
        [string]$vmSize = "Standard_B1s",
        [string]$resourceGroupName,
        [string]$adminUsername,
        [string]$adminPassword
    )

    New-AzVm `
    -ResourceGroupName $resourceGroupName `
    -Name $vmName `
    -Size $vmSize `
    -Location $location `
    -VirtualNetworkName 'myVnet' `
    -SubnetName 'mySubnet' `
    -SecurityGroupName 'myNetworkSecurityGroup' `
    -PublicIpAddressName 'myPublicIpAddress' `
    -OpenPorts 80,3389 `
    -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList $adminUsername, $(ConvertTo-SecureString -String $adminPassword -AsPlainText -Force))

    Write-Output "[+] VM '$vmName' Created successfully!"
}

$vmSizes = Get-AzVMSize -Location $location
$selectedVMSize = $vmSizes | Where-Object {$_.Name -eq "Standard_B1s"}
if ($selectedVMSize -eq $null) {
    $selectedVMSize = $vmSizes | Where-Object {$_.Name -eq "Standard_B2s"}
}
$selectedSize = $selectedVMSize.Name

Create-AzureVM -vmName "AzVM-01" -vmSize $selectedSize -resourceGroupName Production -adminUsername webadmin -adminPassword "SuperPassword123!"

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
            Write-Output "No Object Found. Aborting..."
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

        # Assign the role to the user
        Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $node.ObjectId

        Write-Output "[+] Added Role '$roleName' to $($node.DisplayName) successfully!"
    }  
    catch {
        Write-Error "[-] Error while assigning role: $_"
    }
}

# This Role is like GA
# Add-AzureADUserToRole -userPrincipalName Charlotte.Moore@$primaryDomain -roleName "Privileged Role Administrator"

Add-AzureADUserToRole -userPrincipalName Emily.Smith@$primaryDomain -roleName "User Administrator"

Add-AzureADUserToRole -userPrincipalName Isabella.Miller@$primaryDomain -roleName "Password Administrator"

function Create-ServicePrincipalWithOwner {
    param (
        [Parameter(Mandatory=$true)][string]$servicePrincipalName,
        [Parameter(Mandatory=$true)][string]$userPrincipalName
    )

    # Create the Service Principal
    $sp = New-AzADServicePrincipal -DisplayName $servicePrincipalName

    Write-Output "[+] Service Principal '$servicePrincipalName' Created successfully!"

    # Remove Default Privileges
    Remove-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName 'Contributor'

    # Add Reader Privileges (Needs ApplicationId instead of ObjectId)
    New-AzRoleAssignment -ApplicationId $sp.ApplicationId -RoleDefinitionName 'Reader'

    # Get the User Object
    $user = Get-AzureADUser -Filter "userPrincipalName eq '$userPrincipalName'"

    # Assign the User as Owner of the Service Principal
    Add-AzureADServicePrincipalOwner -ObjectId $sp.Id -RefObjectId $user.ObjectId

    Write-Output "[+] Added Owner $($user.DisplayName) to '$servicePrincipalName' successfully!"
}

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
            Write-Output "No Object Found. Aborting..."
            break
        }

        # Get the virtual machine resource 
        $vm = Get-AzVM -Name $vmName
        $vmResourceId = $vm.Id

        # Set the owner role for the user on the virtual machine
        New-AzRoleAssignment -ObjectId $node.ObjectId -RoleDefinitionName $roleName -Scope "/subscriptions/$subscriptionId/resourceGroups/$vmResourceGroup/providers/Microsoft.Compute/virtualMachines/$vmName"
        Write-Output "[+] Added Role '$roleName' to $($node.DisplayName) for VM '$vmName' successfully!"
    }  
    Catch {
        Write-Error "[-] Error while assigning role: $_"
    }
}

Add-AzRoleToVM -userPrincipalName "Madison.Johnson@$primaryDomain" -roleName Owner -vmResourceGroup Production -vmName "AzVM-01"
