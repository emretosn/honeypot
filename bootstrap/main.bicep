metadata description = 'Bootstrap for the Terraform remote-state backend, policy-compliant (no public access). Hardens the tfstate storage account (versioning, soft delete, Entra-only auth), reaches it over a Private Endpoint with Private DNS, and provides a network-joined jump VM from which Terraform is run. Deploy scoped to the tfstate resource group. Does not touch the foundation or identity resources.'

targetScope = 'resourceGroup'

@description('Location for all bootstrap resources.')
param location string = resourceGroup().location

@description('Existing Terraform state storage account name (hardened in place).')
param storageAccountName string

@description('State container name.')
param containerName string = 'tfstate'

@description('Management VNet address space.')
param vnetAddressPrefix string = '10.250.0.0/24'

@description('Your current public IP, allowed to SSH the jump VM (e.g. 203.0.113.5). Required.')
param adminSourceIp string

@description('SSH public key for the jump VM admin user.')
@secure()
param jumpVmSshPublicKey string

@description('Jump VM admin username.')
param jumpVmAdminUsername string = 'tfadmin'

@description('Jump VM size.')
param jumpVmSize string = 'Standard_B1s'

@description('Resource tags (internal plane — marker allowed).')
param tags object = {
  project: 'honeypot'
  plane: 'internal-mgmt'
  component: 'tf-backend'
  managedBy: 'iac'
}

var peSubnetPrefix = cidrSubnet(vnetAddressPrefix, 26, 0)
var jumpSubnetPrefix = cidrSubnet(vnetAddressPrefix, 26, 1)
var blobDnsZoneName = 'privatelink.blob.${environment().suffixes.storage}'

// --- Hardened state storage account (updates the existing account in place) -----------------
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
    }
  }
}

resource blobServices 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    isVersioningEnabled: true
    deleteRetentionPolicy: {
      enabled: true
      days: 30
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 30
    }
  }
}

resource stateContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobServices
  name: containerName
  properties: {
    publicAccess: 'None'
  }
}

// --- Management network ----------------------------------------------------------------------
resource jumpNsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: 'nsg-tfbackend-jump'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'Allow-Admin-SSH-Inbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: adminSourceIp
          sourcePortRange: '*'
          destinationAddressPrefix: jumpSubnetPrefix
          destinationPortRange: '22'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: 'vnet-tfbackend'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [vnetAddressPrefix]
    }
    subnets: [
      {
        name: 'pe-subnet'
        properties: {
          addressPrefix: peSubnetPrefix
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
      {
        name: 'jump-subnet'
        properties: {
          addressPrefix: jumpSubnetPrefix
          networkSecurityGroup: {
            id: jumpNsg.id
          }
        }
      }
    ]
  }
}

// --- Private DNS + Private Endpoint to the storage blob service ------------------------------
resource blobDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: blobDnsZoneName
  location: 'global'
  tags: tags
}

resource blobDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: blobDnsZone
  name: 'link-vnet-tfbackend'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource blobPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: 'pe-tfstate-blob'
  location: location
  tags: tags
  properties: {
    subnet: {
      id: '${vnet.id}/subnets/pe-subnet'
    }
    privateLinkServiceConnections: [
      {
        name: 'pe-tfstate-blob'
        properties: {
          privateLinkServiceId: storage.id
          groupIds: ['blob']
        }
      }
    ]
  }
}

resource blobPeDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = {
  parent: blobPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'blob'
        properties: {
          privateDnsZoneId: blobDnsZone.id
        }
      }
    ]
  }
}

// --- Jump VM (Terraform execution host inside the allowed network) --------------------------
resource jumpPip 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: 'pip-tfbackend-jump'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource jumpNic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: 'nic-tfbackend-jump'
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: '${vnet.id}/subnets/jump-subnet'
          }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: jumpPip.id
          }
        }
      }
    ]
  }
}

var jumpCloudInit = base64('''
#cloud-config
package_update: true
runcmd:
  - curl -sL https://aka.ms/InstallAzureCLIDeb | bash
  - apt-get install -y gnupg software-properties-common
  - curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
  - echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list
  - apt-get update && apt-get install -y terraform
''')

resource jumpVm 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: 'vm-tfbackend-jump'
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: jumpVmSize
    }
    osProfile: {
      computerName: 'tfjump'
      adminUsername: jumpVmAdminUsername
      customData: jumpCloudInit
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${jumpVmAdminUsername}/.ssh/authorized_keys'
              keyData: jumpVmSshPublicKey
            }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-jammy'
        sku: '22_04-lts-gen2'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Standard_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: jumpNic.id
        }
      ]
    }
  }
}

@description('Public IP to SSH the jump VM.')
output jumpVmPublicIp string = jumpPip.properties.ipAddress

@description('Jump VM managed identity — grant it Storage Blob Data Contributor on the state account.')
output jumpVmPrincipalId string = jumpVm.identity.principalId

@description('Admin username for the jump VM.')
output jumpVmAdminUsername string = jumpVmAdminUsername
