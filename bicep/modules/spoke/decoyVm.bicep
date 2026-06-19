metadata description = 'Decoy Linux VM for the honeypot spoke. Slightly-inviting SSH surface (reachable via the spoke NSG, no public IP — reached through the spoke). cloud-init plants fake-prod breadcrumbs so an attacker who lands on it finds an enticing but dead-end path. Boot diagnostics and the AMA-ready identity allow log collection.'

@description('VM name (decoy-plane: production-like, no honeypot marker).')
param name string

@description('Deployment location.')
param location string

@description('Subnet resource ID the NIC attaches to.')
param subnetId string

@description('Admin username (production-sounding).')
param adminUsername string = 'sysadmin'

@description('SSH public key for admin access.')
@secure()
param adminSshPublicKey string

@description('VM size. B-series keeps the decoy cheap; accepted realism tradeoff.')
param vmSize string = 'Standard_B1s'

@description('Base64 cloud-init that plants fake-prod breadcrumbs. Caller supplies content.')
param customDataBase64 string = ''

@description('Resource tags.')
param tags object = {}

resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: '${name}-nic'
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: subnetId
          }
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: name
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: name
      adminUsername: adminUsername
      customData: empty(customDataBase64) ? null : customDataBase64
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: adminSshPublicKey
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
          id: nic.id
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
    }
  }
}

output id string = vm.id
output name string = vm.name
output principalId string = vm.identity.principalId
output privateIp string = nic.properties.ipConfigurations[0].properties.privateIPAddress
