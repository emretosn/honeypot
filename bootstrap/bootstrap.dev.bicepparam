using 'main.bicep'

// Existing Terraform state storage account (hardened in place).
param storageAccountName = 'sthpdevweutfstate'

// Your current public IP, allowed to SSH the jump VM. Get it with: curl -s https://api.ipify.org
param adminSourceIp = 'REPLACE_WITH_YOUR_IP'

// SSH public key for the jump VM (e.g. contents of ~/.ssh/id_rsa.pub).
param jumpVmSshPublicKey = 'ssh-rsa REPLACE'
