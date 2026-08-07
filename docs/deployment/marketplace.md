# AEGISX PRO — AWS Marketplace Deployment

## One-Click Deploy (CloudFormation)

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: AEGISX PRO — Unified Security Operations Platform
Parameters:
  InstanceType:
    Type: String
    Default: t3.xlarge
    AllowedValues: [t3.large, t3.xlarge, t3.2xlarge, m5.xlarge, m5.2xlarge]
  KeyName:
    Type: AWS::EC2::KeyPair::KeyName
  AdminEmail:
    Type: String
  DBPassword:
    Type: String
    NoEcho: true
    MinLength: 16

Resources:
  AEGISXSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: AEGISX PRO security group
      SecurityGroupIngress:
        - IpProtocol: tcp; FromPort: 22;  ToPort: 22;   CidrIp: 0.0.0.0/0
        - IpProtocol: tcp; FromPort: 443; ToPort: 443;  CidrIp: 0.0.0.0/0
        - IpProtocol: tcp; FromPort: 8001;ToPort: 8001; CidrIp: 0.0.0.0/0

  AEGISXInstance:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: !Ref InstanceType
      KeyName: !Ref KeyName
      SecurityGroupIds: [!Ref AEGISXSecurityGroup]
      BlockDeviceMappings:
        - DeviceName: /dev/xvda
          Ebs: { VolumeSize: 100, VolumeType: gp3 }
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          yum update -y
          yum install -y docker
          systemctl start docker
          systemctl enable docker
          usermod -aG docker ec2-user

          curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
          chmod +x /usr/local/bin/docker-compose

          mkdir -p /opt/aegisx
          cd /opt/aegisx

          cat > .env <<EOF
          APP_ENV=production
          SECRET_KEY=$(openssl rand -hex 32)
          JWT_SECRET_KEY=$(openssl rand -hex 32)
          AGENT_REGISTRATION_KEY=$(openssl rand -hex 16)
          POSTGRES_PASSWORD=${DBPassword}
          OPENSEARCH_PASSWORD=$(openssl rand -hex 16)
          MINIO_ROOT_PASSWORD=$(openssl rand -hex 16)
          CLICKHOUSE_PASSWORD=$(openssl rand -hex 16)
          GRAFANA_ADMIN_PASSWORD=$(openssl rand -hex 12)
          AEGISX_ADMIN_EMAIL=${AdminEmail}
          AEGISX_ADMIN_PASSWORD=$(openssl rand -hex 12)
          EOF

          docker compose -f docker-compose.prod.yml up -d

Outputs:
  DashboardURL:
    Value: !Sub https://${AEGISXInstance.PublicDnsName}:8443
  APIDocs:
    Value: !Sub https://${AEGISXInstance.PublicDnsName}:8001/docs
```

## EKS Deployment

```bash
# 1. Create EKS cluster
eksctl create cluster --name aegisx-prod --region us-east-1 --nodes 3 --node-type m5.xlarge

# 2. Deploy with Helm
aws eks update-kubeconfig --region us-east-1 --name aegisx-prod
bash deploy/k8s-deploy.sh aegisx production

# 3. Expose via AWS Load Balancer
kubectl expose deployment aegisx-frontend --type=LoadBalancer --name=aegisx-lb -n aegisx

# 4. Get public URL
kubectl get svc aegisx-lb -n aegisx
```

## RDS Integration

```bash
# Use AWS RDS PostgreSQL instead of in-cluster TimescaleDB
helm install aegisx ./kubernetes/helm/aegisx \
  --set timescaledb.enabled=false \
  --set postgresql.enabled=false \
  --set config.timescaledbHost=your-rds-instance.region.rds.amazonaws.com
```

---

# AEGISX PRO — Azure Marketplace Deployment

## One-Click Deploy (ARM Template)

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "vmName": { "type": "string", "defaultValue": "aegisx-prod" },
    "adminUsername": { "type": "string" },
    "adminPassword": { "type": "securestring", "minLength": 12 },
    "vmSize": { "type": "string", "defaultValue": "Standard_D4s_v3" }
  },
  "resources": [
    {
      "type": "Microsoft.Compute/virtualMachines",
      "apiVersion": "2023-09-01",
      "name": "[parameters('vmName')]",
      "location": "[resourceGroup().location]",
      "properties": {
        "hardwareProfile": { "vmSize": "[parameters('vmSize')]" },
        "osProfile": {
          "computerName": "[parameters('vmName')]",
          "adminUsername": "[parameters('adminUsername')]",
          "adminPassword": "[parameters('adminPassword')]",
          "customData": "[base64(concat('#!/bin/bash\n','curl -fsSL https://get.docker.com | sh\n','docker compose -f /opt/aegisx/docker-compose.prod.yml up -d\n'))]"
        },
        "storageProfile": {
          "imageReference": {
            "publisher": "Canonical", "offer": "0001-com-ubuntu-server-jammy",
            "sku": "22_04-lts", "version": "latest"
          },
          "osDisk": { "createOption": "FromImage", "diskSizeGB": 100 }
        },
        "networkProfile": {
          "networkInterfaces": [{ "id": "[resourceId('Microsoft.Network/networkInterfaces', concat(parameters('vmName'), '-nic'))]" }]
        }
      }
    }
  ]
}
```

## AKS Deployment

```bash
# 1. Create AKS cluster
az aks create --resource-group aegisx-rg --name aegisx-aks \
  --node-count 3 --node-vm-size Standard_D4s_v3 --enable-addons monitoring

# 2. Deploy
az aks get-credentials --resource-group aegisx-rg --name aegisx-aks
bash deploy/k8s-deploy.sh aegisx production

# 3. Expose
kubectl expose deployment aegisx-frontend --type=LoadBalancer --name=aegisx-lb -n aegisx
```
