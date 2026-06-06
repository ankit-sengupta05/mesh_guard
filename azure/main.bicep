@description('The location for all resources.')
param location string = resourceGroup().location

@description('The name of the environment. Used as a prefix for all resources.')
param environmentName string = 'agentops-mesh'

@description('SKU for the Redis Cache')
param redisSkuName string = 'Standard'

@description('Family for the Redis Cache')
param redisSkuFamily string = 'C'

@description('Capacity for the Redis Cache')
param redisSkuCapacity int = 1

var logAnalyticsWorkspaceName = '${environmentName}-logs'
var containerRegistryName = replace('${environmentName}acr', '-', '')
var keyVaultName = '${environmentName}-kv'
var redisCacheName = '${environmentName}-redis'

// Log Analytics Workspace
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: logAnalyticsWorkspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

// Container Registry
resource containerRegistry 'Microsoft.ContainerRegistry/registries@2022-12-01' = {
  name: containerRegistryName
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: true
  }
}

// Azure Cache for Redis
resource redisCache 'Microsoft.Cache/redis@2023-04-01' = {
  name: redisCacheName
  location: location
  properties: {
    sku: {
      name: redisSkuName
      family: redisSkuFamily
      capacity: redisSkuCapacity
    }
    enableNonSslPort: false
    minimumTlsVersion: '1.2'
  }
}

// Key Vault
resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    accessPolicies: []
    enableRbacAuthorization: true
  }
}

// Store Redis Connection String in Key Vault
resource redisConnectionStringSecret 'Microsoft.KeyVault/vaults/secrets@2023-02-01' = {
  parent: keyVault
  name: 'RedisConnectionString'
  properties: {
    value: '${redisCache.properties.hostName}:${redisCache.properties.sslPort},password=${redisCache.listKeys().primaryKey},ssl=True,abortConnect=False'
  }
}

// Container Apps Environment & Apps (Delegated to nested module)
module containerApps 'container-apps.bicep' = {
  name: 'containerAppsDeployment'
  params: {
    location: location
    environmentName: environmentName
    logAnalyticsWorkspaceId: logAnalytics.id
    registryName: containerRegistry.name
    registryLoginServer: containerRegistry.properties.loginServer
    registryUsername: containerRegistry.name
    registryPassword: containerRegistry.listCredentials().passwords[0].value
    keyVaultUri: keyVault.properties.vaultUri
    redisHost: redisCache.properties.hostName
    redisPassword: redisCache.listKeys().primaryKey
  }
}

// Outputs
output backendUrl string = containerApps.outputs.backendUrl
output frontendUrl string = containerApps.outputs.frontendUrl
output websocketUrl string = replace(containerApps.outputs.backendUrl, 'https://', 'wss://')
output registryLoginServer string = containerRegistry.properties.loginServer
