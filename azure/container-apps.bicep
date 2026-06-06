@description('Location for all resources.')
param location string

@description('Name of the Container Apps Environment')
param environmentName string

param logAnalyticsWorkspaceId string
param registryName string
param registryLoginServer string
param registryUsername string
@secure()
param registryPassword string
param keyVaultUri string

param redisHost string
@secure()
param redisPassword string

// Container Apps Environment
resource containerAppEnv 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: '${environmentName}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: reference(logAnalyticsWorkspaceId, '2022-10-01').customerId
        sharedKey: listKeys(logAnalyticsWorkspaceId, '2022-10-01').primarySharedKey
      }
    }
  }
}

// Neo4j Database App (Stateful)
resource neo4jApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: 'neo4j-trust-store'
  location: location
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: false
        targetPort: 7687
      }
    }
    template: {
      containers: [
        {
          name: 'neo4j'
          image: 'neo4j:5.9'
          env: [
            { name: 'NEO4J_AUTH', value: 'neo4j/agentops_secure_password' }
            { name: 'NEO4J_ACCEPT_LICENSE_AGREEMENT', value: 'yes' }
          ]
          resources: {
            cpu: json('1.0')
            memory: '2.0Gi'
          }
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}

// Backend App (FastAPI + WebSockets)
resource backendApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: 'backend'
  location: location
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8000
        transport: 'auto' // Supports WebSockets automatically
        corsPolicy: {
          allowedOrigins: ['*']
          allowedMethods: ['*']
          allowedHeaders: ['*']
        }
      }
      secrets: [
        { name: 'redis-password', value: redisPassword }
        { name: 'registry-password', value: registryPassword }
      ]
      registries: [
        {
          server: registryLoginServer
          username: registryUsername
          passwordSecretRef: 'registry-password'
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'backend'
          // In a real deployment, replace with actual ACR image
          image: '${registryLoginServer}/agentops-backend:latest'
          env: [
            { name: 'REDIS_URL', value: 'rediss://:${redisPassword}@${redisHost}:6380/0' }
            { name: 'NEO4J_URI', value: 'bolt://neo4j-trust-store:7687' }
            { name: 'NEO4J_USER', value: 'neo4j' }
            { name: 'NEO4J_PASSWORD', value: 'agentops_secure_password' }
            { name: 'ENABLE_SEMANTIC_FIREWALL', value: 'true' }
          ]
          resources: {
            cpu: json('1.0')
            memory: '2.0Gi'
          }
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 10
      }
    }
  }
}

// Frontend App (React Dashboard)
resource frontendApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: 'frontend'
  location: location
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 80
      }
      secrets: [
        { name: 'registry-password', value: registryPassword }
      ]
      registries: [
        {
          server: registryLoginServer
          username: registryUsername
          passwordSecretRef: 'registry-password'
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'frontend'
          // In a real deployment, replace with actual ACR image
          image: '${registryLoginServer}/agentops-frontend:latest'
          env: [
            { name: 'VITE_API_URL', value: 'https://${backendApp.properties.configuration.ingress.fqdn}/api' }
            { name: 'VITE_WS_URL', value: 'wss://${backendApp.properties.configuration.ingress.fqdn}/ws/dashboard' }
          ]
          resources: {
            cpu: json('0.5')
            memory: '1.0Gi'
          }
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 5
      }
    }
  }
}

// Outputs
output backendUrl string = 'https://${backendApp.properties.configuration.ingress.fqdn}'
output frontendUrl string = 'https://${frontendApp.properties.configuration.ingress.fqdn}'
