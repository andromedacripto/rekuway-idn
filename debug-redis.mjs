import { Redis } from '@upstash/redis'
import { readFileSync } from 'fs'

// Ler .env manualmente
const envFile = readFileSync('.env', 'utf-8')
const envVars = {}
envFile.split('\n').forEach(line => {
  const [key, ...valueParts] = line.split('=')
  if (key && valueParts.length) {
    envVars[key.trim()] = valueParts.join('=').trim().replace(/['"]/g, '')
  }
})

const redis = new Redis({
  url: envVars.UPSTASH_REDIS_REST_URL,
  token: envVars.UPSTASH_REDIS_REST_TOKEN
})

async function debug() {
  console.log('🔍 Buscando keys no Redis...\n')
  
  const patterns = ['apikey:*', 'ApiKey:*', '*key*']
  
  for (const pattern of patterns) {
    try {
      const keys = await redis.keys(pattern)
      console.log(`📊 Pattern "${pattern}": ${keys.length} keys encontradas`)
      
      if (keys.length > 0 && keys.length < 50) {
        console.log('   Primeiras keys:', keys.slice(0, 3))
        
        const firstKey = keys[0]
        const data = await redis.get(firstKey)
        if (data) {
          console.log(`\n   📄 Exemplo "${firstKey}":`)
          console.log(JSON.stringify(JSON.parse(data), null, 2).substring(0, 500))
        }
        console.log('\n')
      }
    } catch (error) {
      console.error(`❌ Erro:`, error.message)
    }
  }
}

debug().catch(console.error)
