import { Redis } from '@upstash/redis'
import dotenv from 'dotenv'

dotenv.config()

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN
})

async function debug() {
  console.log('🔍 Buscando keys no Redis...\n')
  console.log('URL:', process.env.UPSTASH_REDIS_REST_URL)
  console.log('Token:', process.env.UPSTASH_REDIS_REST_TOKEN?.substring(0, 20) + '...\n')
  
  // Tentar vários padrões
  const patterns = ['apikey:*', 'ApiKey:*', 'api_key:*', '*key*']
  
  for (const pattern of patterns) {
    try {
      const keys = await redis.keys(pattern)
      console.log(`📊 Pattern "${pattern}": ${keys.length} keys encontradas`)
      
      if (keys.length > 0 && keys.length < 100) {
        console.log('   Keys:', keys.slice(0, 5))
        
        // Ver conteúdo da primeira key
        const firstKey = keys[0]
        const data = await redis.get(firstKey)
        if (data) {
          console.log(`\n   📄 Conteúdo de "${firstKey}":`)
          try {
            console.log(JSON.stringify(JSON.parse(data), null, 2))
          } catch {
            console.log(data)
          }
        }
        console.log('\n')
      }
    } catch (error) {
      console.error(`Erro no pattern ${pattern}:`, error.message)
    }
  }
}

debug().catch(console.error)
