import { Redis } from '@upstash/redis'
import { readFileSync } from 'fs'

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

const keys = await redis.keys('apikey:*')
console.log(`\n📊 Total de ${keys.length} API keys no Redis\n`)

let totalReq = 0
let totalBlocked = 0

for (const key of keys) {
  const data = await redis.get(key)
  if (data && data.usage) {
    const req = data.usage.totalRequests || 0
    const blocked = data.usage.blockedRequests || 0
    
    if (req > 0 || blocked > 0) {
      console.log(`Key: ${data.name || 'Unknown'}`)
      console.log(`  totalRequests: ${req}`)
      console.log(`  blockedRequests: ${blocked}`)
      console.log('')
    }
    
    totalReq += req
    totalBlocked += blocked
  }
}

console.log(`\n🎯 TOTAIS GLOBAIS:`)
console.log(`   Total Requests: ${totalReq}`)
console.log(`   Blocked Requests: ${totalBlocked}\n`)
