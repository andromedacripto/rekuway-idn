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
const data = await redis.get(keys[0])

console.log('TIPO:', typeof data)
console.log('CONTEUDO:', JSON.stringify(data, null, 2))
