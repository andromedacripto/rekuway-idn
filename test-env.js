// test-env.js - Script para testar se o .env está sendo lido
require('dotenv').config();

console.log('=================================================');
console.log('🔍 TESTE DE VARIÁVEIS DE AMBIENTE');
console.log('=================================================\n');

const vars = {
  'PORT': process.env.PORT,
  'NODE_ENV': process.env.NODE_ENV,
  'UPSTASH_REDIS_REST_URL': process.env.UPSTASH_REDIS_REST_URL,
  'UPSTASH_REDIS_REST_TOKEN': process.env.UPSTASH_REDIS_REST_TOKEN ? '***TOKEN PRESENTE***' : undefined,
  'JWT_SECRET': process.env.JWT_SECRET ? '***SECRET PRESENTE***' : undefined,
  'ALLOWED_ORIGINS': process.env.ALLOWED_ORIGINS
};

let allOk = true;

for (const [key, value] of Object.entries(vars)) {
  const status = value ? '✅' : '❌';
  console.log(`${status} ${key}: ${value || 'NOT FOUND'}`);
  
  if (!value) {
    allOk = false;
  }
}

console.log('\n=================================================');
if (allOk) {
  console.log('✅ TODAS AS VARIÁVEIS ESTÃO PRESENTES!');
  console.log('O problema NÃO é o .env');
} else {
  console.log('❌ ALGUMAS VARIÁVEIS ESTÃO FALTANDO!');
  console.log('Verifique o arquivo .env na raiz do projeto');
}
console.log('=================================================');

process.exit(allOk ? 0 : 1);