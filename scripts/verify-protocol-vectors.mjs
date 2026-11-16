import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'

const seedHex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
const privatePrefix = Buffer.from('302e020100300506032b657004220420', 'hex')
const publicPrefix = Buffer.from('302a300506032b6570032100', 'hex')
const privateKey = createPrivateKey({ key: Buffer.concat([privatePrefix, Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' })
const publicKey = createPublicKey(privateKey)
const publicKeyHex = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')

const domains = {
  task: 'MCUI-TASK-V1\n',
  config: 'MCUI-CONFIG-V1\n',
  cancel: 'MCUI-CANCEL-V1\n',
  skip: 'MCUI-SKIP-V1\n',
}

function parseStrict(source) {
  let index = 0
  const whitespace = () => { while (/[\t\n\r ]/.test(source[index] ?? '\0')) index++ }
  const string = () => {
    const start = index++
    while (index < source.length) {
      const char = source[index++]
      if (char === '"') return JSON.parse(source.slice(start, index))
      if (char === '\\') {
        if (index >= source.length) throw new Error('incomplete string escape')
        const escape = source[index++]
        if (escape === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(source.slice(index, index + 4))) throw new Error('invalid Unicode escape')
          index += 4
        }
      } else if (char.charCodeAt(0) < 0x20) throw new Error('control character in string')
    }
    throw new Error('unterminated string')
  }
  const value = () => {
    whitespace()
    const char = source[index]
    if (char === '{') {
      index++
      whitespace()
      const object = Object.create(null)
      if (source[index] === '}') { index++; return object }
      while (true) {
        whitespace()
        if (source[index] !== '"') throw new Error('object key must be a string')
        const key = string()
        if (Object.hasOwn(object, key)) throw new Error(`duplicate key: ${key}`)
        whitespace()
        if (source[index++] !== ':') throw new Error('missing colon')
        object[key] = value()
        whitespace()
        const delimiter = source[index++]
        if (delimiter === '}') return object
        if (delimiter !== ',') throw new Error('invalid object delimiter')
      }
    }
    if (char === '[') {
      index++
      whitespace()
      const array = []
      if (source[index] === ']') { index++; return array }
      while (true) {
        array.push(value())
        whitespace()
        const delimiter = source[index++]
        if (delimiter === ']') return array
        if (delimiter !== ',') throw new Error('invalid array delimiter')
      }
    }
    if (char === '"') return string()
    const match = source.slice(index).match(/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/)
    if (!match) throw new Error('invalid JSON value')
    index += match[0].length
    if (match[0] === 'true') return true
    if (match[0] === 'false') return false
    if (match[0] === 'null') return null
    return Number(match[0])
  }
  const parsed = value()
  whitespace()
  if (index !== source.length) throw new Error('trailing JSON data')
  return parsed
}

function canonicalize(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || typeof value === 'number') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  const keys = Object.keys(value).sort()
  return `{${keys.map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`
}

function canonicalBody(input) {
  const body = Object.assign(Object.create(null), input)
  delete body.signature
  return canonicalize(body)
}

function makeObject(kind, values) {
  return { ...values, signing_key_id: 'test-key-01', signature_algorithm: 'Ed25519' }
}

function vector(id, kind, body, extra = {}) {
  const unsignedJSON = JSON.stringify(body)
  const unsigned = parseStrict(unsignedJSON)
  const canonical = canonicalBody(unsigned)
  const signingBytes = Buffer.concat([Buffer.from(domains[kind], 'ascii'), Buffer.from(canonical, 'utf8')])
  const signature = sign(null, signingBytes, privateKey)
  const input = { ...unsigned, signature: signature.toString('base64') }
  const inputJSON = JSON.stringify(input)
  const reorderedJSON = JSON.stringify(Object.fromEntries(Object.entries(input).reverse()))
  return {
    id, kind, input_json: inputJSON, input_json_reordered: reorderedJSON,
    canonical_json: canonical, signing_input_hex: signingBytes.toString('hex'),
    public_key_hex: publicKeyHex, signature_hex: signature.toString('hex'),
    signature_base64: signature.toString('base64'), expected_valid: true, ...extra,
  }
}

function buildVectors() {
  const configBytes = Buffer.from('{"inbounds":[],"outbounds":[]}', 'utf8')
  const configDigest = createHash('sha256').update(configBytes).digest('hex')
  const vectors = [
    vector('task-core-status', 'task', makeObject('task', {
      schema_version: 1, task_id: 'task-status-001', node_id: 'node-001', sequence: 1,
      operation: 'core.status', issued_at: '2026-11-16T00:00:00Z', not_before: '2026-11-16T00:00:00Z',
      expires_at: '2026-11-16T00:10:00Z', payload: { core: 'xray' },
    })),
    vector('config-revision-1', 'config', makeObject('config', {
      schema_version: 1, node_id: 'node-001', core: 'xray', core_version: 'v1.0.0', revision: 1,
      content_sha256: configDigest, content_size: configBytes.length,
      issued_at: '2026-11-16T00:00:00Z', not_before: '2026-11-16T00:00:00Z', expires_at: '2026-11-16T00:10:00Z',
    }), { config_bytes_hex: configBytes.toString('hex'), config_size: configBytes.length, config_sha256: configDigest }),
    vector('cancel-task-1', 'cancel', makeObject('cancel', {
      schema_version: 1, node_id: 'node-001', task_id: 'task-001', sequence: 1,
      issued_at: '2026-11-16T00:00:00Z', not_before: '2026-11-16T00:00:00Z', expires_at: '2026-11-16T00:10:00Z',
    })),
    vector('skip-sequence-1', 'skip', makeObject('skip', {
      schema_version: 1, node_id: 'node-001', sequence: 1, reason: 'VOID_UNISSUED',
      issued_at: '2026-11-16T00:00:00Z', not_before: '2026-11-16T00:00:00Z', expires_at: '2026-11-16T00:10:00Z',
    })),
  ]
  const task = parseStrict(vectors[0].input_json)
  const negativeCases = [
    { id: 'tampered-node', kind: 'task', input_json: vectors[0].input_json.replace('node-001', 'node-002'), expected_reject: 'signature' },
    { id: 'duplicate-task-id', kind: 'task', input_json: vectors[0].input_json.replace('"task_id":"task-status-001",', '"task_id":"task-status-001","task_id":"task-status-001",'), expected_reject: 'duplicate-key' },
    { id: 'escaped-duplicate-task-id', kind: 'task', input_json: vectors[0].input_json.replace('"task_id":"task-status-001",', '"task_id":"task-status-001","task\\u005fid":"task-status-001",'), expected_reject: 'duplicate-key' },
    { id: 'unknown-field', kind: 'task', input_json: vectors[0].input_json.replace('"signature":', '"extra":"value","signature":'), expected_reject: 'schema' },
    { id: 'fractional-sequence', kind: 'task', input_json: vectors[0].input_json.replace('"sequence":1,', '"sequence":1.0,'), expected_reject: 'schema' },
    { id: 'unsafe-integer', kind: 'task', input_json: vectors[0].input_json.replace('"sequence":1,', '"sequence":9007199254740992,'), expected_reject: 'schema' },
    { id: 'wrong-domain', kind: 'config', input_json: vectors[0].input_json, expected_reject: 'schema-or-signature' },
    { id: 'noncanonical-base64', kind: 'task', input_json: vectors[0].input_json.replace(/"signature":"([^"]+)"/, (_m, sig) => `"signature":"${sig}="`), expected_reject: 'base64' },
  ]
  if (!task.signature) throw new Error('task vector is missing a signature')
  return {
    schema_version: 1,
    generated_with: 'Node.js crypto Ed25519 plus ECMAScript JSON.stringify; public test key only',
    test_private_seed_hex: seedHex,
    public_key_hex: publicKeyHex,
    vectors,
    negative_cases: negativeCases,
  }
}

function verifyVector(vector) {
  const input = parseStrict(vector.input_json)
  const canonical = canonicalBody(input)
  const bytes = Buffer.concat([Buffer.from(domains[vector.kind], 'ascii'), Buffer.from(canonical, 'utf8')])
  const signature = Buffer.from(input.signature, 'base64')
  if (canonical !== vector.canonical_json || bytes.toString('hex') !== vector.signing_input_hex) throw new Error(`${vector.id}: canonical bytes mismatch`)
  if (signature.toString('hex') !== vector.signature_hex || input.signature !== vector.signature_base64) throw new Error(`${vector.id}: signature representation mismatch`)
  const key = createPublicKey({ key: Buffer.concat([publicPrefix, Buffer.from(vector.public_key_hex, 'hex')]), format: 'der', type: 'spki' })
  if (!verify(null, bytes, key, signature)) throw new Error(`${vector.id}: Ed25519 verification failed`)
  const reordered = parseStrict(vector.input_json_reordered)
  if (canonicalBody(reordered) !== canonical) throw new Error(`${vector.id}: field order changed canonical bytes`)
  if (vector.config_bytes_hex) {
    const config = Buffer.from(vector.config_bytes_hex, 'hex')
    if (config.length !== vector.config_size || createHash('sha256').update(config).digest('hex') !== vector.config_sha256) throw new Error(`${vector.id}: config byte binding mismatch`)
  }
}

function verifyNegativeCase(testCase, vectors) {
  const vector = vectors.find(item => item.kind === (testCase.kind === 'config' ? 'config' : 'task'))
  try {
    const input = parseStrict(testCase.input_json)
    if (testCase.expected_reject === 'duplicate-key') throw new Error('duplicate-key case unexpectedly parsed')
    if (testCase.expected_reject === 'base64') {
      if (!input.signature || Buffer.from(input.signature, 'base64').toString('base64') !== input.signature) return
      throw new Error('noncanonical Base64 case unexpectedly passed')
    }
    if (testCase.expected_reject === 'schema') {
      const keys = Object.keys(input)
      const expected = ['schema_version', 'task_id', 'node_id', 'sequence', 'operation', 'issued_at', 'not_before', 'expires_at', 'payload', 'signing_key_id', 'signature_algorithm', 'signature']
      if (input.operation !== 'core.status' || keys.length !== expected.length || expected.some(key => !Object.hasOwn(input, key))) return
      const sequence = testCase.input_json.match(/"sequence":([^,}]+)/)?.[1]
      if (!sequence || !/^(0|[1-9][0-9]*)$/.test(sequence) || !Number.isSafeInteger(input.sequence) || input.sequence < 1) return
      throw new Error('schema negative case unexpectedly passed')
    }
    const canonical = canonicalBody(input)
    const bytes = Buffer.concat([Buffer.from(domains[testCase.kind], 'ascii'), Buffer.from(canonical, 'utf8')])
    const key = createPublicKey({ key: Buffer.concat([publicPrefix, Buffer.from(vector.public_key_hex, 'hex')]), format: 'der', type: 'spki' })
    const signature = Buffer.from(input.signature, 'base64')
    if (!verify(null, bytes, key, signature)) return
    throw new Error('negative signature case unexpectedly verified')
  } catch (error) {
    if (String(error.message).includes('unexpectedly')) throw error
  }
}

const outputPath = new URL('../internal/protocol/testdata/protocol-v1.json', import.meta.url)
if (process.argv.includes('--generate')) {
  const vectors = buildVectors()
  await mkdir(new URL('../internal/protocol/testdata/', import.meta.url), { recursive: true })
  await writeFile(outputPath, `${JSON.stringify(vectors, null, 2)}\n`, 'utf8')
  console.log(`generated ${vectors.vectors.length} signed vectors`)
} else {
  const vectors = JSON.parse(await readFile(outputPath, 'utf8'))
  for (const item of vectors.vectors) verifyVector(item)
  for (const item of vectors.negative_cases) verifyNegativeCase(item, vectors.vectors)
  console.log(`verified ${vectors.vectors.length} signed vectors and ${vectors.negative_cases.length} negative cases`)
}
