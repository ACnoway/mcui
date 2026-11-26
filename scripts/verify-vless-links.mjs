import assert from 'node:assert/strict'
import { buildVlessLink, buildXrayClient } from '../web/src/xraySubscription.ts'

const id = '00000000-0000-4000-8000-000000000001'
const base = {
  schema_version: 3, username: 'alice', address: '127.0.0.1', ports: [1080],
  port_protocols: { 1080: 'vless' }, revision: 1, expires_at: 2000000000,
}
const raw = new URL(buildVlessLink(base, 1080, id, '节点 1'))
assert.equal(raw.protocol, 'vless:')
assert.equal(raw.username, id)
assert.equal(raw.hostname, '127.0.0.1')
assert.equal(raw.searchParams.get('type'), 'tcp')
assert.equal(raw.searchParams.get('security'), 'none')
assert.equal(decodeURIComponent(raw.hash.slice(1)), '节点 1')
const published = {
  ...base, schema_version: 4, public_endpoints: { 1080: { address: '93.184.216.34', port: 443 } },
}
const publicLink = new URL(buildVlessLink(published, 1080, id, 'public'))
assert.equal(publicLink.hostname, '93.184.216.34')
assert.equal(publicLink.port, '443')

const key = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const reality = { ...base, port_protocols: { 1080: 'vless-reality' }, reality_public_key: key }
const link = new URL(buildVlessLink(reality, 1080, `${id}:0123456789abcdef`, 'reality'))
assert.equal(link.searchParams.get('security'), 'reality')
assert.equal(link.searchParams.get('pbk'), key)
assert.equal(link.searchParams.get('sid'), '0123456789abcdef')
assert.equal(link.searchParams.get('sni'), 'localhost')
assert.throws(() => buildVlessLink(reality, 1080, `${id}:bad`, 'bad'))
assert.throws(() => buildVlessLink(base, 1081, id, 'bad'))
assert.throws(() => buildVlessLink({ ...base, port_protocols: { 1080: 'vmess' } }, 1080, id, 'bad'))

for (const stream of [
  { network: 'ws', path: '/websocket', host: 'example.test' },
  { network: 'httpupgrade', path: '/upgrade' },
  { network: 'xhttp', path: '/xhttp', mode: 'auto' },
  { network: 'grpc', service_name: 'proxy', authority: 'example.test', multi_mode: true },
]) {
  const config = { ...base, schema_version: 5, vless_streams: { 1080: stream } }
  const url = new URL(buildVlessLink(config, 1080, id, 'test'))
  assert.equal(url.searchParams.get('type'), stream.network)
  if (stream.path) assert.equal(url.searchParams.get('path'), stream.path)
  if (stream.service_name) assert.equal(url.searchParams.get('serviceName'), stream.service_name)
  if (stream.authority) assert.equal(url.searchParams.get('authority'), stream.authority)
  if (stream.multi_mode) assert.equal(url.searchParams.get('mode'), 'multi')
  const client = buildXrayClient(config, 1080, 10808, id)
  assert.equal(client.outbounds[0].streamSettings.network, stream.network)
  const settings = client.outbounds[0].streamSettings[`${stream.network}Settings`]
  if (stream.path) assert.equal(settings.path, stream.path)
  if (stream.service_name) assert.equal(settings.serviceName, stream.service_name)
}

const tls = {
  ...base, schema_version: 5,
  trojan_trust: { certificate: '-----BEGIN CERTIFICATE-----\nMII=\n-----END CERTIFICATE-----', sha256: 'a'.repeat(64) },
  vless_streams: { 1080: { network: 'grpc', security: 'tls', service_name: 'proxy' } },
}
const tlsURL = new URL(buildVlessLink(tls, 1080, id, 'tls'))
assert.equal(tlsURL.searchParams.get('security'), 'tls')
assert.equal(tlsURL.searchParams.get('pcs'), 'a'.repeat(64))
assert.equal(tlsURL.searchParams.get('sni'), 'localhost')
const tlsClient = buildXrayClient(tls, 1080, 10808, id)
assert.equal(tlsClient.outbounds[0].streamSettings.tlsSettings.pinnedPeerCertSha256, 'a'.repeat(64))
assert.throws(() => buildVlessLink({ ...tls, trojan_trust: undefined }, 1080, id, 'tls'))
