export type Destination = { address: string; port: number }
export type Outbound = { tag: string; destination: Destination }
export type Route = { inbound_port: number; outbound_tag: string }
export type Network = { outbounds: Outbound[]; routes: Route[] }

export function destinationLabel(destination: Destination) {
  return `${destination.address}:${destination.port}`
}

export function copyNetwork(network?: Network | null): Network | null {
  return network ? {
    outbounds: network.outbounds.map(outbound => ({ ...outbound, destination: { ...outbound.destination } })),
    routes: network.routes.map(route => ({ ...route })),
  } : null
}

export type RouteDecision = {
  ruleIndex: number
  route: Route
  outbound: Outbound
} | null

export function testRoute(network: Network, inboundPort: number, destination: Destination): RouteDecision {
  for (const [ruleIndex, route] of network.routes.entries()) {
    if (route.inbound_port !== inboundPort) continue
    const outbound = network.outbounds.find(candidate => candidate.tag === route.outbound_tag)
    if (outbound?.destination.address === destination.address && outbound.destination.port === destination.port) {
      return { ruleIndex, route, outbound }
    }
  }
  return null
}
