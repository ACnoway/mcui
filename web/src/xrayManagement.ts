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
