import { lookup } from 'node:dns/promises';
import type { LookupFunction } from 'node:net';
import ipaddr from 'ipaddr.js';
import { Agent } from 'undici';

type Address = { address: string; family: number };
type Resolver = (host: string) => Promise<Address[]>;

export function isPublicAuditAddress(address: string): boolean {
  try {
    // Only plain globally routable unicast; mapped/transition IPv6 is rejected.
    return ipaddr.parse(address).range() === 'unicast';
  } catch { return false; }
}

/** Validate inside the socket's lookup callback. The socket receives these exact
 * addresses, so no second DNS resolution can replace them after validation. */
export function createSafeLookup(resolve: Resolver = host => lookup(host, { all: true, verbatim: true })): LookupFunction {
  return (host, options, callback) => {
    void resolve(host).then(answers => {
      if (!answers.length) throw new Error('No DNS addresses for audit target');
      if (answers.some(a => !isPublicAuditAddress(a.address))) throw new Error('Non-public DNS address for audit target');
      const family = typeof options === 'number' ? options : options.family;
      const selected = family ? answers.filter(a => a.family === family) : answers;
      if (!selected.length) throw new Error('No DNS addresses for requested address family');
      if (typeof options === 'object' && options.all) callback(null, selected);
      else callback(null, selected[0].address, selected[0].family);
    }).catch(error => callback(error as Error, '', 0));
  };
}

// This dispatcher cannot inherit a proxy or another caller's unsafe resolver.
export const auditDispatcher = new Agent({ connect: { lookup: createSafeLookup() } });
