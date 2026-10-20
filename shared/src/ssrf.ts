/**
 * SSRF defence (Part A / A5, Part F / F7).
 *
 * This module is deliberately pure: it only parses and classifies strings. It
 * runs unchanged in the browser (form validation, immediate feedback) and in
 * the probe engine (the authoritative check, applied again for every redirect).
 *
 * The rules:
 *   - only `http:` and `https:` are accepted;
 *   - hostnames must be a real DNS name or a literal IP address;
 *   - every literal or resolved IP must be a globally routable address;
 *   - loopback, private, link-local, CGNAT, multicast, reserved, documentation,
 *     unique-local and cloud metadata addresses are all rejected;
 *   - IPv4-mapped, IPv4-compatible, NAT64 and 6to4 addresses are unwrapped and
 *     the embedded IPv4 address is classified, so `::ffff:127.0.0.1` cannot
 *     smuggle a loopback target past the check.
 *
 * DNS resolution itself lives in `server/src/probe/net.ts` because it needs
 * `node:dns`; the decision logic lives here so it is unit-testable.
 */

/* -------------------------------------------------------------------------- */
/* IP parsing                                                                 */
/* -------------------------------------------------------------------------- */

/** IPv4 dotted quad -> 32-bit unsigned integer, or `null` when malformed. */
export function parseIpv4(value: string): number | null {
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    // Reject octal-looking values such as `0177` that different parsers read
    // differently.
    if (part.length > 1 && part[0] === '0') return null;
    const octet = Number(part);
    if (octet > 255) return null;
    result = (result * 256 + octet) >>> 0;
  }
  return result;
}

export function formatIpv4(value: number): string {
  return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.');
}

/** IPv6 (with optional brackets and zone) -> 16 bytes, or `null`. */
export function parseIpv6(value: string): Uint8Array | null {
  let input = value.trim();
  if (input.startsWith('[') && input.endsWith(']')) input = input.slice(1, -1);
  const zone = input.indexOf('%');
  if (zone !== -1) input = input.slice(0, zone);
  if (input.length === 0) return null;

  // Unwrap a trailing dotted quad into two hextets (e.g. `::ffff:127.0.0.1`).
  const tail: string[] = [];
  if (input.includes('.')) {
    const colon = input.lastIndexOf(':');
    if (colon === -1) return null;
    const embedded = parseIpv4(input.slice(colon + 1));
    if (embedded === null) return null;
    tail.push(((embedded >>> 16) & 0xffff).toString(16));
    tail.push((embedded & 0xffff).toString(16));
    input = input.slice(0, colon + 1);
  }

  const compression = input.indexOf('::');
  let groups: string[];
  if (compression !== -1) {
    if (input.indexOf('::', compression + 1) !== -1) return null;
    const left = input.slice(0, compression).split(':').filter((part) => part !== '');
    const right = input.slice(compression + 2).split(':').filter((part) => part !== '');
    const missing = 8 - left.length - right.length - tail.length;
    if (missing < 0) return null;
    groups = [...left, ...new Array<string>(missing).fill('0'), ...right];
  } else {
    groups = input.split(':');
  }

  groups = [...groups, ...tail];
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let index = 0; index < groups.length; index += 1) {
    const group = groups[index]!;
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    const parsed = Number.parseInt(group, 16);
    bytes[index * 2] = (parsed >> 8) & 255;
    bytes[index * 2 + 1] = parsed & 255;
  }
  return bytes;
}

/** Formats 16 bytes back into a readable IPv6 literal (compressed). */
export function formatIpv6(bytes: Uint8Array): string {
  const groups: string[] = [];
  for (let index = 0; index < 16; index += 2) {
    groups.push(((bytes[index]! << 8) | bytes[index + 1]!).toString(16));
  }
  
  // Find the longest run of "0" groups to compress with ::
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] === '0') {
      if (curLen === 0) curStart = i;
      curLen += 1;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curLen = 0;
      curStart = -1;
    }
  }
  
  // Only compress if run is at least 2 groups
  if (bestLen >= 2) {
    const before = groups.slice(0, bestStart).join(':');
    const after = groups.slice(bestStart + bestLen).join(':');
    if (before && after) return `${before}::${after}`;
    if (before) return `${before}::`;
    if (after) return `::${after}`;
    return '::';
  }
  
  return groups.join(':');
}

export function isIpLiteral(host: string): boolean {
  const value = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  return parseIpv4(value) !== null || parseIpv6(value) !== null;
}

export function addressFamilyOf(host: string): 4 | 6 | null {
  const value = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  if (parseIpv4(value) !== null) return 4;
  if (parseIpv6(value) !== null) return 6;
  return null;
}

/** Wraps an IPv6 literal in brackets so it can be used in a URL. */
export function toUrlHostname(host: string): string {
  const family = addressFamilyOf(host);
  return family === 6 ? `[${host}]` : host;
}

/* -------------------------------------------------------------------------- */
/* Classification                                                             */
/* -------------------------------------------------------------------------- */

export type AddressCategory =
  | 'public'
  | 'unspecified'
  | 'loopback'
  | 'private'
  | 'unique_local'
  | 'link_local'
  | 'site_local'
  | 'cgnat'
  | 'carrier_grad_nat'
  | 'documentation'
  | 'benchmark'
  | 'multicast'
  | 'reserved'
  | 'metadata'
  | 'ipv4_mapped'
  | 'ipv4_compatible'
  | 'nat64'
  | 'six_to_four'
  | 'teredo';

export interface AddressVerdict {
  /** `true` only for a globally routable address. */
  allowed: boolean;
  category: AddressCategory;
  /** Operator-facing explanation, e.g. "private IPv4 range 10.0.0.0/8". */
  reason: string | null;
}

/** Cloud instance-metadata endpoints that must never be reachable (Part A / A5). */
const METADATA_IPV4 = new Map<string, string>([
  ['169.254.169.254', 'AWS/GCP/Azure/DigitalOcean instance metadata'],
  ['169.254.170.2', 'ECS task metadata'],
  ['100.100.100.200', 'Alibaba Cloud metadata'],
  ['192.0.0.192', 'Oracle Cloud metadata'],
  ['192.0.0.170', 'Oracle Cloud metadata (NAT64 discovery)'],
]);

const METADATA_IPV6 = new Map<string, string>([
  ['fd00:ec2::254', 'AWS IMDS over IPv6'],
  ['fe80::a9fe:a9fe', 'Link-local metadata (AWS classic)'],
]);

/** IPv4 ranges that must never be probed, with a readable reason each. */
const IPV4_RANGES: Array<{ cidr: string; start: number; end: number; category: AddressCategory; reason: string }> = [
  { cidr: '0.0.0.0/8', start: 0x00000000, end: 0x00ffffff, category: 'unspecified', reason: 'unspecified "this network" range' },
  { cidr: '10.0.0.0/8', start: 0x0a000000, end: 0x0affffff, category: 'private', reason: 'private IPv4 range 10.0.0.0/8' },
  { cidr: '100.64.0.0/10', start: 0x64400000, end: 0x647fffff, category: 'cgnat', reason: 'carrier-grade NAT range 100.64.0.0/10' },
  { cidr: '127.0.0.0/8', start: 0x7f000000, end: 0x7fffffff, category: 'loopback', reason: 'loopback range 127.0.0.0/8' },
  { cidr: '169.254.0.0/16', start: 0xa9fe0000, end: 0xa9feffff, category: 'link_local', reason: 'link-local range 169.254.0.0/16' },
  { cidr: '172.16.0.0/12', start: 0xac100000, end: 0xac1fffff, category: 'private', reason: 'private IPv4 range 172.16.0.0/12' },
  { cidr: '192.0.0.0/24', start: 0xc0000000, end: 0xc00000ff, category: 'reserved', reason: 'IETF protocol assignments 192.0.0.0/24' },
  { cidr: '192.0.2.0/24', start: 0xc0000200, end: 0xc00002ff, category: 'documentation', reason: 'documentation range 192.0.2.0/24' },
  { cidr: '192.88.99.0/24', start: 0xc0586300, end: 0xc05863ff, category: 'reserved', reason: '6to4 relay anycast 192.88.99.0/24' },
  { cidr: '192.168.0.0/16', start: 0xc0a80000, end: 0xc0a8ffff, category: 'private', reason: 'private IPv4 range 192.168.0.0/16' },
  { cidr: '198.18.0.0/15', start: 0xc6120000, end: 0xc613ffff, category: 'benchmark', reason: 'benchmark range 198.18.0.0/15' },
  { cidr: '198.51.100.0/24', start: 0xc6336400, end: 0xc63364ff, category: 'documentation', reason: 'documentation range 198.51.100.0/24' },
  { cidr: '203.0.113.0/24', start: 0xcb007100, end: 0xcb0071ff, category: 'documentation', reason: 'documentation range 203.0.113.0/24' },
  { cidr: '224.0.0.0/4', start: 0xe0000000, end: 0xefffffff, category: 'multicast', reason: 'multicast range 224.0.0.0/4' },
  { cidr: '240.0.0.0/4', start: 0xf0000000, end: 0xffffffff, category: 'reserved', reason: 'reserved range 240.0.0.0/4 (includes broadcast)' },
];

function classifyIpv4(address: number): AddressVerdict {
  const dotted = formatIpv4(address);
  const metadata = METADATA_IPV4.get(dotted);
  if (metadata) {
    return { allowed: false, category: 'metadata', reason: `cloud metadata address (${metadata})` };
  }
  for (const range of IPV4_RANGES) {
    if (address >= range.start && address <= range.end) {
      return { allowed: false, category: range.category, reason: range.reason };
    }
  }
  return { allowed: true, category: 'public', reason: null };
}

function matchesIpv6Prefix(bytes: Uint8Array, prefixHex: string, bits: number): boolean {
  const fullBytes = bits >> 3;
  for (let index = 0; index < fullBytes; index += 1) {
    if (bytes[index] !== Number.parseInt(prefixHex.slice(index * 2, index * 2 + 2), 16)) return false;
  }
  const remainder = bits % 8;
  if (remainder === 0) return true;
  const mask = (0xff << (8 - remainder)) & 0xff;
  return (bytes[fullBytes]! & mask) === (Number.parseInt(prefixHex.slice(fullBytes * 2, fullBytes * 2 + 2), 16) & mask);
}

function embeddedIpv4(bytes: Uint8Array, offset: number): number {
  return (
    (((bytes[offset]! << 24) | (bytes[offset + 1]! << 16) | (bytes[offset + 2]! << 8) | bytes[offset + 3]!) >>> 0)
  );
}

function isAllZero(bytes: Uint8Array, from: number, to: number): boolean {
  for (let index = from; index < to; index += 1) if (bytes[index] !== 0) return false;
  return true;
}

function classifyIpv6(bytes: Uint8Array): AddressVerdict {
  const literal = formatIpv6(bytes);
  const metadata = METADATA_IPV6.get(literal);
  if (metadata) return { allowed: false, category: 'metadata', reason: `cloud metadata address (${metadata})` };

  if (isAllZero(bytes, 0, 16)) {
    return { allowed: false, category: 'unspecified', reason: 'unspecified IPv6 address ::' };
  }
  if (isAllZero(bytes, 0, 15) && bytes[15] === 1) {
    return { allowed: false, category: 'loopback', reason: 'IPv6 loopback ::1' };
  }

  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d).
  if (isAllZero(bytes, 0, 10) && bytes[10] === 0xff && bytes[11] === 0xff) {
    const inner = classifyIpv4(embeddedIpv4(bytes, 12));
    return inner.allowed
      ? { allowed: false, category: 'ipv4_mapped', reason: 'IPv4-mapped IPv6 address is not accepted' }
      : { ...inner, reason: `IPv4-mapped IPv6 address (${inner.reason})` };
  }
  if (isAllZero(bytes, 0, 12) && bytes[12] !== 0 && bytes[12] !== 0xff) {
    const inner = classifyIpv4(embeddedIpv4(bytes, 12));
    return inner.allowed
      ? { allowed: false, category: 'ipv4_compatible', reason: 'IPv4-compatible IPv6 address is not accepted' }
      : { ...inner, reason: `IPv4-compatible IPv6 address (${inner.reason})` };
  }

  // NAT64 well-known prefix 64:ff9b::/96.
  if (matchesIpv6Prefix(bytes, '0064ff9b0000000000000000', 96)) {
    const inner = classifyIpv4(embeddedIpv4(bytes, 12));
    return inner.allowed
      ? { allowed: false, category: 'nat64', reason: 'NAT64 address is not accepted' }
      : { ...inner, reason: `NAT64-wrapped ${inner.reason}` };
  }

  if (matchesIpv6Prefix(bytes, '0064', 96)) {
    return { allowed: false, category: 'reserved', reason: 'reserved IPv6 range 64::/96' };
  }
  if (matchesIpv6Prefix(bytes, '0100', 64)) {
    return { allowed: false, category: 'reserved', reason: 'discard-only range 100::/64' };
  }
  if (matchesIpv6Prefix(bytes, '2001', 32) && bytes[2] === 0x00 && bytes[3] === 0x00) {
    return { allowed: false, category: 'reserved', reason: 'Teredo range 2001:0000::/32' };
  }
  if (matchesIpv6Prefix(bytes, '20010db8', 32)) {
    return { allowed: false, category: 'documentation', reason: 'documentation range 2001:db8::/32' };
  }
  if (matchesIpv6Prefix(bytes, '2002', 16)) {
    const inner = classifyIpv4(embeddedIpv4(bytes, 2));
    return inner.allowed
      ? { allowed: false, category: 'six_to_four', reason: '6to4 address is not accepted' }
      : { ...inner, reason: `6to4-wrapped ${inner.reason}` };
  }
  if (matchesIpv6Prefix(bytes, 'fc00', 7)) {
    return { allowed: false, category: 'unique_local', reason: 'IPv6 unique-local range fc00::/7' };
  }
  if (matchesIpv6Prefix(bytes, 'fe80', 10)) {
    return { allowed: false, category: 'link_local', reason: 'IPv6 link-local range fe80::/10' };
  }
  if (matchesIpv6Prefix(bytes, 'fec0', 10)) {
    return { allowed: false, category: 'site_local', reason: 'deprecated IPv6 site-local range fec0::/10' };
  }
  if ((bytes[0]! & 0xf0) === 0xf0) {
    return { allowed: false, category: 'multicast', reason: 'IPv6 multicast range ff00::/8' };
  }

  return { allowed: true, category: 'public', reason: null };
}

/** Classifies any IPv4/IPv6 literal. Never throws. */
export function classifyAddress(value: string): AddressVerdict {
  const host = value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value.trim();
  const v4 = parseIpv4(host);
  if (v4 !== null) return classifyIpv4(v4);
  const v6 = parseIpv6(host);
  if (v6) return classifyIpv6(v6);
  return { allowed: false, category: 'reserved', reason: 'not an IP address' };
}

export function isPublicAddress(value: string): boolean {
  return classifyAddress(value).allowed;
}

/* -------------------------------------------------------------------------- */
/* Hostnames                                                                  */
/* -------------------------------------------------------------------------- */

const HOSTNAME_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * A DNS name made of LDH labels, 1-253 characters, with at least one dot
 * unless it is an IP literal (which is classified separately). Trailing dots
 * are accepted and stripped.
 */
export function isValidHostname(value: string): boolean {
  const host = value.trim().replace(/\.$/, '').toLowerCase();
  if (host.length === 0 || host.length > 253) return false;
  if (isIpLiteral(host)) return true;
  const labels = host.split('.');
  if (labels.length < 2) return false;
  return labels.every((label) => HOSTNAME_LABEL.test(label));
}

/** Lower-cased hostname with the trailing root dot removed. */
export function normalizeHostname(value: string): string {
  return value.trim().replace(/\.$/, '').toLowerCase();
}

/** True when the label's rightmost part is a single character (`a.io`). */
export function hasDestructiveTld(hostname: string): boolean {
  const tld = normalizeHostname(hostname).split('.').pop() ?? '';
  return tld.length === 1;
}

/* -------------------------------------------------------------------------- */
/* Target validation                                                          */
/* -------------------------------------------------------------------------- */

export type TargetKind = 'http' | 'tcp';

export interface TargetCheckOk {
  ok: true;
  kind: TargetKind;
  /** Normalised absolute URL for HTTP targets. */
  url: string;
  hostname: string;
  port: number;
  /** `true` when the user typed an IP literal rather than a DNS name. */
  literal: boolean;
}

export interface TargetCheckFail {
  ok: false;
  reason: string;
  code:
    | 'invalid_url'
    | 'unsupported_protocol'
    | 'credentials_in_url'
    | 'invalid_hostname'
    | 'blocked_address'
    | 'port_not_allowed';
}

export type TargetCheck = TargetCheckOk | TargetCheckFail;

const FAIL = (reason: string, code: TargetCheckFail['code']): TargetCheck => ({ ok: false, reason, code });

/**
 * Validates and normalises an HTTP(S) monitor target.
 *
 * `allowedPorts` is required so a monitor cannot be turned into a request
 * generator for an arbitrary port. A literal IP is classified here; a DNS name
 * must be resolved and validated by the caller (server-side) before use.
 */
export function checkHttpTarget(rawUrl: string, allowedPorts: readonly number[]): TargetCheck {
  let url: URL;
  try {
    url = new URL(rawUrl.trim());
    // Strip fragment - it's never sent to the server and shouldn't be stored
    url.hash = '';
  } catch {
    return FAIL('Enter a full URL, for example https://example.com/health.', 'invalid_url');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return FAIL(
      `Only http:// and https:// targets are supported. "${url.protocol.replace(':', '')}" is not allowed.`,
      'unsupported_protocol',
    );
  }
  if (url.username !== '' || url.password !== '') {
    return FAIL('Remove the username/password from the URL. Credentials in a monitor URL are not supported.', 'credentials_in_url');
  }

  const hostname = normalizeHostname(url.hostname);
  if (!isValidHostname(hostname)) {
    return FAIL('Enter a valid hostname such as example.com.', 'invalid_hostname');
  }

  const literal = isIpLiteral(hostname);
  if (literal) {
    const verdict = classifyAddress(hostname);
    if (!verdict.allowed) {
      return FAIL(`Target address is blocked: ${verdict.reason}.`, 'blocked_address');
    }
  }

  const port = url.port === '' ? (url.protocol === 'https:' ? 443 : 80) : Number(url.port);
  if (!allowedPorts.includes(port)) {
    return FAIL(
      `Port ${port} is not on the allowlist (${allowedPorts.join(', ')}).`,
      'port_not_allowed',
    );
  }

  url.port = '';
  return {
    ok: true,
    kind: 'http',
    url: url.toString(),
    hostname,
    port,
    literal,
  };
}

/**
 * Validates a TCP monitor target: `host` or `host:port`, with the port
 * restricted to the shared allowlist so a monitor cannot become a port scanner
 * (Part F / F7).
 */
export function checkTcpTarget(rawTarget: string, allowedPorts: readonly number[]): TargetCheck {
  const value = rawTarget.trim();
  if (value.length === 0) return FAIL('Enter a host, for example db.example.com.', 'invalid_hostname');
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    return FAIL('Enter a bare host and port (host:port), not a URL.', 'invalid_url');
  }

  let hostPart = value;
  let port: number | null = null;

  if (value.startsWith('[')) {
    const close = value.indexOf(']');
    if (close === -1) return FAIL('Enter a valid IPv6 host, for example [2606:4700::1111].', 'invalid_hostname');
    hostPart = value.slice(1, close);
    const rest = value.slice(close + 1);
    if (rest.startsWith(':')) {
      const parsed = Number(rest.slice(1));
      if (!Number.isInteger(parsed)) return FAIL('Enter a numeric port.', 'invalid_hostname');
      port = parsed;
    } else if (rest !== '') {
      return FAIL('Enter a valid IPv6 host and port.', 'invalid_hostname');
    }
  } else {
    const colon = value.indexOf(':');
    // More than one colon and no brackets means a bare IPv6 literal.
    if (value.indexOf(':', colon + 1) !== -1) {
      hostPart = value;
    } else if (colon !== -1) {
      hostPart = value.slice(0, colon);
      const parsed = Number(value.slice(colon + 1));
      if (!Number.isInteger(parsed)) return FAIL('Enter a numeric port.', 'invalid_hostname');
      port = parsed;
    }
  }

  const hostname = normalizeHostname(hostPart);
  if (!isValidHostname(hostname)) {
    return FAIL('Enter a valid hostname such as db.example.com.', 'invalid_hostname');
  }

  const literal = isIpLiteral(hostname);
  if (literal) {
    const verdict = classifyAddress(hostname);
    if (!verdict.allowed) {
      return FAIL(`Target address is blocked: ${verdict.reason}.`, 'blocked_address');
    }
  }

  const effectivePort = port ?? 443;
  if (!allowedPorts.includes(effectivePort)) {
    return FAIL(
      `Port ${effectivePort} is not on the allowlist (${allowedPorts.join(', ')}). Choose an allowlisted port.`,
      'port_not_allowed',
    );
  }

  return { ok: true, kind: 'tcp', url: `${toUrlHostname(hostname)}:${effectivePort}`, hostname, port: effectivePort, literal };
}

/** Hostname used by the SSL and (unavailable) domain monitor types. */
export function checkHostnameTarget(rawTarget: string): TargetCheck {
  const hostname = normalizeHostname(rawTarget.trim());
  if (!isValidHostname(hostname)) {
    return FAIL('Enter a hostname such as example.com (no scheme, no path).', 'invalid_hostname');
  }
  if (isIpLiteral(hostname)) {
    const verdict = classifyAddress(hostname);
    if (!verdict.allowed) {
      return FAIL(`Target address is blocked: ${verdict.reason}.`, 'blocked_address');
    }
  }
  return { ok: true, kind: 'tcp', url: toUrlHostname(hostname), hostname, port: 443, literal: isIpLiteral(hostname) };
}

/** Hostname of an HTTP target, for the SSL and domain monitors. */
export function hostnameFromUrl(rawUrl: string): string | null {
  try {
    const url = new URL(rawUrl.trim());
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    return normalizeHostname(url.hostname);
  } catch {
    return null;
  }
}

/**
 * Validates one resolved address produced by DNS.
 * Returns `null` when the address is acceptable.
 */
export function rejectionReasonForAddress(address: string): string | null {
  const verdict = classifyAddress(address);
  return verdict.allowed ? null : verdict.reason;
}

/** Human-readable summary used in the UI and in `safe_message`. */
export function describeBlockedAddress(address: string): string {
  const verdict = classifyAddress(address);
  return verdict.reason ?? 'unknown address class';
}
