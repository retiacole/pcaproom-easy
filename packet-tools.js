'use strict';

// Packet generation happens at build time. The shipped HTML has no tshark dependency.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {execFileSync} = require('node:child_process');

const DEFAULT_MAC = '02:00:00:00:00:10';
const ROUTER_MAC = '02:00:00:00:00:01';
const DEFAULT_IP = '10.0.0.10';
const ROUTER_IP = '10.0.0.1';
const bytes = text => Buffer.from(text || '', 'utf8');
const u16 = n => { const b = Buffer.alloc(2); b.writeUInt16BE(n & 0xffff); return b; };
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const cat = (...parts) => Buffer.concat(parts);
// Deterministic fixture values, never host clocks or Math.random(). Small authored
// TCP counters are translated on the wire while preserving their relative values.
const hash32 = text => { let n = 2166136261; for (const c of text) n = Math.imul(n ^ c.charCodeAt(0), 16777619); return n >>> 0; };
const ECHO_PAYLOAD = 'abcdefghijklmnopqrstuvwabcdefghi';

function mac(s) {
  if (!/^(?:[\da-f]{2}:){5}[\da-f]{2}$/i.test(s)) throw new Error(`Invalid MAC address: ${s}`);
  return Buffer.from(s.replace(/:/g, ''), 'hex');
}
function ip4(s) {
  const parts = String(s).split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) throw new Error(`Invalid IPv4 address: ${s}`);
  return Buffer.from(parts);
}
function ip6(s) {
  let address = String(s);
  if (address.includes('.')) {
    const lastColon = address.lastIndexOf(':');
    const v4 = ip4(address.slice(lastColon + 1));
    address = address.slice(0, lastColon + 1) + v4.readUInt16BE(0).toString(16) + ':' + v4.readUInt16BE(2).toString(16);
  }
  if ((address.match(/::/g) || []).length > 1) throw new Error(`Invalid IPv6 address: ${s}`);
  const halves = address.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const words = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
  if (words.length !== 8 || words.some(w => !/^[\da-f]{1,4}$/i.test(w))) throw new Error(`Invalid IPv6 address: ${s}`);
  return cat(...words.map(w => u16(parseInt(w, 16))));
}
function checksum(buf) {
  let sum = 0;
  for (let i = 0; i < buf.length; i += 2) sum += (buf[i] << 8) | (buf[i + 1] || 0);
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}
function endpoints(s) {
  const v6 = !!s.ipv6 || s.type === 'icmp6';
  return {v6, src: s.src || (v6 ? '2001:db8::10' : DEFAULT_IP), dst: s.dst || (v6 ? '2001:db8::1' : ROUTER_IP)};
}
function pseudo(s, protocol, length) {
  const e = endpoints(s);
  return e.v6 ? cat(ip6(e.src), ip6(e.dst), u32(length), Buffer.from([0, 0, 0, protocol])) : cat(ip4(e.src), ip4(e.dst), Buffer.from([0, protocol]), u16(length));
}
function network(s, protocol, body, index) {
  const e = endpoints(s);
  if (e.v6) {
    const h = Buffer.alloc(40);
    h.writeUInt32BE(0x60000000); h.writeUInt16BE(body.length, 4); h[6] = protocol; h[7] = s.hopLimit ?? (s.type === 'icmp6' && [134, 135, 136].includes(s.icmpType) ? 255 : 64);
    ip6(e.src).copy(h, 8); ip6(e.dst).copy(h, 24);
    return cat(h, body);
  }
  const h = Buffer.alloc(20);
  h[0] = 0x45; h.writeUInt16BE(20 + body.length, 2); h.writeUInt16BE((index + 1) & 0xffff, 4);
  h.writeUInt16BE(0x4000, 6); h[8] = s.ttl ?? 64; h[9] = protocol;
  ip4(e.src).copy(h, 12); ip4(e.dst).copy(h, 16); h.writeUInt16BE(checksum(h), 10);
  return cat(h, body);
}
function dnsName(name) {
  const labels = String(name).replace(/\.$/, '').split('.');
  if (labels.some(l => !l.length || Buffer.byteLength(l) > 63)) throw new Error(`Invalid DNS name: ${name}`);
  return cat(...labels.flatMap(l => [Buffer.from([Buffer.byteLength(l)]), bytes(l)]), Buffer.from([0]));
}
function dnsMessage(s) {
  const qtype = s.qtype ?? 1;
  const answers = s.answers || [];
  const hasQuestion = s.dnsQuestion !== false;
  const h = Buffer.alloc(12);
  h.writeUInt16BE(s.dnsId ?? 0x1234, 0); h.writeUInt16BE(s.dnsFlags ?? ((s.response ? 0x8180 : 0x0100) | (s.rcode || 0)), 2);
  h.writeUInt16BE(hasQuestion ? 1 : 0, 4); h.writeUInt16BE(s.response ? answers.length : 0, 6);
  const edns = s.edns !== false;
  h.writeUInt16BE(edns ? 1 : 0, 10);
  const q = hasQuestion ? cat(dnsName(s.name), u16(qtype), u16(1)) : Buffer.alloc(0);
  const owner = hasQuestion ? Buffer.from([0xc0, 0x0c]) : dnsName(s.name);
  const rr = s.response ? answers.map(answer => { const data = qtype === 28 ? ip6(answer) : ip4(answer); return cat(owner, u16(qtype), u16(1), u32(300), u16(data.length), data); }) : [];
  // OPT is additional metadata, not an answer. No DNSSEC/extended flags are set.
  const opt = edns ? cat(Buffer.from([0]), u16(41), u16(s.ednsPayloadSize ?? 1232), u32(0), u16(0)) : Buffer.alloc(0);
  return cat(h, q, ...rr, opt);
}
function dhcpMessage(s) {
  const h = Buffer.alloc(236);
  h[0] = [2, 5].includes(s.message) ? 2 : 1; h[1] = 1; h[2] = 6;
  h.writeUInt32BE((s.xid ?? 0x3903f326) >>> 0, 4); h.writeUInt16BE(0x8000, 10);
  ip4(s.yiaddr || '0.0.0.0').copy(h, 16); ip4(s.server || '0.0.0.0').copy(h, 20);
  mac(s.clientMac || DEFAULT_MAC).copy(h, 28);
  const opts = [Buffer.from([99, 130, 83, 99, 53, 1, s.message])];
  const option = (code, data) => {
    if (data.length > 255) throw new Error(`DHCP option ${code} exceeds 255 bytes`);
    opts.push(cat(Buffer.from([code, data.length]), data));
  };
  if (s.requested) option(50, ip4(s.requested));
  if (s.server) option(54, ip4(s.server));
  if (s.mask) option(1, ip4(s.mask));
  if (s.router) option(3, ip4(s.router));
  if (s.dns) option(6, ip4(s.dns));
  if ([2, 5].includes(s.message)) {
    const lease = s.leaseTime ?? 3600;
    const renewal = s.renewalTime ?? Math.floor(lease / 2), rebinding = s.rebindingTime ?? Math.floor(lease * 7 / 8);
    if (![lease, renewal, rebinding].every(Number.isInteger) || !(0 < renewal && renewal < rebinding && rebinding < lease && lease <= 0xffffffff)) throw new Error('DHCP lease must satisfy 0 < renewal < rebinding < lease <= 2^32-1');
    option(51, u32(lease));
    if (s.dhcpOptions !== false) { option(58, u32(renewal)); option(59, u32(rebinding)); }
  }
  if ([1, 3].includes(s.message)) {
    option(55, Buffer.from([1, 3, 6]));
    if (s.dhcpOptions !== false) {
      option(61, cat(Buffer.from([1]), mac(s.clientMac || DEFAULT_MAC)));
      option(12, bytes(s.hostName ?? 'pcaproom-client'));
      option(60, bytes(s.vendorClass ?? 'pcaproom-easy'));
      option(57, u16(s.maximumMessageSize ?? 1500));
    }
  }
  opts.push(Buffer.from([255]));
  let result = cat(h, ...opts);
  if (result.length < 300) result = cat(result, Buffer.alloc(300 - result.length));
  return result;
}
function ntpMessage(s) {
  const b = Buffer.alloc(48);
  b[0] = ((s.version ?? 4) << 3) | s.mode; b[1] = s.stratum ?? (s.mode === 4 ? 2 : 0); b[2] = 6; b[3] = 0xec;
  if (s.mode === 4) { b.writeUInt32BE(0x00000100, 4); b.writeUInt32BE(0x00000080, 8); ip4('192.0.2.123').copy(b, 12); }
  // Fixed, non-sensitive demonstration timestamps. The response echoes the request timestamp.
  const stamp = cat(u32(3991593600), u32(0x20000000));
  if (s.mode === 4) { stamp.copy(b, 16); stamp.copy(b, 24); stamp.copy(b, 32); }
  stamp.copy(b, 40);
  return b;
}
function tlsMessage(s) {
  if (s.tlsKind === 'applicationData') {
    // Opaque fixture, deliberately not represented as real ciphertext of any session.
    const opaque = Buffer.from('7a31b80ff390a2becc612701c8d93ef5a218c483fd8be03c', 'hex');
    return cat(Buffer.from([23, 3, 3]), u16(opaque.length), opaque);
  }
  const random = Buffer.from(Array.from({length: 32}, (_, i) => s.tlsKind === 'serverHello' ? (i + 73) & 255 : (i + 17) & 255));
  let body;
  if (s.tlsKind === 'clientHello') {
    const extensions = [];
    if (s.serverName) {
      const host = bytes(s.serverName);
      const names = cat(Buffer.from([0]), u16(host.length), host);
      const data = cat(u16(names.length), names);
      extensions.push(cat(u16(0), u16(data.length), data));
    }
    // TLS 1.2 + RSA cipher keeps the demonstrative hello valid without fake key exchange.
    extensions.push(cat(u16(13), u16(6), u16(4), Buffer.from([4, 1, 5, 1])));
    const ext = cat(...extensions);
    body = cat(Buffer.from([3, 3]), random, Buffer.from([0]), u16(2), u16(0x002f), Buffer.from([1, 0]), u16(ext.length), ext);
  } else if (s.tlsKind === 'serverHello') {
    body = cat(Buffer.from([3, 3]), random, Buffer.from([0]), u16(0x002f), Buffer.from([0]), u16(0));
  } else throw new Error(`Unknown TLS fixture kind: ${s.tlsKind}`);
  const hs = Buffer.alloc(4); hs[0] = s.tlsKind === 'clientHello' ? 1 : 2; hs.writeUIntBE(body.length, 1, 3);
  const record = cat(hs, body);
  return cat(Buffer.from([22, 3, 3]), u16(record.length), record);
}
function transportPayload(s) {
  if (s.type === 'dns') { const d = dnsMessage(s); return s.transport === 'tcp' ? cat(u16(d.length), d) : d; }
  if (s.type === 'dhcp') return dhcpMessage(s);
  if (s.type === 'ntp') return ntpMessage(s);
  if (s.type === 'tls') return tlsMessage(s);
  return bytes(s.payload);
}
function portDefaults(s) {
  if (s.type === 'dns') return s.response ? [53, 53000] : [53000, 53];
  if (s.type === 'dhcp') return [2, 5].includes(s.message) ? [67, 68] : [68, 67];
  if (s.type === 'ntp') return s.mode === 4 ? [123, 54000] : [54000, 123];
  if (s.type === 'tls') return s.tlsKind === 'serverHello' ? [443, 55000] : [55000, 443];
  return [50000, 8080];
}
function tcpFlags(s) { return s.flags || (s.type === 'tcp' ? 'A' : 'PA'); }
function isTCP(s) { return ['tcp', 'tls'].includes(s.type) || s.type === 'dns' && s.transport === 'tcp'; }
function tcpDirection(s) {
  const e = endpoints(s), ports = portDefaults(s);
  return {from:`${e.src}|${s.sport ?? ports[0]}`, to:`${e.dst}|${s.dport ?? ports[1]}`};
}
function sequenceOffset(key) {
  // The authored range is capped at 24 bits; this range cannot overflow uint32.
  return 0x10000000 + hash32(key) % 0xc0000000;
}
function tcpOptions(s) {
  if (s.tcpOptions === false || tcpFlags(s).includes('R')) return Buffer.alloc(0);
  const flags = tcpFlags(s), syn = flags.includes('S'), settings = s.tcpOptions || {};
  const options = [];
  if (syn) {
    if (settings.mss !== false) options.push(cat(Buffer.from([2, 4]), u16(settings.mss ?? (endpoints(s).v6 ? 1440 : 1460))));
    if (settings.sackPermitted !== false && s._sackAllowed !== false) options.push(Buffer.from([4, 2]));
  }
  const timestamp = s._tcpTimestamp || (!s._tcpPrepared && syn && !flags.includes('A') && s.timestamps !== false
    ? {value:hash32(tcpDirection(s).from) % 0x70000000 + 100000, echo:0} : null);
  if (timestamp) {
    if (!syn) options.push(Buffer.from([1, 1]));
    options.push(cat(Buffer.from([8, 10]), u32(timestamp.value), u32(timestamp.echo)));
  }
  if (syn && settings.windowScale !== false && s._scaleAllowed !== false) {
    const scale = settings.windowScale ?? 7;
    if (!Number.isInteger(scale) || scale < 0 || scale > 14) throw new Error('TCP Window Scale must be an integer from 0 to 14');
    options.push(Buffer.from([1, 3, 3, scale]));
  }
  let result = cat(...options);
  if (result.length % 4) result = cat(result, Buffer.alloc(4 - result.length % 4, 1));
  return result;
}
function prepareTCP(specs) {
  const flows = new Map();
  for (const s of specs.filter(isTCP)) {
    const d = tcpDirection(s), key = [d.from, d.to].sort().join('~');
    if (!flows.has(key)) flows.set(key, {directions:new Map(), offers:new Map(), latest:new Map(), negotiated:false});
    const f = flows.get(key);
    for (const [endpoint, value] of [[d.from, s.seq ?? 1], ...(tcpFlags(s).includes('A') ? [[d.to, s.ack ?? 1]] : [])]) {
      const eligible = s.rawSequence !== true && Number.isInteger(value) && value >= 0 && value <= 0xffffff;
      f.directions.set(endpoint, (f.directions.get(endpoint) ?? true) && eligible);
    }
  }
  return specs.map((s, index) => {
    if (!isTCP(s)) return s;
    const d = tcpDirection(s), f = flows.get([d.from, d.to].sort().join('~')), flags = tcpFlags(s);
    const syn = flags.includes('S'), ack = flags.includes('A'), settings = s.tcpOptions || {};
    if (syn && !ack) { f.negotiated = false; f.offers.delete(d.to); f.latest.clear(); }
    const other = f.offers.get(d.to);
    const offered = {timestamp:s.tcpOptions !== false && s.timestamps !== false, scale:s.tcpOptions !== false && settings.windowScale !== false, sack:s.tcpOptions !== false && settings.sackPermitted !== false};
    if (syn && ack) { offered.timestamp &&= !!other?.timestamp; offered.scale &&= !!other?.scale; offered.sack &&= !!other?.sack; }
    if (syn) { f.offers.set(d.from, offered); if (ack) f.negotiated = offered.timestamp && !!other?.timestamp; }
    const wantsTimestamp = !flags.includes('R') && s.tcpOptions !== false && (syn ? offered.timestamp : f.negotiated);
    let timestamp = null;
    if (wantsTimestamp) {
      const time = s.time ?? index * .01;
      const value = (hash32(d.from) % 0x70000000 + 100000 + Math.round(time * 1000)) >>> 0;
      timestamp = {value, echo:ack ? f.latest.get(d.to) ?? 0 : 0};
      f.latest.set(d.from, value);
    }
    // A reset rejecting a SYN uses SEQ=0, not the peer's nonexistent ISN.
    const seq = s.seq ?? 1, keepResetZero = flags.includes('R') && seq === 0 && !f.offers.has(d.from);
    return {...s, seq:seq + (f.directions.get(d.from) && !keepResetZero ? sequenceOffset(d.from + '>' + d.to) : 0),
      ack:ack ? (s.ack ?? 1) + (f.directions.get(d.to) ? sequenceOffset(d.to + '>' + d.from) : 0) : 0,
      _tcpPrepared:true, _tcpTimestamp:timestamp, _scaleAllowed:!syn || offered.scale, _sackAllowed:!syn || offered.sack};
  });
}
function transport(s, protocol) {
  const payload = transportPayload(s); const ports = portDefaults(s);
  const options = protocol === 6 ? tcpOptions(s) : Buffer.alloc(0);
  const h = Buffer.alloc(protocol === 6 ? 20 + options.length : 8);
  h.writeUInt16BE(s.sport ?? ports[0], 0); h.writeUInt16BE(s.dport ?? ports[1], 2);
  if (protocol === 6) {
    const flags = tcpFlags(s);
    h.writeUInt32BE((s.seq ?? 1) >>> 0, 4); h.writeUInt32BE((s.ack ?? (flags.includes('A') ? 1 : 0)) >>> 0, 8); h[12] = (h.length / 4) << 4;
    h[13] = (flags.includes('F') ? 1 : 0) | (flags.includes('S') ? 2 : 0) | (flags.includes('R') ? 4 : 0) | (flags.includes('P') ? 8 : 0) | (flags.includes('A') ? 16 : 0);
    h.writeUInt16BE(s.window ?? 64240, 14);
    options.copy(h, 20);
  } else h.writeUInt16BE(h.length + payload.length, 4);
  const result = cat(h, payload);
  const c = checksum(cat(pseudo(s, protocol, result.length), result));
  result.writeUInt16BE(c || 0xffff, protocol === 6 ? 16 : 6);
  return result;
}
function icmpMessage(s, index) {
  const h = Buffer.alloc(8); h[0] = s.icmpType ?? 8; h[1] = s.code ?? 0;
  let payload;
  if ([3, 11].includes(h[0])) {
    const q = {...s.quoted, type:'udp', src:s.quoted?.src || DEFAULT_IP, dst:s.quoted?.dst || '198.51.100.20', sport:s.quoted?.sport ?? 53000, dport:s.quoted?.dport ?? 33434, ttl:s.quoted?.ttl ?? 1, payload:s.quoted?.payload || ''};
    // ICMP includes the original IP header and the first 8 bytes of its payload.
    // Build the original in full before truncation so its lengths/checksum remain exact.
    payload = network(q, 17, transport(q, 17), s.quoted?.frameIndex ?? index).subarray(0, 28);
  } else {
    h.writeUInt16BE(s.icmpId ?? 0x1001, 4); h.writeUInt16BE(s.icmpSeq ?? 1, 6); payload = bytes(s.payload ?? ECHO_PAYLOAD);
  }
  const b = cat(h, payload); b.writeUInt16BE(checksum(b), 2); return b;
}
function icmp6Message(s) {
  const type = s.icmpType ?? 128; const h = Buffer.alloc(4); h[0] = type; h[1] = s.code ?? 0;
  let body;
  if ([128, 129].includes(type)) body = cat(u16(s.icmpId ?? 0x1001), u16(s.icmpSeq ?? 1), bytes(s.payload ?? ECHO_PAYLOAD));
  else if ([135, 136].includes(type)) {
    const flags = type === 136 ? (s.router ? 0x80000000 : 0) | (s.solicited === false ? 0 : 0x40000000) | (s.override === false ? 0 : 0x20000000) : 0;
    body = cat(u32(flags), ip6(s.target || endpoints(s).dst), Buffer.from([type === 135 ? 1 : 2, 1]), mac(s.smac || DEFAULT_MAC));
  } else if (type === 134) {
    const ra = Buffer.alloc(12); ra[0] = 64; ra.writeUInt16BE(s.routerLifetime ?? 1800, 2);
    const opts = [cat(Buffer.from([1, 1]), mac(s.smac || DEFAULT_MAC))];
    if (s.prefix) {
      const [prefix, bits = '64'] = s.prefix.split('/'); const p = Buffer.alloc(32); p[0] = 3; p[1] = 4; p[2] = Number(bits); p[3] = 0xc0;
      p.writeUInt32BE(3600, 4); p.writeUInt32BE(1800, 8); ip6(prefix).copy(p, 16); opts.push(p);
    }
    body = cat(ra, ...opts);
  } else throw new Error(`Unsupported ICMPv6 type: ${type}`);
  const b = cat(h, body); b.writeUInt16BE(checksum(cat(pseudo({...s, ipv6:true}, 58, b.length), b)), 2); return b;
}
function frameBytes(s, index = 0) {
  if (isTCP(s) && !s._tcpPrepared) s = prepareTCP([s])[0];
  let body, ethertype; let smac = s.smac || DEFAULT_MAC, dmac = s.dmac || ROUTER_MAC;
  if (s.type === 'arp') {
    if ((s.op ?? 1) === 2 && !s.hwdst && !s.dmac) throw new Error('ARP reply requires hwdst or dmac for its target MAC');
    const a = Buffer.alloc(28); a.writeUInt16BE(1); a.writeUInt16BE(0x0800, 2); a[4] = 6; a[5] = 4; a.writeUInt16BE(s.op ?? 1, 6);
    smac = s.smac || s.hwsrc || DEFAULT_MAC; dmac = s.dmac || ((s.op ?? 1) === 1 ? 'ff:ff:ff:ff:ff:ff' : s.hwdst || ROUTER_MAC);
    mac(s.hwsrc || smac).copy(a, 8); ip4(s.psrc || DEFAULT_IP).copy(a, 14); mac(s.hwdst || ((s.op ?? 1) === 1 ? '00:00:00:00:00:00' : dmac)).copy(a, 18); ip4(s.pdst || ROUTER_IP).copy(a, 24);
    body = a; ethertype = 0x0806;
  } else {
    let spec = s;
    if (s.type === 'dhcp') {
      const reply = [2, 5].includes(s.message);
      spec = {...s, src:s.src || (reply ? s.server || ROUTER_IP : '0.0.0.0'), dst:s.dst || '255.255.255.255'};
      smac = s.smac || (reply ? ROUTER_MAC : s.clientMac || DEFAULT_MAC); dmac = s.dmac || 'ff:ff:ff:ff:ff:ff';
    }
    let proto, l4;
    if (s.type === 'icmp') { proto = 1; l4 = icmpMessage(spec, index); }
    else if (s.type === 'icmp6') { proto = 58; spec = {...spec, ipv6:true}; l4 = icmp6Message(spec); }
    else if (['tcp', 'tls'].includes(s.type) || s.type === 'dns' && s.transport === 'tcp') { proto = 6; l4 = transport(spec, proto); }
    else if (['udp', 'dns', 'dhcp', 'ntp'].includes(s.type)) { proto = 17; l4 = transport(spec, proto); }
    else throw new Error(`Unsupported packet type: ${s.type}`);
    body = network(spec, proto, l4, index); ethertype = endpoints(spec).v6 ? 0x86dd : 0x0800;
    if (!s.dmac && endpoints(spec).v6 && endpoints(spec).dst.toLowerCase().startsWith('ff')) dmac = '33:33:' + ip6(endpoints(spec).dst).subarray(12).toString('hex').match(/../g).join(':');
    if (!s.dmac && endpoints(spec).dst === '255.255.255.255') dmac = 'ff:ff:ff:ff:ff:ff';
    if (!s.dmac && !endpoints(spec).v6) {
      const destination = ip4(endpoints(spec).dst);
      if (destination[0] >= 224 && destination[0] <= 239) dmac = Buffer.from([1, 0, 0x5e, destination[1] & 0x7f, destination[2], destination[3]]).toString('hex').match(/../g).join(':');
    }
  }
  let frame = cat(mac(dmac), mac(smac), u16(ethertype), body);
  // Ethernet minimum is 60 bytes excluding the FCS; PCAP convention omits the FCS.
  if (s.padEthernet !== false && frame.length < 60) frame = cat(frame, Buffer.alloc(60 - frame.length));
  return frame;
}
function pcapBytes(specs) {
  const global = Buffer.alloc(24); global.writeUInt32LE(0xa1b2c3d4); global.writeUInt16LE(2, 4); global.writeUInt16LE(4, 6); global.writeUInt32LE(65535, 16); global.writeUInt32LE(1, 20);
  const frames = prepareTCP(specs).map(frameBytes);
  const records = frames.map((frame, i) => {
    const time = specs[i].time ?? i * .01;
    if (!Number.isFinite(time) || time < 0) throw new Error(`Invalid packet timestamp: ${time}`);
    const h = Buffer.alloc(16); const micros = Math.round(time * 1e6);
    h.writeUInt32LE(1767225600 + Math.floor(micros / 1e6)); h.writeUInt32LE(micros % 1e6, 4); h.writeUInt32LE(frame.length, 8); h.writeUInt32LE(frame.length, 12);
    return cat(h, frame);
  });
  return {pcap:cat(global, ...records), frames};
}
function printable(buf) {
  if (!buf.length) return '';
  const text = buf.toString('utf8');
  if ([...text].filter(c => c === '\ufffd' || c.charCodeAt(0) < 32 && !'\r\n\t'.includes(c)).length > text.length * .08) return '[バイナリデータ]\n' + buf.toString('hex').match(/.{1,32}/g).join('\n');
  return text.replace(/\r\n/g, '\n').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '·');
}
function reassemble(packets) {
  const groups = new Map();
  for (const p of packets) {
    const id = p.fields['tcp.stream']?.[0]; if (id === undefined) continue;
    p.stream = Number(id);
    if (!groups.has(id)) groups.set(id, []); groups.get(id).push(p);
  }
  return [...groups].map(([id, ps]) => {
    const formatEndpoint = (address, port) => `${address.includes(':') ? '[' + address + ']' : address}:${port}`;
    const endpoint = p => formatEndpoint(p.src,p.fields['tcp.srcport'][0]);
    const first = ps.find(p => p.fields['tcp.flags.syn']?.[0] && !p.fields['tcp.flags.ack']?.[0]) || ps[0];
    const client = endpoint(first), server = formatEndpoint(first.dst,first.fields['tcp.dstport'][0]);
    const chunks = [];
    for (const direction of [client, server]) {
      // Relative sequence numbers also keep a raw uint32 wrap inside a short
      // captured stream from sorting the tail before the head.
      const segments = ps.filter(p => endpoint(p) === direction && p.fields['tcp.payload']?.[0]).map(p => ({p, seq:Number(p.fields['tcp.seq']?.[0] ?? p.fields['tcp.seq_raw']?.[0]), data:Buffer.from(String(p.fields['tcp.payload'][0]).replace(/:/g,''), 'hex')})).sort((a,b) => a.seq - b.seq || a.p.number - b.p.number);
      let next = null; const pieces = []; let pending = []; const frameNumbers = [];
      const flush = () => { if (pending.length) { pieces.push(printable(cat(...pending))); pending = []; } };
      for (const seg of segments) {
        let data = seg.data;
        if (next !== null && seg.seq < next) data = data.subarray(Math.min(data.length, next - seg.seq));
        if (!data.length) continue;
        if (next !== null && seg.seq > next) { flush(); pieces.push(`\n[未収録 ${seg.seq - next} bytes]\n`); }
        pending.push(data); frameNumbers.push(seg.p.number);
        next = Math.max(next ?? seg.seq, seg.seq + seg.data.length);
      }
      flush();
      if (pieces.length) chunks.push({direction, frameNumbers, text:pieces.join('')});
    }
    return {id:Number(id), client, server, packetNumbers:ps.map(p=>p.number), segments:chunks.map(c=>({direction:c.direction === client ? 'client' : 'server', text:c.text, packetNumbers:c.frameNumbers, binary:c.text.startsWith('[バイナリデータ]')})), text:chunks.map(c => `${c.direction === client ? 'クライアント → サーバー' : 'サーバー → クライアント'}（方向別に再構成） [Frame ${c.frameNumbers.join(', ')}]\n${c.text}`).join('\n\n') || 'このストリームには、収録された TCP ペイロードがありません。'};
  });
}
function buildCapture(capture) {
  if (!capture || !Array.isArray(capture.packets) || !capture.packets.length) throw new Error('Capture requires packet specifications');
  const {pcap, frames} = pcapBytes(capture.packets);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pcaproom-build-'));
  try {
    const file = path.join(dir, 'capture.pcap'); fs.writeFileSync(file, pcap);
    let decoded;
    try {
      decoded = JSON.parse(execFileSync(process.env.PCAPROOM_PYTHON || '/usr/bin/python3', [path.join(__dirname, 'decode-pcap.py'), file, process.env.PCAPROOM_TSHARK || '/usr/local/bin/tshark'], {encoding:'utf8', maxBuffer:64 * 1024 * 1024}));
    } catch (e) { throw new Error(`Cannot decode capture ${capture.id}: install tshark (or set PCAPROOM_TSHARK). ${e.stderr?.toString() || e.message}`); }
    if (decoded.packets.length !== frames.length) throw new Error(`Decoded frame count mismatch for ${capture.id}`);
    const packets = decoded.packets.map((p, i) => ({...p, rawHex:frames[i].toString('hex')}));
    return {id:capture.id, title:capture.title, description:capture.description, pcapBase64:pcap.toString('base64'), packets, streams:reassemble(packets)};
  } finally { fs.rmSync(dir, {recursive:true, force:true}); }
}
module.exports = {buildCapture, transportPayload, frameBytes, pcapBytes};
