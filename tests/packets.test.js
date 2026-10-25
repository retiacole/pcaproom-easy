'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {buildCapture, transportPayload, pcapBytes, frameBytes} = require('../packet-tools');

function capture(id, packets) { return buildCapture({id, title:id, description:'Protocol fixture validation', packets}); }
function first(c,n,key) { return c.packets[n-1].fields[key]?.[0]; }
function healthy(c) {
  for (const p of c.packets) {
    assert.equal(p.fields['_ws.malformed'], undefined, `${c.id} frame ${p.number} malformed`);
    assert.equal(p.fields['_ws.expert.severity']?.includes(8388608) || false, false, `${c.id} frame ${p.number} error: ${p.info}`);
    assert.equal(p.rawHex.length / 2, p.length);
    assert.equal(p.fields['frame.number'][0], p.number);
    for (const [k,values] of Object.entries(p.fields)) if (k.endsWith('.checksum.status')) assert.ok(values.every(v => v === 1 || v === 2), `${c.id} ${k}: ${values}`);
  }
}

test('Ethernet, ARP, IPv4, ICMP echo/error, and UDP encode without errors', () => {
  const c = capture('foundation4', [
    {type:'arp',op:1,psrc:'10.0.0.10',pdst:'10.0.0.1'},
    {type:'arp',op:2,psrc:'10.0.0.1',pdst:'10.0.0.10',hwsrc:'02:00:00:00:00:01',hwdst:'02:00:00:00:00:10'},
    {type:'icmp',icmpType:8,icmpId:30,icmpSeq:7},
    {type:'icmp',icmpType:0,icmpId:30,icmpSeq:7,src:'10.0.0.1',dst:'10.0.0.10'},
    {type:'icmp',icmpType:3,code:3,quoted:{src:'10.0.0.10',dst:'10.0.0.1',sport:52000,dport:9999}},
    {type:'icmp',icmpType:11,code:0,quoted:{src:'10.0.0.10',dst:'198.51.100.20',sport:52001,dport:33434,ttl:1}},
    {type:'udp',sport:50000,dport:9000,payload:'hello'},
  ]);
  healthy(c);
  assert.equal(first(c,1,'eth.dst'),'ff:ff:ff:ff:ff:ff');
  assert.equal(first(c,2,'arp.src.proto_ipv4'),'10.0.0.1');
  assert.equal(first(c,3,'icmp.seq'),7);
  assert.equal(first(c,5,'icmp.type'),3);
  assert.equal(first(c,6,'icmp.type'),11);
  assert.equal(first(c,7,'udp.length'),13);
  const ip = c.packets[6].layers.flatMap(l=>l.fields).find(f=>f.key==='ip.src');
  assert.equal(Buffer.from(c.packets[6].rawHex,'hex').subarray(ip.offset,ip.offset+ip.length).join('.'),'10.0.0.10');
});

test('IPv6, ICMPv6 echo, NDP solicit/advertise, RA and UDP have correct checksum and fields', () => {
  const c = capture('foundation6', [
    {type:'icmp6',icmpType:128,src:'2001:db8::10',dst:'2001:db8::1'},
    {type:'icmp6',icmpType:129,src:'2001:db8::1',dst:'2001:db8::10'},
    {type:'icmp6',icmpType:135,src:'fe80::10',dst:'ff02::1:ff00:1',target:'fe80::1'},
    {type:'icmp6',icmpType:136,src:'fe80::1',dst:'fe80::10',target:'fe80::1',smac:'02:00:00:00:00:01'},
    {type:'icmp6',icmpType:134,src:'fe80::1',dst:'ff02::1',routerLifetime:900,prefix:'2001:db8:1::/64'},
    {type:'udp',ipv6:true,src:'2001:db8::10',dst:'2001:db8::1',sport:51000,dport:9000,payload:'IPv6 payload'},
  ]);
  healthy(c);
  assert.equal(first(c,3,'icmpv6.nd.ns.target_address'),'fe80::1');
  assert.equal(first(c,3,'ipv6.hlim'),255);
  assert.equal(first(c,3,'eth.dst'),'33:33:ff:00:00:01');
  assert.equal(first(c,4,'icmpv6.nd.na.target_address'),'fe80::1');
  assert.equal(first(c,5,'icmpv6.nd.ra.router_lifetime'),900);
  assert.equal(first(c,6,'ipv6.nxt'),17);
});

test('DNS UDP A/AAAA/NXDOMAIN and DNS TCP decode faithfully', () => {
  const q={type:'dns',name:'portal.test',transport:'tcp',seq:101,ack:201,sport:53002,dport:53};
  const c = capture('dns', [
    {type:'dns',name:'portal.test'},
    {type:'dns',name:'portal.test',response:true,src:'10.0.0.1',dst:'10.0.0.10',answers:['192.0.2.20']},
    {type:'dns',name:'portal.test',qtype:28,response:true,src:'10.0.0.1',dst:'10.0.0.10',answers:['2001:db8::20']},
    {type:'dns',name:'missing.test',response:true,rcode:3,src:'10.0.0.1',dst:'10.0.0.10'},
    {type:'tcp',sport:53002,dport:53,flags:'S',seq:100,ack:0},
    {type:'tcp',sport:53,dport:53002,src:'10.0.0.1',dst:'10.0.0.10',flags:'SA',seq:200,ack:101},
    {type:'tcp',sport:53002,dport:53,flags:'A',seq:101,ack:201},q,
    {...q,response:true,src:'10.0.0.1',dst:'10.0.0.10',sport:53,dport:53002,seq:201,ack:101+transportPayload(q).length,answers:['192.0.2.20']},
  ]);
  healthy(c);
  assert.equal(first(c,2,'dns.a'),'192.0.2.20');
  assert.equal(first(c,3,'dns.aaaa'),'2001:db8::20');
  assert.equal(first(c,4,'dns.flags.rcode'),3);
  assert.equal(first(c,8,'dns.qry.name'),'portal.test');
  assert.equal(first(c,9,'dns.a'),'192.0.2.20');
});

test('DHCP DORA and NTP request/response contain expected actual fields', () => {
  const settings={server:'10.0.0.1',router:'10.0.0.1',dns:'10.0.0.53',mask:'255.255.255.0'};
  const c = capture('configuration', [
    {type:'dhcp',message:1},{type:'dhcp',message:2,yiaddr:'10.0.0.10',...settings},
    {type:'dhcp',message:3,requested:'10.0.0.10',server:'10.0.0.1'},
    {type:'dhcp',message:5,yiaddr:'10.0.0.10',...settings},
    {type:'ntp',mode:3},{type:'ntp',mode:4,src:'10.0.0.1',dst:'10.0.0.10',stratum:2},
  ]);
  healthy(c);
  assert.deepEqual(c.packets.slice(0,4).map(p=>p.fields['dhcp.option.dhcp'][0]),[1,2,3,5]);
  assert.equal(first(c,1,'ip.src'),'0.0.0.0');
  assert.equal(first(c,4,'dhcp.ip.your'),'10.0.0.10');
  assert.equal(first(c,4,'dhcp.option.domain_name_server'),'10.0.0.53');
  assert.equal(first(c,5,'ntp.flags.mode'),3);
  assert.equal(first(c,6,'ntp.stratum'),2);
});

test('HTTP reassembles split body; follow stream deduplicates retransmission and respects sequence order', () => {
  const C={src:'10.0.0.10',dst:'198.51.100.20',sport:50000,dport:80}, S={src:C.dst,dst:C.src,sport:80,dport:50000};
  const req='GET /index.html HTTP/1.1\r\nHost: portal.test\r\n\r\n';
  const one='HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nHello', two=' world';
  const seg={type:'tcp',...S,flags:'PA',seq:2001,ack:1001+req.length,payload:one};
  const c=capture('http', [{type:'tcp',...C,flags:'S',seq:1000,ack:0},{type:'tcp',...S,flags:'SA',seq:2000,ack:1001},{type:'tcp',...C,flags:'A',seq:1001,ack:2001},{type:'tcp',...C,flags:'PA',seq:1001,ack:2001,payload:req},seg,{type:'tcp',...S,flags:'PA',seq:2001+one.length,ack:1001+req.length,payload:two},seg]);
  healthy(c);
  assert.equal(first(c,4,'http.request.method'),'GET');
  assert.equal(first(c,4,'http.host'),'portal.test');
  assert.equal(first(c,6,'http.response.code'),200);
  const field=c.packets[5].layers.flatMap(l=>l.fields).find(f=>f.key==='http.response.code');
  assert.equal(field.offset,undefined,'Reassembled data cannot use offsets in final raw frame');
  assert.match(c.streams[0].text,/Hello world/);
  assert.equal(c.streams[0].text.split('HTTP/1.1 200 OK').length,2);
});

test('TLS hello with optional SNI and opaque application-data fixtures are structurally valid', () => {
  const q={type:'tls',tlsKind:'clientHello',serverName:'portal.test',sport:55000,dport:443,seq:1001,ack:2001};
  const server={type:'tls',tlsKind:'serverHello',src:'10.0.0.1',dst:'10.0.0.10',sport:443,dport:55000,seq:2001,ack:1001+transportPayload(q).length};
  const c=capture('tls', [{type:'tcp',sport:55000,dport:443,flags:'S',seq:1000,ack:0},{type:'tcp',src:'10.0.0.1',dst:'10.0.0.10',sport:443,dport:55000,flags:'SA',seq:2000,ack:1001},{type:'tcp',sport:55000,dport:443,flags:'A',seq:1001,ack:2001},q,server,{type:'tls',tlsKind:'applicationData',src:'10.0.0.1',dst:'10.0.0.10',sport:443,dport:55000,seq:2001+transportPayload(server).length,ack:1001+transportPayload(q).length},{type:'tls',tlsKind:'clientHello',serverName:'',sport:55001,dport:443}]);
  healthy(c);
  assert.equal(first(c,4,'tls.handshake.extensions_server_name'),'portal.test');
  assert.equal(first(c,4,'tls.handshake.type'),1);
  assert.equal(first(c,5,'tls.handshake.type'),2);
  assert.equal(first(c,6,'tls.record.content_type'),23);
  assert.equal(first(c,7,'tls.handshake.extensions_server_name'),undefined);
});

test('directional TCP text follows sequence numbers when segments arrive out of order', () => {
  const base={type:'tcp',sport:51000,dport:9000};
  const c=capture('out-of-order',[
    {...base,flags:'S',seq:100,ack:0},
    {...base,flags:'PA',seq:104,ack:1,payload:'DEF'},
    {...base,flags:'PA',seq:101,ack:1,payload:'ABC'},
    {...base,flags:'PA',seq:104,ack:1,payload:'DEF'},
  ]);
  assert.equal(c.streams[0].segments[0].text,'ABCDEF');
  assert.equal(c.streams[0].segments[0].direction,'client');
});

test('PCAP is Ethernet with valid little-endian file header and minimum Ethernet frame length', () => {
  const {pcap,frames}=pcapBytes([{type:'arp',op:1,time:.123456}]);
  assert.equal(pcap.readUInt32LE(0),0xa1b2c3d4);
  assert.equal(pcap.readUInt32LE(20),1);
  assert.equal(pcap.readUInt32LE(28),123456);
  assert.equal(frames[0].length,60);
  assert.throws(()=>frameBytes({type:'unknown'}),/Unsupported/);
  const original={type:'udp',src:'10.0.0.10',dst:'192.0.2.20',sport:50000,dport:33434,ttl:1,payload:'probe-1'};
  const originalFrame=frameBytes(original,0);
  const errorFrame=frameBytes({type:'icmp',icmpType:11,quoted:{...original,frameIndex:0}},1);
  assert.deepEqual(errorFrame.subarray(42,70),originalFrame.subarray(14,42),'ICMP quotes retain original IPv4 and UDP headers byte for byte');
});
