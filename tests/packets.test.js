'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {buildCapture, transportPayload, pcapBytes, frameBytes} = require('../packet-tools');
const E = require('../src/engine');

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

test('ICMP quoted UDP protocol filters match tshark without duplicating fields or detail layers', () => {
  const specs = require('../content/foundation').captures.filter(c => ['base-icmp-unreachable', 'base-icmp-ttl'].includes(c.id));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pcaproom-icmp-filter-'));
  try {
    const profile = path.join(dir, 'profile');
    fs.mkdirSync(profile);
    const env = {...process.env, TZ:'UTC', LC_ALL:'C', WIRESHARK_CONFIG_DIR:profile, WIRESHARK_PLUGIN_DIR:path.join(profile, 'plugins'), SSLKEYLOGFILE:''};
    delete env.WIRESHARK_DATA_DIR;
    for (const spec of specs) {
      const c = buildCapture(spec), file = path.join(dir, c.id + '.pcap');
      fs.writeFileSync(file, Buffer.from(c.pcapBase64, 'base64'));
      for (const [filter, expected] of [['udp', [1, 2]], ['icmp && udp', [2]]]) {
        const output = execFileSync(process.env.PCAPROOM_TSHARK || '/usr/local/bin/tshark', ['-n', '-2', '-r', file, '-Y', filter, '-T', 'fields', '-e', 'frame.number'], {encoding:'utf8', env});
        const actual = output.trim().split('\n').filter(Boolean).map(Number);
        assert.deepEqual(actual, expected, `${c.id}: tshark ${filter}`);
        assert.deepEqual(E.filterPackets(filter, c.packets).map(p => p.number), actual, `${c.id}: ${filter} agrees with tshark`);
      }
      const error = c.packets[1];
      assert.deepEqual(error.fields.udp, [true]);
      assert.equal(error.fields['ip.src'].length, 2, 'Outer and quoted IPv4 sources occur once each');
      assert.equal(error.fields['udp.srcport'].length, 1, 'Quoted UDP fields are not extracted twice');
      assert.equal(error.layers.filter(l => l.name === 'ip').length, 1, 'Keep quoted IP details under ICMP');
      assert.equal(error.layers.some(l => l.name === 'udp'), false, 'Do not add a separate quoted UDP layer');
      assert.equal(error.layers.find(l => l.name === 'icmp').fields.filter(f => f.key === 'udp.srcport').length, 1);
    }
  } finally { fs.rmSync(dir, {recursive:true, force:true}); }
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

function tcpConversation(clientOptions = {}, serverOptions = {}) {
  const c = {type:'tcp',src:'10.0.0.10',dst:'198.51.100.20',sport:50123,dport:8080};
  const s = {type:'tcp',src:c.dst,dst:c.src,sport:c.dport,dport:c.sport};
  return [
    {...c,flags:'S',seq:1000,ack:0,...clientOptions},
    {...s,flags:'SA',seq:9000,ack:1001,...serverOptions},
    {...c,flags:'A',seq:1001,ack:9001},
    {...c,flags:'PA',seq:1001,ack:9001,payload:'abc'},
    {...s,flags:'A',seq:9001,ack:1004},
    {...c,flags:'FA',seq:1004,ack:9001},
    {...s,flags:'RA',seq:9001,ack:1005},
  ];
}

test('TCP options decode with valid checksums; timestamps echo negotiated values and exclude resets', () => {
  const c = capture('tcp-options', tcpConversation());
  healthy(c);
  for (const n of [1,2]) {
    assert.equal(first(c,n,'tcp.options.mss_val'),1460);
    assert.equal(first(c,n,'tcp.options.wscale.multiplier'),128);
    assert.ok(first(c,n,'tcp.options.sack_perm'));
    assert.equal(first(c,n,'tcp.hdr_len'),40);
  }
  assert.equal(first(c,1,'tcp.options.timestamp.tsecr'),0);
  assert.equal(first(c,1,'tcp.ack_raw'),0,'Initial SYN does not carry a shifted ACK');
  assert.equal(first(c,2,'tcp.options.timestamp.tsecr'),first(c,1,'tcp.options.timestamp.tsval'));
  assert.equal(first(c,3,'tcp.options.timestamp.tsecr'),first(c,2,'tcp.options.timestamp.tsval'));
  assert.equal(first(c,5,'tcp.options.timestamp.tsecr'),first(c,4,'tcp.options.timestamp.tsval'));
  for (const n of [3,4,5,6]) {
    assert.equal(first(c,n,'tcp.hdr_len'),32);
    assert.ok(first(c,n,'tcp.options.timestamp.tsval'));
    assert.equal(first(c,n,'tcp.options.mss_val'),undefined);
  }
  assert.equal(first(c,7,'tcp.options.timestamp.tsval'),undefined);
  assert.equal(first(c,7,'tcp.hdr_len'),20);
});

test('TCP timestamps require both handshake offers; minimal fixtures and disabled options remain possible', () => {
  const specs = [
    ...tcpConversation({timestamps:false}).map(p=>({...p,sport:p.sport === 50123 ? 50124 : p.sport,dport:p.dport === 50123 ? 50124 : p.dport})),
    ...tcpConversation({}, {timestamps:false}),
    ...tcpConversation({tcpOptions:false}, {tcpOptions:false}).map(p=>({...p,sport:p.sport === 50123 ? 50125 : p.sport,dport:p.dport === 50123 ? 50125 : p.dport})),
  ];
  const c = capture('tcp-negotiation', specs);
  healthy(c);
  for (let n=1;n<=21;n++) {
    if (n===8) assert.ok(first(c,n,'tcp.options.timestamp.tsval'),'Client may offer TS even when the server declines');
    else assert.equal(first(c,n,'tcp.options.timestamp.tsval'),undefined,`No TS in frame ${n}`);
  }
  assert.equal(first(c,15,'tcp.hdr_len'),20);
  assert.equal(first(c,16,'tcp.hdr_len'),20);
  assert.equal(first(c,16,'tcp.options.wscale.shift'),undefined);
  const noHandshake = capture('tcp-midstream',[{type:'tcp',flags:'PA',payload:'abc'}]);
  assert.equal(first(noHandshake,1,'tcp.options.timestamp.tsval'),undefined,'Do not invent unseen timestamp negotiation');
});

test('deterministic 32-bit sequence translation preserves ACKs, relative counters, reset semantics and raw-wrap streams', () => {
  const specs=tcpConversation(), c=capture('tcp-sequences',specs);
  assert.ok(first(c,1,'tcp.seq_raw')>0xffffff);
  assert.ok(first(c,2,'tcp.seq_raw')>0xffffff);
  assert.notEqual(first(c,1,'tcp.seq_raw'),first(c,2,'tcp.seq_raw'));
  assert.equal(first(c,1,'tcp.seq'),0);
  assert.equal(first(c,2,'tcp.ack_raw'),first(c,1,'tcp.seq_raw')+1);
  assert.equal(first(c,5,'tcp.ack_raw'),first(c,1,'tcp.seq_raw')+4);
  assert.equal(first(c,5,'tcp.ack'),4);
  assert.deepEqual(pcapBytes(specs).pcap,pcapBytes(specs).pcap);
  assert.equal(specs[0].seq,1000,'Building does not mutate authored specs');
  const rejected=capture('tcp-reset',[specs[0],{...specs[1],flags:'RA',seq:0}]);
  assert.equal(first(rejected,2,'tcp.seq_raw'),0);
  assert.equal(first(rejected,2,'tcp.ack_raw'),first(rejected,1,'tcp.seq_raw')+1);
  const nearLimit=[...tcpConversation()].slice(0,3).map(p=>({...p,seq:p.seq+0xff0000,ack:p.ack ? p.ack+0xff0000 : 0}));
  const limitCapture=capture('tcp-offset-limit',nearLimit);
  assert.equal(first(limitCapture,3,'tcp.seq_raw'),first(limitCapture,1,'tcp.seq_raw')+1,'Small counters cannot wrap after translation');
  const raw={type:'tcp',sport:50126,dport:8080,rawSequence:true,tcpOptions:false};
  const wrapped=capture('tcp-raw-wrap',[
    {...raw,flags:'S',seq:0xfffffffd,ack:0},
    {...raw,flags:'PA',seq:0xfffffffe,ack:1,payload:'ABCD'},
    {...raw,flags:'PA',seq:2,ack:1,payload:'EF'},
  ]);
  assert.equal(first(wrapped,1,'tcp.seq_raw'),0xfffffffd);
  assert.equal(wrapped.streams[0].segments[0].text,'ABCDEF');
});

test('EDNS0 is additional metadata, supports opt-out, and leaves DNS-over-TCP lengths exact', () => {
  const base={type:'dns',name:'portal.test'}, c=capture('edns',[
    base,{...base,response:true,answers:['192.0.2.20'],src:'10.0.0.1',dst:'10.0.0.10'},
    {...base,sport:5353,dport:5353,dst:'224.0.0.251',dnsId:0,dnsFlags:0,edns:false},
    {...base,response:true,answers:['10.0.0.20'],src:'10.0.0.20',sport:5353,dport:5353,dst:'224.0.0.251',dnsId:0,dnsFlags:0x8400,dnsQuestion:false,edns:false},
  ]);
  healthy(c);
  assert.equal(first(c,1,'dns.count.answers'),0);
  assert.equal(first(c,1,'dns.count.add_rr'),1);
  assert.equal(first(c,1,'dns.rr.udp_payload_size'),1232);
  assert.equal(first(c,2,'dns.count.answers'),1);
  assert.equal(first(c,2,'dns.count.add_rr'),1);
  assert.equal(first(c,3,'dns.count.add_rr'),0);
  assert.equal(first(c,3,'dns.flags'),0,'mDNS query does not request recursion');
  assert.equal(first(c,3,'dns.resp.edns0_version'),undefined);
  assert.equal(first(c,4,'dns.count.queries'),0);
  assert.equal(first(c,4,'dns.count.answers'),1);
  assert.equal(first(c,4,'dns.resp.name'),'portal.test');
  assert.equal(first(c,4,'dns.a'),'10.0.0.20');
  const tcp=transportPayload({...base,transport:'tcp'}), udp=transportPayload(base);
  assert.equal(tcp.readUInt16BE(0),udp.length);
  assert.deepEqual(tcp.subarray(2),udp);
  assert.equal(transportPayload({...base,edns:false}).length,udp.length-11);
});

test('DHCP client identity and lease timers are realistic, configurable and internally consistent', () => {
  const c=capture('dhcp-options',[
    {type:'dhcp',message:1,clientMac:'02:00:00:00:00:42',hostName:'training-42'},
    {type:'dhcp',message:5,server:'10.0.0.1',yiaddr:'10.0.0.42'},
    {type:'dhcp',message:1,dhcpOptions:false},
    {type:'dhcp',message:5,server:'10.0.0.1',yiaddr:'10.0.0.42',leaseTime:7200},
  ]);
  healthy(c);
  for (const code of [61,12,60,57]) assert.ok(c.packets[0].fields['dhcp.option.type'].includes(code));
  assert.equal(first(c,1,'dhcp.option.hostname'),'training-42');
  assert.equal(first(c,1,'dhcp.option.dhcp_max_message_size'),1500);
  assert.ok(c.packets[0].fields['dhcp.option.value'].includes('01020000000042'));
  assert.equal(first(c,2,'dhcp.option.ip_address_lease_time'),3600);
  assert.equal(first(c,2,'dhcp.option.renewal_time_value'),1800);
  assert.equal(first(c,2,'dhcp.option.rebinding_time_value'),3150);
  assert.equal(first(c,3,'dhcp.option.hostname'),undefined);
  assert.equal(first(c,4,'dhcp.option.renewal_time_value'),3600);
  assert.equal(first(c,4,'dhcp.option.rebinding_time_value'),6300);
  assert.throws(()=>transportPayload({type:'dhcp',message:5,renewalTime:3500,rebindingTime:3100}),/renewal < rebinding/);
});

test('multicast MACs, router NA flags, ARP fallback, echo payload and sender capture padding match packet semantics', () => {
  const c=capture('link-details',[
    {type:'udp',dst:'224.0.0.251',sport:50000,dport:9000},
    {type:'udp',dst:'239.255.255.250',sport:50000,dport:9000},
    {type:'icmp6',icmpType:136,src:'fe80::1',dst:'fe80::10',target:'fe80::1',smac:'02:00:00:00:00:01',router:true},
    {type:'icmp'},
    {type:'arp',op:2,hwdst:'02:00:00:00:00:42'},
    {type:'arp',op:2,dmac:'02:00:00:00:00:43'},
    {type:'tcp',tcpOptions:false,padEthernet:false},
    {type:'tcp',tcpOptions:false},
  ]);
  healthy(c);
  assert.equal(first(c,1,'eth.dst'),'01:00:5e:00:00:fb');
  assert.equal(first(c,2,'eth.dst'),'01:00:5e:7f:ff:fa');
  assert.equal(first(c,3,'icmpv6.nd.na.flag'),0xe0000000);
  assert.equal(first(c,4,'data.len'),32);
  assert.equal(Buffer.from(first(c,4,'icmp.data'),'hex').toString(),'abcdefghijklmnopqrstuvwabcdefghi');
  assert.equal(first(c,5,'eth.dst'),first(c,5,'arp.dst.hw_mac'));
  assert.equal(first(c,6,'eth.dst'),first(c,6,'arp.dst.hw_mac'));
  assert.equal(c.packets[6].length,54);
  assert.equal(c.packets[7].length,60);
  assert.throws(()=>frameBytes({type:'arp',op:2}),/requires hwdst or dmac/);
});

test('decoded absolute/delta timestamps come from PCAP, and builds are identical across host timezones/locales', () => {
  const c=capture('timestamp-data',[{type:'udp',time:.123456},{type:'udp',time:.145678}]);
  assert.equal(c.packets[0].timestampEpoch,1767225600.123456);
  assert.equal(c.packets[0].time,0);
  assert.equal(c.packets[0].timeDelta,0);
  assert.equal(c.packets[1].timeDelta,.022222);
  assert.deepEqual(c.packets[1].fields['frame.time_delta'],[.022222]);
  const script="const {buildCapture}=require('./packet-tools');process.stdout.write(JSON.stringify(buildCapture({id:'zone',title:'Zone fixture',packets:[{type:'udp',time:.123456},{type:'tls',tlsKind:'clientHello',serverName:'portal.test',time:1.234567}]})));";
  const build = (TZ,LC_ALL) => execFileSync(process.execPath,['-e',script],{cwd:path.join(__dirname,'..'),env:{...process.env,TZ,LC_ALL},encoding:'utf8'});
  const tokyo=build('Asia/Tokyo','ja_JP.UTF-8'), newYork=build('America/New_York','en_US.UTF-8');
  assert.equal(tokyo,newYork,'PCAP, tshark fields, display strings and streams are byte-identical');
  assert.match(tokyo,/UTC/);
  assert.doesNotMatch(tokyo,/JST|EST|EDT/);
});
