'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {execFileSync}=require('node:child_process');
const {buildCapture}=require('../packet-tools');
const E=require('../src/engine');
const content=require('../content/realworld');
let decoded;
function captures(){return decoded ||= new Map(content.captures.map(c=>[c.id,buildCapture(c)]));}
function value(c,frame,key){return c.packets[frame-1].fields[key]?.[0];}

test('applied lessons use real, selectable fields and their official answers pass',()=>{
  assert.equal(content.chapters.length,2);
  assert.equal(content.lessons.length,6);
  for(const lesson of content.lessons){
    const c=captures().get(lesson.captureId);
    const filter=lesson.tasks.find(t=>t.kind==='filter')?.expectedFilter||'';
    for(const t of lesson.tasks){
      const entry={answer:t.answer,evidence:t.evidence||[]};
      assert.equal(E.gradeTask(t,entry,c,filter).correct,true,`${lesson.id}/${t.id}`);
      for(const evidence of t.evidence||[]){
        assert.ok(c.packets[evidence.frame-1].layers.some(layer=>layer.fields.some(f=>f.key===evidence.field)),`${lesson.id}: ${evidence.field} selectable`);
      }
    }
  }
});

test('TCP options, EDNS and DHCP examples carry the taught values in decoded bytes',()=>{
  const tcp=captures().get('realworld-tcp-options');
  assert.equal(value(tcp,1,'tcp.options.mss_val'),1460);
  assert.equal(value(tcp,1,'tcp.seq'),0);
  assert.ok(value(tcp,1,'tcp.seq_raw')>0xffffff);
  assert.ok(value(tcp,3,'tcp.options.timestamp.tsval')>0);
  const extra=captures().get('realworld-extra-records');
  assert.equal(value(extra,5,'dns.count.answers'),0);
  assert.equal(value(extra,5,'dns.count.add_rr'),1);
  assert.equal(value(extra,5,'dns.rr.udp_payload_size'),1232);
  assert.equal(value(extra,4,'dhcp.option.renewal_time_value'),1800);
  assert.equal(value(extra,4,'dhcp.option.rebinding_time_value'),3150);
});

test('time and padding comparison distinguishes a 54-byte sender record from a padded 60-byte frame',()=>{
  const c=captures().get('realworld-time-padding');
  assert.deepEqual(c.packets.map(p=>p.length),[54,60,54]);
  assert.equal(c.packets[1].timeDelta,.125);
  assert.equal(c.packets[1].timestampEpoch,1767225600.125);
  assert.equal(value(c,2,'eth.padding'),'000000000000');
  assert.equal(value(c,2,'tcp.len'),0);
  const filtered=E.filterPackets('frame.number >= 2',c.packets);
  assert.equal(filtered[0].timeDelta,.125,'Filtering must not replace the captured-frame delta with a displayed-row delta');
});

test('LAN investigation has 270 diverse background frames, dispersed targets and two distinct HTTP streams',()=>{
  const c=captures().get('realworld-lan');
  assert.equal(c.packets.length,284);
  assert.equal(c.packets.filter(p=>!p.fields['tcp']&&!p.fields['dns']).length,270);
  for(const protocol of ['ARP','MDNS','SSDP','ICMPv6','DHCP','NTP','DNS','TCP','HTTP']){
    assert.ok(c.packets.some(p=>p.protocol===protocol),`${protocol} background/target decoded`);
  }
  assert.deepEqual(c.streams.map(s=>s.id),[0,1]);
  assert.match(c.streams[0].text,/GET \/health HTTP\/1\.1/);
  assert.match(c.streams[1].text,/GET \/reports\/latest HTTP\/1\.1/);
  assert.match(c.streams[1].text,/404 Not Found/);
  assert.ok(c.streams[1].packetNumbers.at(-1)-c.streams[1].packetNumbers[0]>50,'Background traffic separates the target frames');
  assert.ok(c.packets.every((p,i)=>!i||p.time>c.packets[i-1].time));
  for(const p of c.packets){
    assert.equal(p.fields['_ws.malformed'],undefined,`Frame ${p.number} malformed`);
    assert.equal(p.fields['_ws.expert.severity']?.includes(8388608)||false,false,`Frame ${p.number} expert error`);
    for(const [key,values] of Object.entries(p.fields))if(key.endsWith('.checksum.status')){
      assert.ok(values.every(v=>v===1||v===2),`Frame ${p.number}: ${key}`);
    }
  }
});

test('DNS, stream and byte-search filters return the same frame numbers as real tshark',()=>{
  const c=captures().get('realworld-lan');
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'pcaproom-filter-oracle-'));
  try{
    const file=path.join(dir,'lan.pcap'),profile=path.join(dir,'profile');
    fs.mkdirSync(profile);fs.writeFileSync(file,Buffer.from(c.pcapBase64,'base64'));
    const env={...process.env,TZ:'UTC',LC_ALL:'C',WIRESHARK_CONFIG_DIR:profile,WIRESHARK_PLUGIN_DIR:path.join(profile,'plugins'),SSLKEYLOGFILE:''};
    delete env.WIRESHARK_DATA_DIR;
    for(const lesson of content.lessons.filter(l=>l.captureId===c.id)){
      const task=lesson.tasks.find(t=>t.kind==='filter'),filter=task.expectedFilter;
      const output=execFileSync(process.env.PCAPROOM_TSHARK||'/usr/local/bin/tshark',['-n','-2','-r',file,'-Y',filter,'-T','fields','-e','frame.number'],{encoding:'utf8',env});
      const actual=output.trim().split('\n').filter(Boolean).map(Number);
      assert.deepEqual(actual,task.answer,`${lesson.id}: tshark expected frames`);
      assert.deepEqual(E.filterPackets(filter,c.packets).map(p=>p.number),actual,`${lesson.id}: engine agrees with tshark`);
    }
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
