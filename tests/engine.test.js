'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const E=require('../src/engine');
const fixtures=[
 {number:1,layers:[{name:'ip'},{name:'udp'},{name:'dns'}],fields:{'frame.number':[1],'ip.src':['10.0.0.10'],'ip.dst':['10.0.0.53'],'udp.srcport':[53000],'udp.dstport':[53],'dns.qry.name':['portal.test'],'dns.flags.response':[0],'eth.src':['02:00:00:00:00:aa']}},
 {number:2,layers:[{name:'ip'},{name:'udp'},{name:'dns'}],fields:{'frame.number':[2],'ip.src':['10.0.0.53'],'ip.dst':['10.0.0.10'],'udp.srcport':[53],'udp.dstport':[53000],'dns.qry.name':['portal.test'],'dns.flags.response':[1],'dns.a':['192.0.2.20']}},
 {number:3,layers:[{name:'ip'},{name:'tcp'}],fields:{'frame.number':[3],'ip.src':['10.0.0.10'],'ip.dst':['192.0.2.20'],'tcp.srcport':[51000],'tcp.dstport':[80],'tcp.flags.syn':[1],'tcp.flags.ack':[0]}},
 {number:4,layers:[{name:'ipv6'},{name:'tcp'},{name:'http'}],fields:{'frame.number':[4],'ipv6.src':['2001:db8::10'],'ipv6.dst':['2001:db8::20'],'tcp.srcport':[51001],'tcp.dstport':[80],'tcp.flags.syn':[0],'tcp.flags.ack':[true],'http.host':['portal.test'],'http.request.uri':['/guide']}},
 {number:5,layers:[{name:'ip'},{name:'udp'},{name:'dhcp'}],fields:{'frame.number':[5],'ip.src':['0.0.0.0'],'ip.dst':['255.255.255.255'],'udp.srcport':[68],'udp.dstport':[67],'dhcp.option.dhcp':[1]}},
];
const ids=query=>E.filterPackets(query,fixtures).map(p=>p.number);

test('frame contains matches case-sensitive UTF-8 captured bytes at byte boundaries',()=>{
 const packets=[{number:1,rawHex:Buffer.from('GET /こんにちは HTTP/1.1').toString('hex')},{number:2,rawHex:'04745540'},{number:3,rawHex:Buffer.from('get').toString('hex'),fields:{'http.request.method':['GET']}}];
 const run=q=>E.filterPackets(q,packets).map(p=>p.number);
 assert.deepEqual(run('frame contains "GET"'),[1]);
 assert.deepEqual(run('frame contains "こんにちは"'),[1]);
 assert.deepEqual(run('frame contains "get"'),[3]);
 assert.throws(()=>run('frame contains GET'),E.FilterError);
 assert.throws(()=>run('frame contains ""'),E.FilterError);
});

test('time formats use UTC and captured delta rather than filtered previous row',()=>{
 const p={time:0.125,timestampEpoch:1767225600.125,timeDelta:0.005};
 assert.equal(E.formatTime(p,'relative'),'0.125000');
 assert.equal(E.formatTime(p,'utc'),'2026-01-01 00:00:00.125000');
 assert.equal(E.formatTime(p,'delta'),'0.005000');
});

test('protocol, endpoint aliases, conjunction/disjunction, precedence and parentheses work',()=>{
 assert.deepEqual(ids('dns'),[1,2]);
 assert.deepEqual(ids('ip.addr == 10.0.0.10'),[1,2,3]);
 assert.deepEqual(ids('dns && ip.src == 10.0.0.10'),[1]);
 assert.deepEqual(ids('dns and ip.dst == 10.0.0.10'),[2]);
 assert.deepEqual(ids('udp.port == 53'),[1,2]);
 assert.deepEqual(ids('tcp.port == 80'),[3,4]);
 assert.deepEqual(ids('bootp'),[5]);
 assert.deepEqual(ids('dns || tcp && ip'),[1,2,3]);
 assert.deepEqual(ids('(dns || tcp) && ip'),[1,2,3]);
 assert.deepEqual(ids('!(dns || tcp)'),[5]);
 assert.deepEqual(ids('not dns and udp'),[5]);
});

test('numeric and boolean scalar comparisons, contains and != use Wireshark-style all semantics',()=>{
 assert.deepEqual(ids('tcp.flags.syn == 1'),[3]);
 assert.deepEqual(ids('tcp.flags.syn == true'),[3]);
 assert.deepEqual(ids('tcp.flags.ack == false'),[3]);
 assert.deepEqual(ids('tcp.flags.ack == 1'),[4]);
 assert.deepEqual(ids('tcp.port != 80'),[]);
 assert.deepEqual(ids('ip.addr != 10.0.0.10'),[5]);
 assert.deepEqual(ids('frame.number >= 3 && frame.number < 5'),[3,4]);
 assert.deepEqual(ids('udp.dstport == 0x35'),[1]);
 assert.deepEqual(ids('http.host contains "portal"'),[4]);
 assert.deepEqual(ids('dns.qry.name == "portal.test"'),[1,2]);
});

test('IPv6 spelling and MAC case do not change address comparison semantics',()=>{
 assert.deepEqual(ids('ipv6.src == 2001:0DB8:0000:0000:0000:0000:0000:0010'),[4]);
 assert.deepEqual(ids('ipv6.addr == 2001:db8::20'),[4]);
 assert.deepEqual(ids('eth.src == 02:00:00:00:00:AA'),[1]);
});

test('malformed or unsupported filters are rejected instead of silently matching nothing',()=>{
 for(const q of ['missing','dns &&','dns tcp','(dns','dns)','ip.src = 10.0.0.10','dns.qry.name == "unterminated','frame.number ==','ip.src == ==','tcp.port == !','tcp.port == >=','tcp.port == banana','tcp.port matches "80"','tcp.port in {80}','dns || || tcp'])assert.throws(()=>E.compileFilter(q,fixtures),E.FilterError,q);
 assert.throws(()=>E.compileFilter('x'.repeat(2001),fixtures),E.FilterError);
});

test('text normalization accepts intended number, MAC, IPv6, case and full-width variants',()=>{
 assert.equal(E.normalize(' ２００ ','number'),'200');
 assert.equal(E.normalize('0200.0000.00AA','mac'),E.normalize('02:00:00:00:00:aa','mac'));
 assert.equal(E.normalize('2001:0DB8:0:0:0:0:0:10','ip'),E.normalize('2001:db8::10','ip'));
 assert.equal(E.normalize('  PORTAL.TEST  '),'portal.test');
});

test('evidence grading requires the right frame and field, rejects extra unrelated evidence and supports all',()=>{
 const cap={packets:fixtures};
 const task={kind:'text',answer:'10.0.0.10',evidence:[{frame:1,field:'ip.src'},{frame:2,field:'ip.dst'}]};
 assert.equal(E.gradeTask(task,{answer:'10.0.0.10'},cap).correct,false);
 assert.equal(E.gradeTask(task,{answer:'10.0.0.10',evidence:[{frame:1,field:'ip.src'}]},cap).correct,true);
 assert.equal(E.gradeTask(task,{answer:'10.0.0.10',evidence:[{frame:2,field:'ip.src'}]},cap).correct,false);
 assert.equal(E.gradeTask(task,{answer:'10.0.0.10',evidence:[{frame:1,field:'ip.src'},{frame:1,field:'frame.number'}]},cap).correct,false);
 assert.equal(E.gradeTask({...task,evidenceMode:'all'},{answer:'10.0.0.10',evidence:[{frame:1,field:'ip.src'}]},cap).correct,false);
 assert.equal(E.gradeTask({...task,evidenceMode:'all'},{answer:'10.0.0.10',evidence:task.evidence},cap).correct,true);
 assert.equal(E.gradeTask(task,{answer:'wrong',evidence:task.evidence},cap).correct,false);
});

test('packet/order tasks and equivalent filters grade by actual results',()=>{
 const cap={packets:fixtures};
 assert.equal(E.gradeTask({kind:'packets',answer:[1,2]},{answer:[2,1]},cap).correct,true);
 assert.equal(E.gradeTask({kind:'packets',answer:[1,2]},{answer:[1,1]},cap).correct,false);
 assert.equal(E.gradeTask({kind:'order',answer:[1,2]},{answer:[2,1]},cap).correct,false);
 assert.equal(E.gradeTask({kind:'filter',answer:[1,2]},{},cap,'udp.port == 53').correct,true);
 assert.equal(E.gradeTask({kind:'filter',answer:[1,2]},{},cap,'dns').correct,true);
 assert.equal(E.gradeTask({kind:'filter',answer:[1,2]},{},cap,'').correct,false);
 assert.equal(E.gradeTask({kind:'filter',answer:[1,2]},{},cap,'dns &&').correct,false);
});

test('hydration validates completion, removes unknown fields, bounds hints, and resets invalid filters',()=>{
 const data={captures:[{id:'fixture',packets:fixtures}],lessons:[{id:'lesson',captureId:'fixture',tasks:[{id:'source',kind:'text',answer:'10.0.0.10',evidence:[{frame:1,field:'ip.src'}]}]}]};
 const raw={...E.emptyProgress(),currentLesson:'unknown',lessons:{lesson:{...E.emptyLesson(),filter:'dns &&',hints:900,selected:999,complete:true,completedAt:'2026-10-25T00:00:00Z',answers:{source:{answer:'wrong',evidence:[{frame:1,field:'missing'},{frame:999,field:'ip.src'}]},unknown:{answer:'x'}}},unknown:{complete:true}}};
 const restored=E.hydrate(raw,data);
 assert.equal(restored.currentLesson,null);
 assert.equal(restored.lessons.lesson.filter,'');
 assert.equal(restored.lessons.lesson.hints,3);
 assert.equal(restored.lessons.lesson.selected,1);
 assert.equal(restored.lessons.lesson.complete,false);
 assert.equal(restored.lessons.lesson.completedAt,null);
 assert.deepEqual(restored.lessons.lesson.answers.source.evidence,[]);
 assert.equal(restored.lessons.unknown,undefined);
 assert.equal(restored.lessons.lesson.answers.unknown,undefined);
 raw.lessons.lesson.answers.source={answer:'10.0.0.10',evidence:[{frame:1,field:'ip.src'}]};
 assert.equal(E.hydrate(raw,data).lessons.lesson.complete,true);
 for(const invalid of [null,{},[],{...raw,app:'wrong'},{...raw,schemaVersion:999},{...raw,lessons:[]}])assert.throws(()=>E.hydrate(invalid,data));
});

let cachedData;
function builtData(){
 if(cachedData)return cachedData;
 const filename=path.join(__dirname,'../src/data.js');
 assert.ok(fs.existsSync(filename),'Run node build.js before curriculum integration tests');
 const sandbox={};vm.runInNewContext(fs.readFileSync(filename,'utf8'),sandbox,{timeout:10000});
 return cachedData=JSON.parse(JSON.stringify(sandbox.PcapData));
}
const officialFilters={'ops-filter-1':'dns','ops-filter-2':'dns && ip.src == 10.0.0.11','ops-filter-3':'dns && ip.addr == 10.0.0.10','app-dns-03':'dns && tcp'};
function officialEntry(t){return {answer:t.kind==='text'&&Array.isArray(t.answer)?t.answer[0]:t.answer,evidence:t.evidence||[]};}

test('all 45 completion proofs from v0.1 survive the upgraded curriculum',()=>{
 const legacy=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures/progress-v0.1.json'),'utf8'));
 const restored=E.hydrate(legacy,builtData());
 assert.equal(Object.keys(legacy.lessons).length,45);
 for(const id of Object.keys(legacy.lessons))assert.equal(restored.lessons[id]?.complete,true,id);
 assert.equal(Object.values(restored.lessons).filter(s=>s.complete).length,45);
});

test('all 51 lessons validate, every official answer passes, wrong answers fail, evidence is selectable',()=>{
 const data=builtData();assert.deepEqual(E.validateData(data),[]);
 assert.equal(data.lessons.length,51);let tasks=0;
 for(const lesson of data.lessons){
  const cap=data.captures.find(c=>c.id===lesson.captureId);const filter=lesson.tasks.find(t=>t.kind==='filter')?.expectedFilter||officialFilters[lesson.id]||'';
  for(const t of lesson.tasks){
   tasks++;assert.equal(E.gradeTask(t,officialEntry(t),cap,filter).correct,true,`${lesson.id}/${t.id} official`);
   const wrong={...officialEntry(t),answer:['packets','order'].includes(t.kind)?[]:'__wrong__'};
   assert.equal(E.gradeTask(t,wrong,cap,t.kind==='filter'?'':filter).correct,false,`${lesson.id}/${t.id} wrong`);
   for(const evidence of t.evidence||[]){const p=cap.packets.find(p=>p.number===evidence.frame);assert.ok(p.layers.flatMap(l=>l.fields).some(f=>f.key===evidence.field),`${lesson.id}/${t.id} visible evidence ${evidence.field}`);}
  }
 }
 assert.ok(tasks>=45);
});

test('complete curriculum progress survives a validated export/import round trip',()=>{
 const data=builtData(),raw=E.emptyProgress();raw.currentLesson=data.lessons.at(-1).id;
 for(const lesson of data.lessons)raw.lessons[lesson.id]={...E.emptyLesson(),filter:lesson.tasks.find(t=>t.kind==='filter')?.expectedFilter||officialFilters[lesson.id]||'',complete:true,completedAt:'2026-10-25T12:00:00Z',answers:Object.fromEntries(lesson.tasks.map(t=>[t.id,officialEntry(t)]))};
 const restored=E.hydrate(JSON.parse(JSON.stringify(raw)),data);
 assert.equal(Object.values(restored.lessons).filter(s=>s.complete).length,51);
 assert.equal(restored.currentLesson,raw.currentLesson);
});

test('every authored capture has actual PCAP bytes, consistent frame lengths and no malformed/checksum errors',()=>{
 const data=builtData();let frames=0;
 for(const cap of data.captures){
  assert.equal(Buffer.from(cap.pcapBase64,'base64').readUInt32LE(0),0xa1b2c3d4,cap.id);
  for(const p of cap.packets){frames++;
   assert.equal(p.length,p.rawHex.length/2,`${cap.id}/${p.number} length`);
   assert.equal(p.fields['_ws.malformed'],undefined,`${cap.id}/${p.number} malformed`);
   assert.equal(p.fields['_ws.expert.severity']?.includes(8388608)||false,false,`${cap.id}/${p.number} expert error`);
   for(const [key,values]of Object.entries(p.fields))if(key.endsWith('.checksum.status'))assert.ok(values.every(v=>v===1||v===2),`${cap.id}/${p.number} ${key}: ${values}`);
  }
 }
 assert.ok(frames>100);
});
