(function(root){
 'use strict';
 const VERSION=1;
 class FilterError extends Error{}
 function tokenize(input){
  const result=[];let i=0;
  while(i<input.length){
   if(/\s/.test(input[i])){i++;continue;}
   const tail=input.slice(i),op=/^(==|!=|>=|<=|&&|\|\||[()!<>])/.exec(tail);
   if(op){result.push(op[1]);i+=op[1].length;continue;}
   if(input[i]==='"'){
    let value='',closed=false;i++;
    while(i<input.length){if(input[i]==='"'){closed=true;i++;break;}if(input[i]==='\\'){i++;if(i>=input.length)break;const c=input[i++];value+=c==='n'?'\n':c==='r'?'\r':c==='t'?'\t':c;}else value+=input[i++];}
    if(!closed)throw new FilterError('文字列の終わりに " を付けてください。');
    result.push({string:value});continue;
   }
   const atom=/^[A-Za-z0-9_.:\/-]+/.exec(tail);
   if(!atom)throw new FilterError(`「${input[i]}」は、この教材の表示フィルターでは使えません。`);
   result.push(atom[0]);i+=atom[0].length;
  }
  return result;
 }
 function fieldValues(packet,key){
  const f=packet.fields||{};
  if(Object.hasOwn(f,key))return Array.isArray(f[key])?f[key]:[f[key]];
  const aliases={'ip.addr':['ip.src','ip.dst'],'ipv6.addr':['ipv6.src','ipv6.dst'],'tcp.port':['tcp.srcport','tcp.dstport'],'udp.port':['udp.srcport','udp.dstport'],'eth.addr':['eth.src','eth.dst']};
  if(aliases[key])return aliases[key].flatMap(k=>fieldValues(packet,k));
  if((packet.layers||[]).some(l=>l.name===key))return [true];
  if(key==='bootp')return fieldValues(packet,'dhcp');
  return [];
 }
 function vocabulary(packets){
  const keys=new Set(['frame','eth','arp','ip','ipv6','icmp','icmpv6','tcp','udp','dns','dhcp','bootp','ntp','http','tls','data','frame.number','ip.addr','ipv6.addr','eth.addr','tcp.port','udp.port']);
  for(const p of packets){Object.keys(p.fields||{}).forEach(k=>keys.add(k));(p.layers||[]).forEach(l=>keys.add(l.name));}
  return keys;
 }
 function scalar(v){if(typeof v==='boolean')return +v;if(typeof v==='number')return v;const s=String(v);if(/^(true|false)$/i.test(s))return s.toLowerCase()==='true'?1:0;if(/^(?:-?\d+(?:\.\d+)?|0x[0-9a-f]+)$/i.test(s))return Number(s);return s;}
 function compileFilter(input,packets){
  if(typeof input!=='string'||input.length>2000)throw new FilterError('フィルターは2000文字以内で入力してください。');
  const tokens=tokenize(input);if(!tokens.length)return ()=>true;
  const known=vocabulary(packets);let at=0;
  const peek=()=>tokens[at],take=()=>tokens[at++];
  function term(){
   if(peek()==='!'||peek()==='not'){take();const a=term();return p=>!a(p);}
   if(peek()==='('){take();const a=or();if(take()!==')')throw new FilterError('閉じかっこ ) が必要です。');return a;}
   const name=take();
   if(typeof name!=='string'||!known.has(name))throw new FilterError(`「${typeof name==='string'?name:'入力の末尾'}」は未対応か、この教材に存在しない項目です。フィルター早見表も確認できます。`);
   if(!['==','!=','>','<','>=','<=','contains'].includes(peek()))return p=>fieldValues(p,name).length>0;
   const op=take(),rhs=take();
   if(rhs===undefined||['&&','||','and','or','not','contains',')','(','==','!=','>','<','>=','<=','!'].includes(rhs))throw new FilterError('比較する値を入力してください。');
   const val=typeof rhs==='object'?rhs.string:scalar(rhs);
   if(name==='frame'&&op==='contains'){
    if(typeof rhs!=='object')throw new FilterError('frame contains の検索語は二重引用符で囲んでください。');
    let hex;try{hex=encodeURIComponent(val).replace(/%([0-9a-f]{2})|([^%])/gi,(_,byte,char)=>byte||char.charCodeAt(0).toString(16).padStart(2,'0')).toLowerCase();}catch{throw new FilterError('検索語の文字を確認してください。');}
    if(!hex)throw new FilterError('検索語を入力してください。');
    // Match captured bytes at byte boundaries, never decoded/reassembled text.
    return p=>{const raw=(p.rawHex||'').toLowerCase();for(let i=raw.indexOf(hex);i>=0;i=raw.indexOf(hex,i+1))if(i%2===0)return true;return false;};
   }
   if(typeof rhs!=='object'&&known.has(rhs))throw new FilterError('この教材では、右辺にはIP・数値・引用符付きの文字列を指定してください。');
   const observed=packets.flatMap(p=>fieldValues(p,name));
   const isNumeric=observed.length&&observed.every(v=>typeof v==='number'||typeof v==='boolean');
   if(isNumeric&&typeof scalar(val)!=='number')throw new FilterError('この項目は数値（またはtrue / false）で比較してください。');
   if(['>','<','>=','<='].includes(op)&&typeof scalar(val)!=='number')throw new FilterError('大小の比較には数値を指定してください。');
   const addressMode=/^(eth\.(src|dst|addr)|arp\.(src|dst)\.hw_mac)$/.test(name)?'mac':/^(ipv6\.(src|dst|addr)|ip\.(src|dst|addr))$/.test(name)?'ip':null;
   function eq(a){if(addressMode)return normalize(a,addressMode)===normalize(val,addressMode);const x=scalar(a),y=scalar(val);return typeof x===typeof y?x===y:String(x)===String(y);}
   return p=>{const values=fieldValues(p,name);if(!values.length)return false;if(op==='!=')return values.every(x=>!eq(x));return values.some(x=>op==='=='?eq(x):op==='contains'?String(x).includes(String(val)):typeof scalar(x)==='number'&&typeof scalar(val)==='number'?(op==='>'?scalar(x)>scalar(val):op==='<'?scalar(x)<scalar(val):op==='>='?scalar(x)>=scalar(val):scalar(x)<=scalar(val)):false);};
  }
  function and(){let left=term();while(peek()==='&&'||peek()==='and'){take();const a=left,b=term();left=p=>a(p)&&b(p);}return left;}
  function or(){let left=and();while(peek()==='||'||peek()==='or'){take();const a=left,b=and();left=p=>a(p)||b(p);}return left;}
  const fn=or();if(at!==tokens.length)throw new FilterError('条件の間には && または || を入れてください。');return fn;
 }
 function filterPackets(input,packets){const test=compileFilter(input,packets);return packets.filter(test);}
 function normalize(value,mode='text'){
  let s=String(value??'').trim().normalize('NFKC');
  if(mode==='exact')return s;
  if(mode==='number')return /^-?\d+(\.\d+)?$/.test(s)?String(Number(s)):s;
  if(mode==='mac')return s.replace(/[-:.]/g,'').toLowerCase();
  if(mode==='ip'&&s.includes(':')){
   const sides=s.toLowerCase().split('::');if(sides.length>2)return s.toLowerCase();
   const a=sides[0]?sides[0].split(':'):[],b=sides[1]?sides[1].split(':'):[];
   if([...a,...b].some(n=>!/^[0-9a-f]{1,4}$/i.test(n))||(sides.length===1&&a.length!==8))return s.toLowerCase();
   if(sides.length===2){const missing=8-a.length-b.length;if(missing<1)return s.toLowerCase();return [...a,...Array(missing).fill('0'),...b].map(n=>parseInt(n,16).toString(16)).join(':');}
   return a.map(n=>parseInt(n,16).toString(16)).join(':');
  }
  return s.toLowerCase();
 }
 function sameSet(a,b){return Array.isArray(a)&&Array.isArray(b)&&a.length===b.length&&new Set(a).size===a.length&&a.every(v=>b.includes(v));}
 function gradeTask(task,entry,capture,appliedFilter=''){
  entry=entry||{};const answer=entry.answer;let correct=false;
  if(task.kind==='text'){const answers=Array.isArray(task.answer)?task.answer:[task.answer];correct=answers.some(a=>normalize(a,task.normalize)===normalize(answer,task.normalize));}
  else if(task.kind==='choice')correct=answer===task.answer;
  else if(task.kind==='packets')correct=sameSet(answer,task.answer);
  else if(task.kind==='order')correct=Array.isArray(answer)&&answer.length===task.answer.length&&answer.every((a,i)=>a===task.answer[i]);
  else if(task.kind==='filter'){
   try{correct=Boolean(appliedFilter.trim())&&sameSet(filterPackets(appliedFilter,capture.packets).map(p=>p.number),task.answer);}catch{return {correct:false,reason:'表示フィルターの入力を確認してください。'};}
  }
  if(!correct)return {correct:false,reason:task.kind==='filter'?'表示されているパケットの範囲を確認しましょう。':task.kind==='order'?'選んだパケットと順番を確認しましょう。':'回答と、パケットに記録された値を見比べてみましょう。'};
  if(task.evidence?.length){
   const expected=task.evidence,selected=entry.evidence||[];
   const valid=e=>expected.some(x=>x.frame===e.frame&&x.field===e.field)&&capture.packets.some(p=>p.number===e.frame&&fieldValues(p,e.field).length>0);
   const ok=selected.length>0&&selected.every(valid)&&(task.evidenceMode==='all'?expected.every(x=>selected.some(e=>x.frame===e.frame&&x.field===e.field)):true);
   if(!ok)return {correct:false,reason:selected.length?'根拠のパケットと項目を確認しましょう。別の通信の値が混ざっていないかも見てください。':'回答を裏づける項目を詳細欄から選び、「根拠に追加」を押してください。'};
  }
  return {correct:true,reason:task.why||'パケットに記録された内容と一致しています。'};
 }
 function emptyProgress(){return {schemaVersion:VERSION,app:'pcaproom-easy',currentLesson:null,lessons:{}};}
 function emptyLesson(){return {answers:{},filter:'',timeMode:'relative',hints:0,reflection:'',solutionSeen:false,complete:false,completedAt:null,selected:1};}
 function formatTime(packet,mode='relative'){
  if(mode==='utc'){
   const epoch=packet.timestampEpoch??fieldValues(packet,'frame.time_epoch')[0],micros=Math.round(Number(epoch)*1000000);
   if(!Number.isFinite(micros))return '—';
   const seconds=Math.floor(micros/1000000);
   return new Date(seconds*1000).toISOString().slice(0,19).replace('T',' ')+'.'+String(micros-seconds*1000000).padStart(6,'0');
  }
  return Number(mode==='delta'?(packet.timeDelta??fieldValues(packet,'frame.time_delta')[0]??0):packet.time).toFixed(6);
 }
 function hydrate(raw,data){
  if(!raw||raw.app!=='pcaproom-easy'||raw.schemaVersion!==VERSION||typeof raw.lessons!=='object'||!raw.lessons||Array.isArray(raw.lessons))throw new Error('pcaproom-easyの保存ファイルではないか、対応していない版です。');
  const result=emptyProgress();
  result.currentLesson=data.lessons.some(l=>l.id===raw.currentLesson)?raw.currentLesson:null;
  for(const lesson of data.lessons){
   const from=raw.lessons[lesson.id];if(!from||typeof from!=='object')continue;
   const state=emptyLesson(),capture=data.captures.find(c=>c.id===lesson.captureId);
   state.filter=typeof from.filter==='string'?from.filter.slice(0,2000):'';
   state.timeMode=['relative','utc','delta'].includes(from.timeMode)?from.timeMode:'relative';
   try{compileFilter(state.filter,capture.packets);}catch{state.filter='';}
   state.hints=Number.isInteger(from.hints)?Math.min(3,Math.max(0,from.hints)):0;
   state.solutionSeen=from.solutionSeen===true;
   state.reflection=lesson.reflection&&typeof from.reflection==='string'?from.reflection.slice(0,2000):'';
   state.selected=capture.packets.some(p=>p.number===from.selected)?from.selected:1;
   for(const task of lesson.tasks){const e=from.answers?.[task.id];if(!e||typeof e!=='object')continue;
    const answer=(task.kind==='order'||task.kind==='packets')?(Array.isArray(e.answer)?e.answer.filter(n=>Number.isInteger(n)&&capture.packets.some(p=>p.number===n)).slice(0,100):[]):typeof e.answer==='string'?e.answer.slice(0,2000):'';
    const evidence=Array.isArray(e.evidence)?e.evidence.filter(x=>x&&Number.isInteger(x.frame)&&typeof x.field==='string'&&capture.packets.some(p=>p.number===x.frame&&fieldValues(p,x.field).length)).map(x=>({frame:x.frame,field:x.field})).slice(0,30):[];
    state.answers[task.id]={answer,evidence};
   }
   // Keep an earned flag when the learner changes their working answers for review.
   // A stored flag still needs a valid completed answer snapshot on import.
   const proof=from.proof&&typeof from.proof==='object'?from.proof:{answers:state.answers,filter:state.filter};
   const proofFilter=typeof proof.filter==='string'?proof.filter.slice(0,2000):'';
   const proofValid=from.complete===true&&lesson.tasks.every(t=>gradeTask(t,proof.answers?.[t.id],capture,proofFilter).correct);
   state.complete=proofValid;
   if(proofValid)state.proof={filter:proofFilter,answers:Object.fromEntries(lesson.tasks.map(t=>{const p=proof.answers[t.id];return [t.id,{answer:Array.isArray(p.answer)?p.answer.slice(0,100):String(p.answer??'').slice(0,2000),evidence:(Array.isArray(p.evidence)?p.evidence:[]).map(e=>({frame:e.frame,field:e.field})).slice(0,30)}];}))};
   state.completedAt=state.complete&&typeof from.completedAt==='string'?from.completedAt:null;
   result.lessons[lesson.id]=state;
  }
  return result;
 }
 function validateData(data){
  const errors=[],ids=new Set(),caps=new Map(data.captures.map(c=>[c.id,c]));
  if(!data.lessons.length)errors.push('At least one lesson is required');
  for(const lesson of data.lessons){
   if(ids.has(lesson.id))errors.push(`Duplicate lesson ${lesson.id}`);ids.add(lesson.id);
   if(!data.chapters.some(c=>c.id===lesson.chapter))errors.push(`Missing chapter ${lesson.id}`);
   if(lesson.hints?.length!==3)errors.push(`Three hints required ${lesson.id}`);
   const cap=caps.get(lesson.captureId);if(!cap){errors.push(`Missing capture ${lesson.id}`);continue;}
   if(!lesson.tasks?.length)errors.push(`No tasks ${lesson.id}`);
   for(const t of lesson.tasks){
    for(const e of t.evidence||[])if(!cap.packets.some(p=>p.number===e.frame&&fieldValues(p,e.field).length))errors.push(`Missing evidence ${lesson.id}/${t.id}: ${e.frame} ${e.field}`);
    if(['packets','order','filter'].includes(t.kind)&&(!Array.isArray(t.answer)||t.answer.some(n=>!cap.packets.some(p=>p.number===n))))errors.push(`Invalid packet answer ${lesson.id}/${t.id}`);
    if(t.kind==='choice'&&!t.options.some(o=>o.value===t.answer))errors.push(`Invalid choice ${lesson.id}/${t.id}`);
   }
  }
  return errors;
 }
 const API={FilterError,tokenize,fieldValues,compileFilter,filterPackets,normalize,sameSet,gradeTask,emptyProgress,emptyLesson,formatTime,hydrate,validateData};
 root.PcapEngine=API;if(typeof module!=='undefined')module.exports=API;
})(globalThis);
