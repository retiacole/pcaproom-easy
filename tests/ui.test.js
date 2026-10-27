'use strict';

// Code-level DOM integration tests only: no browser navigation, HTTP server, or
// external resources. A synthetic URL gives the mocked document a stable origin.
// Run after node build.js --data-only. Set PCAPROOM_JSDOM_MODULE if jsdom is not
// installed in this project's node_modules.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');
const { Blob: NodeBlob } = require('node:buffer');
const { JSDOM, VirtualConsole } = require(process.env.PCAPROOM_JSDOM_MODULE || 'jsdom');

const root = path.resolve(__dirname, '..');
const STORE = 'pcaproom-easy.progress.v1';
const filters = {
  'ops-filter-1': 'dns',
  'ops-filter-2': 'dns && ip.src == 10.0.0.11',
  'ops-filter-3': 'dns and ip.addr == 10.0.0.10',
  'app-dns-03': 'dns && tcp',
};

function assembleHtml() {
  if (process.env.PCAPROOM_HTML) return fs.readFileSync(path.resolve(process.env.PCAPROOM_HTML), 'utf8');
  let html = fs.readFileSync(path.join(root, 'src/shell.html'), 'utf8');
  for (const [name, file] of Object.entries({ CSS: 'style.css', DATA: 'data.js', ENGINE: 'engine.js', I18N: 'i18n.js', APP: 'app.js' })) {
    let source = fs.readFileSync(path.join(root, 'src', file), 'utf8');
    if (name !== 'CSS') source = source.replace(/<\/script/gi, '<\\/script');
    html = html.replace(`/*__${name}__*/`, () => source);
  }
  assert.doesNotMatch(html, /\/\*__\w+__\*\//, 'all standalone build markers must be filled');
  assert.doesNotMatch(html, /<script\b[^>]*\bsrc\s*=/i, 'no external runtime scripts');
  assert.doesNotMatch(html, /<link\b[^>]*\brel=["']stylesheet/i, 'no external stylesheets');
  return html;
}

const html = assembleHtml();

test('correlation references, optional note and graduation recommendation survive language and import', async()=>{
 const app=createApp();let reload;
 try{
  assert.equal(app.query('.topbar .version-badge').textContent,`v${require('../package.json').version}`);
  assert.equal(app.document.querySelector('.room-recommendation'),null);
  openLesson(app,'correlation-logs');
  assert.equal(app.document.querySelectorAll('.reference-row').length,8);
  const raw=app.query('[data-reference="access"]').textContent;
  assert.match(raw,/08:59:55 \+0900/);assert.match(raw,/req-report-042/);
  app.change('#language-select','en');
  assert.match(app.query('[data-reference="access"] h2').textContent,/Access logs/);
  const data=app.window.PcapData,localized=app.window.PcapI18n.localize(data);
  assert.equal(localized.lessons.at(-1).referenceCards[1].rows,data.lessons.at(-1).referenceCards[1].rows,'translation retains canonical evidence rows');
  for(const l of data.lessons.filter(l=>l.chapter==='log-correlation'))solveLesson(app,l);
  assert.match(app.query('.room-recommendation').textContent,/optional/);
  assert.ok(app.query('[data-action="home"]'));
  const note='404 / No. 220, A3, B2\nCause unknown; ask application owner for generation logs. <script>draft</script>';
  app.input('#reflection-note',note);
  app.change('#language-select','ja');assert.equal(app.query('#reflection-note').value,note);
  app.click('[data-action="report-note"]');
  assert.equal(app.downloads.at(-1).name,'pcaproom-handoff-note.txt');
  assert.match(await app.downloads.at(-1).blob.text(),/Cause unknown/);
  const exported=JSON.stringify(saved(app));
  await importText(app,exported);app.click('[data-action="confirm-import"]');
  openLesson(app,'correlation-report');assert.equal(app.query('#reflection-note').value,note);
  reload=createApp({storage:new Map(app.storage),expectedFlags:3});
  assert.ok(reload.query('.room-recommendation'));
  openLesson(reload,'correlation-report');assert.equal(reload.query('#reflection-note').value,note);
  assert.equal(app.errors.length,0);assert.equal(reload.errors.length,0);
 }finally{app.window.close();reload?.window.close();}
});

function createApp({ storage = new Map(), unavailable = false, expectedFlags = 0, language } = {}) {
  if(language)storage.set('pcaproom-easy.language.v1',language);
  const errors = [], downloads = [], urls = new Map();
  let urlId = 0;
  const virtualConsole = new VirtualConsole();
  virtualConsole.on('jsdomError', error => errors.push(error));
  const dom = new JSDOM(html, {
    url: 'https://pcaproom.test/',
    runScripts: 'dangerously',
    virtualConsole,
    beforeParse(window) {
      const fail = () => { throw new window.DOMException('Storage is disabled for this test', 'SecurityError'); };
      Object.defineProperty(window, 'localStorage', { configurable: true, value: {
        getItem(key) { if (unavailable) return fail(); return storage.get(String(key)) ?? null; },
        setItem(key, value) { if (unavailable) return fail(); storage.set(String(key), String(value)); },
        removeItem(key) { if (unavailable) return fail(); storage.delete(String(key)); },
        clear() { if (unavailable) return fail(); storage.clear(); },
        key(index) { if (unavailable) return fail(); return [...storage.keys()][index] ?? null; },
        get length() { if (unavailable) return fail(); return storage.size; },
      } });
      window.Blob = NodeBlob;
      window.URL.createObjectURL = blob => { const url = `blob:pcaproom-test-${++urlId}`; urls.set(url, blob); return url; };
      window.URL.revokeObjectURL = url => urls.delete(url);
      window.HTMLAnchorElement.prototype.click = function () {
        if (this.download) downloads.push({ name: this.download, blob: urls.get(this.href), url: this.href });
      };
      window.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
      window.HTMLDialogElement.prototype.close = function () { this.open = false; };
      window.scrollTo = () => {};
      window.fetch = () => { throw new Error('The offline UI must not call fetch'); };
    },
  });
  const window = dom.window;
  const document = window.document;
  const query = selector => {
    const node = document.querySelector(selector);
    assert.ok(node, `UI element exists: ${selector}`);
    return node;
  };
  const click = selectorOrNode => {
    const node = typeof selectorOrNode === 'string' ? query(selectorOrNode) : selectorOrNode;
    assert.ok(node, 'click target exists');
    assert.equal(node.disabled, false, `click target enabled: ${node.outerHTML.slice(0, 180)}`);
    node.click();
  };
  const input = (selector, value) => {
    const node = query(selector);
    node.value = String(value);
    node.dispatchEvent(new window.Event('input', { bubbles: true }));
  };
  const change = (selectorOrNode, value) => {
    const node = typeof selectorOrNode === 'string' ? query(selectorOrNode) : selectorOrNode;
    if (value !== undefined) node.value = String(value);
    node.dispatchEvent(new window.Event('change', { bubbles: true }));
  };
  const app = { dom, window, document, query, click, input, change, storage, downloads, errors };
  assert.equal(query('#top-count').textContent, String(expectedFlags), 'home reflects loaded completion count');
  assert.equal(errors.length, 0, 'application starts without script errors');
  return app;
}

function openLesson(app, id) {
  if (app.document.querySelector('#lesson-select')) app.change('#lesson-select', id);
  else app.click(`[data-open="${id}"]`);
  assert.equal(app.query('#lesson-select').value, id);
}
function applyFilter(app, expression) {
  app.input('#filter-input', expression);
  app.query('#filter-form').dispatchEvent(new app.window.Event('submit', { bubbles: true, cancelable: true }));
}
function visibleFrames(app) {
  return [...app.document.querySelectorAll('#packet-list [data-packet]')].map(b => Number(b.dataset.packet));
}
function chooseTask(app, index, count) {
  if (count > 1) {
    app.click(`[data-task="${index}"]`);
    assert.equal(app.query(`[data-task="${index}"]`).getAttribute('aria-pressed'), 'true');
  }
}
function selectEvidenceField(app, evidence) {
  app.click(`[data-packet="${evidence.frame}"]`);
  assert.match(app.query('#selected-number').textContent, new RegExp(`No\\. ${evidence.frame}$`));
  let field = [...app.document.querySelectorAll('.field')].find(node => node.querySelector('.field-key')?.textContent === evidence.field);
  if (!field) {
    app.click('[data-action="all-fields"]');
    field = [...app.document.querySelectorAll('.field')].find(node => node.querySelector('.field-key')?.textContent === evidence.field);
  }
  assert.ok(field, `visible detail field ${evidence.field} on frame ${evidence.frame}`);
  for(let disclosure=field.closest('details');disclosure;disclosure=disclosure.parentElement.closest('details'))disclosure.open=true;
  app.click(field);
  assert.ok(app.query('#selected-field').textContent.includes(evidence.field));
}
function addEvidence(app, evidence) {
  selectEvidenceField(app, evidence);
  if (!app.query('#add-evidence').disabled) app.click('#add-evidence');
  assert.ok(app.query('.evidence-list').textContent.includes(`No. ${evidence.frame} · ${evidence.field}`));
}
function solveLesson(app, lesson) {
  openLesson(app, lesson.id);
  const targetFilter = lesson.tasks.some(task => task.kind === 'filter') ? lesson.tasks.find(task=>task.kind==='filter')?.expectedFilter||filters[lesson.id] : '';
  if (lesson.tasks.some(task => task.kind === 'filter')) assert.ok(targetFilter, `semantic official filter for ${lesson.id}`);
  for (const [index, task] of lesson.tasks.entries()) {
    chooseTask(app, index, lesson.tasks.length);
    applyFilter(app, '');
    if (task.kind === 'text') app.input('#answer-input', Array.isArray(task.answer) ? task.answer[0] : task.answer);
    else if (task.kind === 'choice') {
      const radio = [...app.document.querySelectorAll('input[name="answer-choice"]')].find(n => n.value === task.answer);
      assert.ok(radio, `official option exists: ${lesson.id}/${task.id}`);
      radio.checked = true;
      app.change(radio);
    } else if (task.kind === 'packets' || task.kind === 'order') {
      for (const number of task.answer) app.click(`#packet-list [data-pick="${number}"]`);
      assert.equal(app.document.querySelectorAll('.selection-chip').length, task.answer.length);
      if (task.kind === 'order') {
        const numbers = [...app.document.querySelectorAll('.selection-chip')].map(n => Number(/No\. (\d+)/.exec(n.textContent)[1]));
        assert.deepEqual(numbers, Array.from(task.answer), 'selection order is retained');
      }
    } else assert.equal(task.kind, 'filter', `supported UI task: ${task.kind}`);
    for (const evidence of task.evidence || []) addEvidence(app, evidence);
    if (targetFilter) applyFilter(app, targetFilter);
    app.click('[data-action="check"]');
    assert.ok(app.query('#feedback .feedback').classList.contains('success'), `${lesson.id}/${task.id}: ${app.query('#feedback').textContent}`);
    if (lesson.tasks.length > 1) assert.ok(app.query(`[data-task="${index}"]`).textContent.includes('✓'), 'correct task tab is checked');
  }
  assert.ok(app.query('#completion-area').textContent.includes(app.window.PcapI18n.locale==='en'?'100 points':'100ポイント'), `${lesson.id} awards a flag`);
  assert.equal(app.errors.length, 0, `${lesson.id}: no runtime errors`);
}
function saved(app) { return JSON.parse(app.storage.get(STORE)); }
function completed(progress) { return Object.values(progress.lessons).filter(lesson => lesson.complete).length; }
async function importText(app, content, size = Buffer.byteLength(content)) {
  const input = app.query('#import-file');
  Object.defineProperty(input, 'files', { configurable: true, value: [{ name: 'progress.json', size, text: async () => content }] });
  app.change(input);
  await new Promise(resolve => setImmediate(resolve));
}

for(const language of ['ja','en'])test(`all 54 lessons are solvable in ${language}; progress reloads`, { timeout: 240000 }, () => {
  const app = createApp({language});
  let reload;
  try {
    const lessons = app.window.PcapData.lessons;
    assert.equal(lessons.length, 54);
    assert.equal(app.document.querySelectorAll('.lesson-link').length, 54, 'all lessons accessible from the map');
    const kinds = new Set();
    let answered = 0;
    for (const [index, lesson] of lessons.entries()) {
      solveLesson(app, lesson);
      if(language==='en'){for(let h=0;h<3;h++)app.click('[data-action="hint"]');app.click('[data-action="solution"]');assertEnglish(app);}
      lesson.tasks.forEach(task => kinds.add(task.kind));
      answered += lesson.tasks.length;
      assert.equal(Number(app.query('#top-count').textContent), index + 1);
      assert.equal(completed(saved(app)), index + 1);
    }
    assert.deepEqual([...kinds].sort(), ['choice', 'filter', 'order', 'packets', 'text']);
    assert.equal(answered, lessons.reduce((sum, lesson) => sum + lesson.tasks.length, 0), 'every individual task is exercised');
    app.click('[data-action="home"]');
    assert.equal(app.query('[role="progressbar"]').getAttribute('aria-valuenow'), '54');
    assert.ok(app.query('.hero-metrics').textContent.includes(language==='en'?'5400 points':'5400ポイント'));
    assert.equal(app.document.querySelectorAll('.lesson-link.done').length, 54);

    // Learners may explore a different filter after winning a flag. The saved
    // completion proof must survive, even when their current view no longer
    // matches the original answer to a filter exercise.
    openLesson(app, 'ops-filter-1');
    applyFilter(app, 'frame.number == 1');
    assert.equal(completed(saved(app)), 54);
    const snapshot = new Map(app.storage);
    app.dom.window.close();
    reload = createRestoredApp(snapshot);
    assert.equal(reload.query('#top-count').textContent, '54');
    assert.equal(reload.document.querySelectorAll('.lesson-link.done').length, 54);
    openLesson(reload, 'ops-filter-1');
    assert.equal(reload.query('#filter-input').value, 'frame.number == 1');
    assert.ok(reload.query('#completion-area').textContent.includes(language==='en'?'100 points':'100ポイント'), 'completion remains after exploratory filter edit and reload');
    assert.equal(reload.errors.length, 0);
  } finally { app.dom.window.close(); reload?.dom.window.close(); }
});

// Run the document from scratch against the previously persisted storage map.
function createRestoredApp(storage) {
  return createApp({ storage, expectedFlags: completed(JSON.parse(storage.get(STORE))) });
}

test('time modes persist, selected fields prepare filters, and chapter endings transfer to Wireshark',()=>{
 const app=createApp();let restored;
 try{
  openLesson(app,'ops-filter-3');
  applyFilter(app,'frame.number == 1 || frame.number == 3');
  app.change('#time-mode','utc');
  assert.match(app.query('#packet-list tbody tr td:nth-child(2)').textContent,/^2026-01-01 00:00:00\./);
  assert.equal(app.query('#packet-list th:nth-child(2)').textContent,'Time (UTC)');
  app.change('#time-mode','delta');
  const capture=app.window.PcapData.captures.find(c=>c.id==='ops-mixed');
  const third=capture.packets[2];
  assert.equal(app.query('#packet-list tbody tr:nth-child(2) td:nth-child(2)').textContent,Number(third.fields['frame.time_delta'][0]).toFixed(6));
  app.click('[data-packet="1"]');
  const field=[...app.document.querySelectorAll('.field')].find(n=>n.querySelector('.field-key')?.textContent==='dns.qry.name');
  app.click(field);
  assert.match(app.query('#field-status').textContent,/dns\.qry\.name/);
  app.click('#field-filter');
  const expression=app.query('#filter-input').value;
  assert.match(expression,/^dns\.qry\.name == "/);
  assert.deepEqual(visibleFrames(app),[1,3],'preparing a filter does not apply it yet');
  applyFilter(app,expression);
  const frames=visibleFrames(app);
  app.click('[data-action="wireshark"]');
  assert.ok(app.query('#modal-content').textContent.includes(expression));
  assert.ok(app.query('#modal-content').textContent.includes(frames.join(', ')));
  app.click('#modal-content [data-action="pcap"]');
  assert.equal(app.downloads.at(-1).name,'ops-mixed.pcap');
  const snapshot=new Map(app.storage);app.window.close();
  restored=createRestoredApp(snapshot);openLesson(restored,'ops-filter-3');
  assert.equal(restored.query('#time-mode').value,'delta');
  openLesson(restored,'realworld-time');restored.click('[data-packet="2"]');
  const bytes=[...restored.document.querySelectorAll('.field')].find(n=>n.querySelector('.field-key')?.textContent==='eth.padding');
  restored.click(bytes);restored.click('#field-filter');
  assert.equal(restored.query('#filter-input').value,'eth.padding','byte fields prepare a presence filter, never a quoted hex string');
  applyFilter(restored,'eth.padding');assert.deepEqual(visibleFrames(restored),[2]);
  assert.equal(restored.errors.length,0);
 }finally{app.window.close();restored?.window.close();}
});

test('field-generated address, string and numeric filters match real tshark',()=>{
 const app=createApp(),dir=fs.mkdtempSync(path.join(os.tmpdir(),'pcaproom-field-filters-'));
 try{
  const env={...process.env,TZ:'UTC',LC_ALL:'C',WIRESHARK_CONFIG_DIR:dir,WIRESHARK_PLUGIN_DIR:path.join(dir,'plugins'),SSLKEYLOGFILE:''};
  delete env.WIRESHARK_DATA_DIR;
  openLesson(app,'realworld-dns');
  for(const [frame,key,expected] of [
   [3,'ip.src','ip.src == 10.0.0.60'],
   [7,'ipv6.src','ipv6.src == fe80::3c'],
   [1,'eth.src','eth.src == 02:00:00:00:00:3c'],
   [3,'dns.qry.name','dns.qry.name == "printer-1.local"'],
   [3,'udp.srcport','udp.srcport == 5353'],
  ]){
   applyFilter(app,'');app.click(`[data-packet="${frame}"]`);
   const field=[...app.document.querySelectorAll('.field')].find(n=>n.querySelector('.field-key')?.textContent===key);
   app.click(field);app.click('#field-filter');
   const expression=app.query('#filter-input').value;
   assert.equal(expression,expected);
   const output=execFileSync(process.env.PCAPROOM_TSHARK||'/usr/local/bin/tshark',['-n','-2','-r',path.join(root,'captures/realworld-lan.pcap'),'-Y',expression,'-T','fields','-e','frame.number'],{encoding:'utf8',env});
   const frames=output.trim().split('\n').filter(Boolean).map(Number);
   assert.ok(frames.includes(frame),`${key} matches the selected frame in Wireshark`);
   applyFilter(app,expression);
   assert.deepEqual(visibleFrames(app),frames,`${key}: generated filter agrees with Wireshark`);
  }
  assert.equal(app.errors.length,0);
 }finally{app.window.close();fs.rmSync(dir,{recursive:true,force:true});}
});

test('packet list retains both scroll offsets during inspection and resets for new filters and lessons',()=>{
 const app=createApp();try{
  openLesson(app,'realworld-dns');
  const setScroll=()=>{const wrap=app.query('.packet-table-wrap');wrap.scrollTop=5000;wrap.scrollLeft=150;};
  const assertScroll=(top=5000,left=150)=>{const wrap=app.query('.packet-table-wrap');assert.equal(wrap.scrollTop,top);assert.equal(wrap.scrollLeft,left);};
  setScroll();app.click('[data-packet="200"]');assertScroll();
  assert.match(app.query('#selected-number').textContent,/No\. 200$/);
  app.change('#time-mode','utc');assertScroll();
  chooseTask(app,1,2);assertScroll();
  app.change('#language-select','en');assertScroll();
  app.change('#language-select','ja');assertScroll();
  applyFilter(app,'unknown_field');assertScroll();
  applyFilter(app,'dns');assertScroll(0,0);
  setScroll();app.click('[data-action="clear-filter"]');assertScroll(0,0);
  setScroll();
  const lesson=app.window.PcapData.lessons.find(l=>l.tasks.some(t=>['packets','order'].includes(t.kind)));
  openLesson(app,lesson.id);assertScroll(0,0);
  chooseTask(app,lesson.tasks.findIndex(t=>['packets','order'].includes(t.kind)),lesson.tasks.length);
  setScroll();app.click(app.query('[data-pick]'));assertScroll();
  assert.equal(app.errors.length,0);
 }finally{app.window.close();}
});

test('TCP Options disclosure remains open while selecting an option and highlights its bytes',()=>{
 const app=createApp();try{
  openLesson(app,'app-tcp-01');
  app.click('[data-packet="2"]');
  app.query('.tcp-options').open=true;
  const field=[...app.document.querySelectorAll('.tcp-options .field')].find(n=>n.querySelector('.field-key')?.textContent==='tcp.options.mss_val');
  app.click(field);
  assert.equal(app.query('.tcp-options').open,true);
  assert.match(app.query('#field-status').textContent,/tcp\.options\.mss_val/);
  assert.ok(app.document.querySelectorAll('.hex-byte.marked').length>0);
 }finally{app.window.close();}
});

test('hints, solutions, blank evidence and unrelated evidence do not award flags', () => {
  const app = createApp();
  try {
    openLesson(app, 'app-dns-01');
    for (let i = 0; i < 3; i++) app.click('[data-action="hint"]');
    assert.equal(app.query('[data-action="hint"]').disabled, true);
    assert.equal(app.document.querySelectorAll('.hint-text').length, 3);
    app.click('[data-action="solution"]');
    assert.ok(app.query('#solution-area').textContent.includes('答えと読み方'));
    assert.equal(app.query('#top-count').textContent, '0');
    assert.equal(saved(app).lessons['app-dns-01'].hints, 3);
    assert.equal(saved(app).lessons['app-dns-01'].solutionSeen, true);
    app.input('#answer-input', 'portal.test');
    app.click('[data-action="check"]');
    assert.ok(!app.query('#feedback .feedback').classList.contains('success'));
    assert.match(app.query('#feedback').textContent, /根拠/);
    addEvidence(app, { frame: 2, field: 'ip.dst' });
    app.click('[data-action="check"]');
    assert.ok(!app.query('#feedback .feedback').classList.contains('success'));
    assert.equal(app.query('#top-count').textContent, '0');
    app.click('[data-remove-evidence="0"]');
    addEvidence(app, { frame: 2, field: 'dns.qry.name' });
    app.click('[data-action="check"]');
    assert.ok(app.query('#feedback .feedback').classList.contains('success'));
    assert.equal(app.query('#top-count').textContent, '0', 'one correct task cannot finish a multi-task lesson');
    assert.equal(completed(saved(app)), 0);
    assert.equal(app.errors.length, 0);
  } finally { app.dom.window.close(); }
});

test('evidence guidance distinguishes inspecting, adding and removing a detail row', () => {
  const app = createApp();
  try {
    openLesson(app, 'ops-view-1');
    assert.match(app.query('#answer-status').textContent, /未入力/);
    assert.match(app.query('#evidence-status').textContent, /未追加/);
    assert.equal(app.document.querySelector('#add-evidence'), null, 'adding is offered beside a selected row');
    assert.match(app.query('[data-action="check"]').textContent, /根拠を選ぶ/);

    app.click('[data-action="check"]');
    assert.equal(app.document.activeElement.id, 'packet-details-title', 'guidance focuses the detail heading, not a correct answer');
    assert.equal(app.document.querySelector('.field.active'), null, 'guidance does not select a field for the learner');
    app.input('#answer-input', '10.0.0.10');
    assert.match(app.query('#answer-status').textContent, /入力済み/);
    app.click('[data-action="check"]');
    assert.match(app.query('#feedback').textContent, /根拠/);
    assert.doesNotMatch(app.query('#feedback').textContent, /もう一度、確かめよう/);
    assert.equal(app.query('#answer-input').value, '10.0.0.10', 'guidance preserves the entered answer');
    assert.equal(app.document.activeElement.id, 'packet-details-title');

    selectEvidenceField(app, { frame: 1, field: 'ip.src' });
    assert.equal(app.document.querySelectorAll('.evidence-item').length, 0, 'reading a field never adds it automatically');
    assert.deepEqual(saved(app).lessons['ops-view-1'].answers.source.evidence, []);
    assert.ok(app.query('#add-evidence').closest('.field-evidence-action'), 'the add action stays beside the selected row');
    assert.equal(app.query('#add-evidence').disabled, false);
    app.click('#add-evidence');
    assert.match(app.query('#evidence-status').textContent, /1件追加済み/);
    assert.match(app.query('.evidence-list').textContent, /Source Address/);
    assert.match(app.query('.evidence-list').textContent, /10\.0\.0\.10/);
    assert.equal(app.query('#add-evidence').disabled, true, 'the same row cannot be added twice');
    assert.match(app.query('[data-action="check"]').textContent, /回答と根拠を答え合わせ/);
    assert.match(app.query('[data-action="choose-evidence"]').textContent, /根拠を追加・変更/);
    assert.equal(app.query('#top-count').textContent, '0', 'added does not mean graded correct');

    app.click('[data-remove-evidence="0"]');
    assert.match(app.query('#evidence-status').textContent, /未追加/);
    assert.equal(app.query('#add-evidence').disabled, false);
    assert.match(app.query('[data-action="check"]').textContent, /根拠を選ぶ/);
    assert.equal(app.errors.length, 0, app.errors.map(e => e.stack).join('\n'));
  } finally { app.window.close(); }
});

test('inline evidence actions and summaries belong to the current task and survive language changes', () => {
  const app = createApp();
  try {
    const lesson = app.window.PcapData.lessons.find(l => l.id === 'base-ethernet-3');
    openLesson(app, lesson.id);
    addEvidence(app, lesson.tasks[0].evidence[0]);
    assert.match(app.query('#add-evidence').textContent, /追加済み/);
    chooseTask(app, 1, lesson.tasks.length);
    assert.match(app.query('#evidence-status').textContent, /未追加/);
    assert.equal(app.document.querySelectorAll('.evidence-item').length, 0);
    assert.equal(app.query('#add-evidence').disabled, false, 'a row saved to another task is not already added here');
    assert.match(app.query('#add-evidence').textContent, /設問2/);
    addEvidence(app, lesson.tasks[1].evidence[0]);
    assert.match(app.query('.evidence-list').textContent, /192\.0\.2\.80/);
    const before = JSON.stringify(saved(app));
    app.change('#language-select', 'en');
    assertEnglish(app);
    assert.equal(JSON.stringify(saved(app)), before);
    assert.equal(app.query('#add-evidence').disabled, true);
    assert.match(app.query('.evidence-list').textContent, /192\.0\.2\.80/);
    app.change('#language-select', 'ja');
    chooseTask(app, 0, lesson.tasks.length);
    assert.match(app.query('.evidence-list').textContent, /02:10:00:00:03:01/);
    assert.doesNotMatch(app.query('.evidence-list').textContent, /192\.0\.2\.80/);
    const answers = saved(app).lessons[lesson.id].answers;
    assert.equal(answers[lesson.tasks[0].id].evidence.length, 1);
    assert.equal(answers[lesson.tasks[1].id].evidence.length, 1);
    assert.equal(app.errors.length, 0, app.errors.map(e => e.stack).join('\n'));
  } finally { app.window.close(); }
});

test('required evidence counts describe submission requirements without grading selected rows early', () => {
  const app = createApp();
  let anyApp;
  try {
    const lesson = app.window.PcapData.lessons.find(l => l.id === 'base-arp-2');
    const task = lesson.tasks[0];
    openLesson(app, lesson.id);
    assert.match(app.query('#answer-area').textContent, /必要な根拠：2件/);
    app.input('#answer-input', task.answer);
    addEvidence(app, task.evidence[0]);
    assert.match(app.query('#evidence-status').textContent, /1件追加済み/);
    app.click('[data-action="check"]');
    assert.equal(app.query('#feedback .feedback').classList.contains('success'), false, 'all-mode needs every required item');
    addEvidence(app, { frame: 3, field: 'arp.opcode' });
    assert.match(app.query('#evidence-status').textContent, /2件追加済み/);
    assert.doesNotMatch(app.query('#evidence-status').textContent, /正解/);
    app.click('[data-action="check"]');
    assert.equal(app.query('#feedback .feedback').classList.contains('success'), false, 'the count alone never satisfies grading');
    app.click('[data-remove-evidence="1"]');
    addEvidence(app, task.evidence[1]);
    app.click('[data-action="check"]');
    assert.equal(app.query('#feedback .feedback').classList.contains('success'), true);

    // Exercise the supported "any" contract with two alternatives. The fixture
    // is local to this isolated app; the shipped all-mode lesson stays intact.
    anyApp = createApp();
    const anyLesson = anyApp.window.PcapData.lessons.find(l => l.id === lesson.id);
    anyLesson.tasks[0].evidenceMode = 'any';
    openLesson(anyApp, anyLesson.id);
    assert.doesNotMatch(anyApp.query('#answer-area').textContent, /必要な根拠：2件/);
    assert.match(anyApp.query('#answer-area').textContent, /1件以上/);
    anyApp.input('#answer-input', anyLesson.tasks[0].answer);
    addEvidence(anyApp, anyLesson.tasks[0].evidence[0]);
    anyApp.click('[data-action="check"]');
    assert.equal(anyApp.query('#feedback .feedback').classList.contains('success'), true, 'any-mode accepts one of several valid alternatives');
    assert.equal(app.errors.length, 0, app.errors.map(e => e.stack).join('\n'));
    assert.equal(anyApp.errors.length, 0, anyApp.errors.map(e => e.stack).join('\n'));
  } finally { app.window.close(); anyApp?.window.close(); }
});

test('English evidence guidance is translated and evidence-free tasks keep their normal flow', () => {
  const app = createApp({ language: 'en' });
  try {
    openLesson(app, 'ops-view-1');
    assertEnglish(app);
    app.input('#answer-input', '10.0.0.10');
    app.click('[data-action="check"]');
    assertEnglish(app);
    assert.equal(app.document.activeElement.id, 'packet-details-title');
    selectEvidenceField(app, { frame: 1, field: 'ip.src' });
    assertEnglish(app);
    app.click('#add-evidence');
    assertEnglish(app);
    app.click('[data-remove-evidence="0"]');
    assertEnglish(app);

    openLesson(app, 'ops-filter-1');
    assert.equal(app.document.querySelector('#evidence-status'), null);
    assert.equal(app.document.querySelector('[data-action="choose-evidence"]'), null);
    selectEvidenceField(app, { frame: 1, field: 'ip.src' });
    assert.equal(app.document.querySelector('#add-evidence'), null, 'inspection does not offer irrelevant evidence actions');
    assert.equal(app.query('#field-filter').disabled, false, 'field inspection still supports filter creation');
    applyFilter(app, 'dns');
    app.click('[data-action="check"]');
    assert.equal(app.query('#feedback .feedback').classList.contains('success'), true);
    assertEnglish(app);
    assert.equal(app.errors.length, 0, app.errors.map(e => e.stack).join('\n'));
  } finally { app.window.close(); }
});

test('evidence summaries show every occurrence of a repeated field and escape decoded values', () => {
  const app = createApp();
  try {
    openLesson(app, 'ops-view-1');
    app.click('[data-packet="2"]');
    app.click('[data-action="all-fields"]');
    const rootField = [...app.document.querySelectorAll('.field')].find(node =>
      node.querySelector('.field-key')?.textContent === 'dns.resp.name' &&
      node.querySelector('.field-value')?.textContent === '<Root>');
    assert.ok(rootField, 'the second DNS Name occurrence is available to inspect');
    for (let disclosure = rootField.closest('details'); disclosure; disclosure = disclosure.parentElement.closest('details')) disclosure.open = true;
    app.click(rootField);
    assert.match(app.query('#selected-field').textContent, /<Root>/);
    app.click('#add-evidence');

    const item = app.query('.evidence-item');
    assert.deepEqual([...item.querySelectorAll('.evidence-value')].map(node => node.textContent), ['Name: portal.test', 'Name: <Root>']);
    assert.equal(item.querySelector('root'), null, 'decoded angle brackets remain text, not HTML elements');
    assert.match(item.innerHTML, /&lt;Root&gt;/);
    assert.deepEqual(saved(app).lessons['ops-view-1'].answers.source.evidence, [{ frame: 2, field: 'dns.resp.name' }], 'the existing frame-and-field save format is retained');
    assert.equal(app.errors.length, 0, app.errors.map(e => e.stack).join('\n'));
  } finally { app.window.close(); }
});

test('invalid filters show errors and retain the last valid displayed packet set', () => {
  const app = createApp();
  try {
    openLesson(app, 'app-dns-03');
    applyFilter(app, 'dns && tcp');
    assert.deepEqual(visibleFrames(app), [6, 8]);
    applyFilter(app, 'dns && (');
    assert.equal(app.query('#filter-input').getAttribute('aria-invalid'), 'true');
    assert.ok(app.query('#filter-message').classList.contains('error'));
    assert.deepEqual(visibleFrames(app), [6, 8]);
    assert.equal(saved(app).lessons['app-dns-03'].filter, 'dns && tcp');
    assert.equal(app.query('#filter-input').value, 'dns && (', 'invalid input is available to correct');
    applyFilter(app, 'frame.number == 999');
    assert.deepEqual(visibleFrames(app), []);
    assert.match(app.query('#packet-list').textContent, /条件に合うパケットはありません/);
    app.click('[data-action="clear-filter"]');
    assert.equal(visibleFrames(app).length, 9);
    assert.equal(app.query('#filter-input').getAttribute('aria-invalid'), 'false');
    assert.equal(app.errors.length, 0);
  } finally { app.dom.window.close(); }
});

test('PCAP downloads contain exact bytes; TCP streams reassemble and treat payload as text', async () => {
  const app = createApp();
  try {
    openLesson(app, 'app-http-03');
    app.click('[data-action="pcap"]');
    const download = app.downloads.at(-1);
    assert.equal(download.name, 'app-http-03-capture.pcap');
    assert.equal(download.blob.type, 'application/vnd.tcpdump.pcap');
    const expected = app.window.PcapData.captures.find(c => c.id === 'app-http-03-capture');
    assert.deepEqual(Buffer.from(await download.blob.arrayBuffer()), Buffer.from(expected.pcapBase64, 'base64'));
    app.click('[data-action="stream"]');
    assert.equal(app.query('#modal').open, true);
    assert.match(app.query('#modal-content').textContent, /packet-reading/);
    assert.match(app.query('#modal-content').textContent, /HTTP\/1\.1 200 OK/);
    app.click('[data-action="close-modal"]');
    openLesson(app, 'app-http-01');
    app.click('[data-action="stream"]');
    assert.ok(app.query('#modal-content').textContent.includes('<h1>Hello</h1>'));
    assert.equal(app.document.querySelector('#modal-content h1'), null, 'HTTP body is escaped, not rendered as HTML');
    app.click('[data-action="close-modal"]');
    openLesson(app, 'app-http-02');
    app.click('[data-action="stream"]');
    assert.equal(app.query('#stream-select').options.length, 2);
    app.change('#stream-select', app.query('#stream-select').options[1].value);
    assert.match(app.query('#modal-content').textContent, /POST \/api\/notes/);
    app.click('[data-action="close-modal"]');
    openLesson(app, 'app-dns-01');
    app.click('[data-action="stream"]');
    assert.match(app.query('#modal-content').textContent, /TCPストリームがありません/);
    assert.equal(app.errors.length, 0);
  } finally { app.dom.window.close(); }
});

test('progress import asks before replacing, cancellation preserves state, confirmation downloads a backup', async () => {
  const app = createApp();
  try {
    const lesson = app.window.PcapData.lessons.find(l => l.id === 'app-dns-01');
    solveLesson(app, lesson);
    const before = app.storage.get(STORE);
    const incoming = JSON.stringify(app.window.PcapEngine.emptyProgress());
    await importText(app, incoming);
    assert.equal(app.query('#modal').open, true);
    assert.match(app.query('#modal-content').textContent, /現在の進捗（1問クリア）/);
    assert.match(app.query('#modal-content').textContent, /ファイルの進捗（0問クリア）/);
    assert.equal(app.storage.get(STORE), before, 'preview does not replace progress');
    app.click('#modal [data-action="close-modal"]');
    assert.equal(app.query('#modal').open, false);
    assert.equal(app.storage.get(STORE), before, 'cancel preserves progress');
    assert.equal(app.downloads.length, 0, 'cancel does not download a backup');
    await importText(app, incoming);
    app.click('[data-action="confirm-import"]');
    assert.equal(app.query('#top-count').textContent, '0');
    assert.equal(completed(saved(app)), 0);
    const backup = app.downloads.at(-1);
    assert.equal(backup.name, 'pcaproom-easy-progress-before-import.json');
    assert.deepEqual(JSON.parse(await backup.blob.text()), JSON.parse(before), 'backup contains the exact previous progress');
    const after = app.storage.get(STORE);
    await importText(app, '{broken json');
    assert.match(app.query('#modal-content').textContent, /読み込めませんでした/);
    assert.equal(app.storage.get(STORE), after);
    app.click('#modal [data-action="close-modal"]');
    await importText(app, incoming, 5 * 1024 * 1024 + 1);
    assert.match(app.query('#modal-content').textContent, /5MB以内/);
    assert.equal(app.storage.get(STORE), after);
    assert.equal(app.errors.length, 0);
  } finally { app.dom.window.close(); }
});

test('learning and manual export work when browser storage is unavailable', async () => {
  const app = createApp({ unavailable: true });
  try {
    assert.equal(app.query('#storage-note').hidden, false);
    assert.match(app.query('#storage-note').textContent, /自動保存/);
    const lesson = app.window.PcapData.lessons.find(l => l.id === 'app-dns-01');
    solveLesson(app, lesson);
    assert.equal(app.query('#top-count').textContent, '1');
    assert.equal(app.query('#storage-note').hidden, false);
    app.click('[data-action="export"]');
    const file = app.downloads.at(-1);
    assert.equal(file.name, 'pcaproom-easy-progress.json');
    const exported = JSON.parse(await file.blob.text());
    assert.equal(exported.app, 'pcaproom-easy');
    assert.equal(completed(exported), 1);
    assert.equal(app.errors.length, 0);
  } finally { app.dom.window.close(); }
});


function assertEnglish(app,scope=app.document.body){
 const copy=scope.cloneNode(true);copy.querySelectorAll('script,style,noscript,[data-language-name]').forEach(n=>n.remove());
 const untranslated=copy.textContent.match(/[^\n]{0,80}[\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Han}][^\n]{0,120}/u);
 assert.equal(untranslated,null,`Untranslated visible content: ${untranslated?.[0]}`);
 for(const el of copy.querySelectorAll('[aria-label],[placeholder],[title]'))for(const attr of ['aria-label','placeholder','title'])assert.doesNotMatch(el.getAttribute(attr)||'',/[\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Han}]/u,`${attr} is translated`);
}

test('language switch retains drafts, task, evidence, selected field, filters, disclosures and earned flags',()=>{
 const app=createApp();let restored;
 try{
  const lesson=app.window.PcapData.lessons.find(l=>l.id==='app-tcp-02');
  solveLesson(app,lesson);
  chooseTask(app,1,lesson.tasks.length);
  app.input('#answer-input','review draft');
  addEvidence(app,lesson.tasks[1].evidence[0]);
  app.change('#time-mode','utc');
  applyFilter(app,'tcp');
  app.input('#filter-input','tcp && unfinished');
  const field=[...app.document.querySelectorAll('.field')].find(el=>el.querySelector('.field-key')?.textContent==='tcp.ack');app.click(field);
  app.query('#bytes-disclosure').open=true;
  app.click('[data-action="hint"]');app.click('[data-action="solution"]');
  const before=JSON.stringify(saved(app));
  app.change('#language-select','en');
  assert.equal(app.document.documentElement.lang,'en');assert.equal(app.query('#language-select').value,'en');
  assert.equal(JSON.stringify(saved(app)),before,'switch writes no progress changes');
  assert.equal(app.query('#answer-input').value,'review draft');assert.equal(app.query('#filter-input').value,'tcp && unfinished');
  assert.equal(app.query('#time-mode').value,'utc');assert.equal(app.query('#bytes-disclosure').open,true);
  assert.equal(app.query('[data-task="1"]').getAttribute('aria-pressed'),'true');
  assert.match(app.query('#selected-field').textContent,/tcp\.ack/);assert.equal(app.query('#top-count').textContent,'1');
  assertEnglish(app);
  app.change('#language-select','ja');
  assert.equal(app.document.documentElement.lang,'ja');assert.equal(JSON.stringify(saved(app)),before);
  assert.match(app.query('.question').textContent,/ACK/);assert.match(app.query('[data-action="check"]').textContent,/答え合わせ/);
  app.change('#language-select','en');
  restored=createRestoredApp(new Map(app.storage));assert.equal(restored.document.documentElement.lang,'en');
  openLesson(restored,lesson.id);assert.equal(restored.query('#top-count').textContent,'1');
  assert.equal(restored.errors.length,0);
 }finally{app.dom.window.close();restored?.dom.window.close();}
});

test('English help, glossary, filters, streams, errors, progress import and PCAP export remain usable',async()=>{
 const app=createApp({language:'en'});
 try{
  assertEnglish(app);
  for(const action of ['help','glossary']){app.click(`[data-action="${action}"]`);assertEnglish(app);app.click('[data-action="close-modal"]');}
  openLesson(app,'app-http-03');
  for(const action of ['filters','wireshark','stream']){app.click(`[data-action="${action}"]`);assertEnglish(app);app.click('[data-action="close-modal"]');}
  applyFilter(app,'tcp');const frames=visibleFrames(app);applyFilter(app,'bogus &&');
  assert.match(app.query('#filter-message').textContent,/unsupported/);assert.deepEqual(visibleFrames(app),frames);assertEnglish(app);
  app.click('[data-action="check"]');assertEnglish(app);
  app.click('[data-action="pcap"]');const download=app.downloads.at(-1);
  const capture=app.window.PcapData.captures.find(c=>c.id==='app-http-03-capture');
  assert.deepEqual(Buffer.from(await download.blob.arrayBuffer()),Buffer.from(capture.pcapBase64,'base64'));
  await importText(app,JSON.stringify(app.window.PcapEngine.emptyProgress()));assertEnglish(app);
  app.click('[data-action="confirm-import"]');assert.equal(app.document.documentElement.lang,'en');assertEnglish(app);
  await importText(app,JSON.stringify({app:'wrong'}));assertEnglish(app);
  assert.equal(app.errors.length,0,app.errors.map(e=>e.stack).join('\n'));
 }finally{app.dom.window.close();}
});

test('English content covers every presentation field while canonical answers and decoded captures are shared',()=>{
 const app=createApp({language:'en'});
 try{
  const source=app.window.PcapData,translated=app.window.PcapI18n.localize(source);
  assert.equal(require('../content/validate-translations')(source,source.translations.en).length,0);
  assert.equal(source.lessons.length,54);assert.equal(source.lessons.reduce((n,l)=>n+l.tasks.length,0),101);
  for(const [i,l]of translated.lessons.entries())for(const [j,t]of l.tasks.entries()){
   const original=source.lessons[i].tasks[j];for(const key of ['id','kind','answer','evidence','normalize','evidenceMode','expectedFilter'])assert.equal(t[key],original[key],`${l.id}/${t.id}: ${key}`);
   if(t.options)assert.deepEqual(Array.from(t.options,o=>o.value),Array.from(original.options,o=>o.value));
  }
  for(const [i,c]of translated.captures.entries()){assert.equal(c.packets,source.captures[i].packets);assert.equal(c.pcapBase64,source.captures[i].pcapBase64);assert.equal(c.streams,source.captures[i].streams);}
 }finally{app.dom.window.close();}
});

test('language preference tolerates blocked storage and invalid values',()=>{
 const app=createApp({unavailable:true});let invalid;
 try{app.change('#language-select','en');assert.equal(app.document.documentElement.lang,'en');assert.match(app.query('#storage-note').textContent,/Autosave/);assertEnglish(app);app.click('[data-open="ops-view-1"]');assertEnglish(app);assert.equal(app.errors.length,0,app.errors.map(e=>e.stack).join('\n'));
 invalid=createApp({language:'unsupported'});assert.equal(invalid.document.documentElement.lang,'ja');
 }finally{app.dom.window.close();invalid?.dom.window.close();}
});
