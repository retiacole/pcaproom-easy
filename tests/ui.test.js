'use strict';

// Code-level DOM integration tests only: no browser navigation, HTTP server, or
// external resources. A synthetic URL gives the mocked document a stable origin.
// Run after node build.js --data-only. Set PCAPROOM_JSDOM_MODULE if jsdom is not
// installed in this project's node_modules.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
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
  for (const [name, file] of Object.entries({ CSS: 'style.css', DATA: 'data.js', ENGINE: 'engine.js', APP: 'app.js' })) {
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

function createApp({ storage = new Map(), unavailable = false, expectedFlags = 0 } = {}) {
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
function addEvidence(app, evidence) {
  app.click(`[data-packet="${evidence.frame}"]`);
  assert.match(app.query('#selected-number').textContent, new RegExp(`No\\. ${evidence.frame}$`));
  let field = [...app.document.querySelectorAll('.field')].find(node => node.querySelector('.field-key')?.textContent === evidence.field);
  if (!field) {
    app.click('[data-action="all-fields"]');
    field = [...app.document.querySelectorAll('.field')].find(node => node.querySelector('.field-key')?.textContent === evidence.field);
  }
  assert.ok(field, `visible detail field ${evidence.field} on frame ${evidence.frame}`);
  const disclosure = field.closest('details');
  if (disclosure) disclosure.open = true;
  app.click(field);
  assert.ok(app.query('#selected-field').textContent.includes(evidence.field));
  app.click('#add-evidence');
  assert.ok(app.query('.evidence-list').textContent.includes(`No. ${evidence.frame} · ${evidence.field}`));
}
function solveLesson(app, lesson) {
  openLesson(app, lesson.id);
  const targetFilter = lesson.tasks.some(task => task.kind === 'filter') ? filters[lesson.id] : '';
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
  assert.ok(app.query('#completion-area').textContent.includes('100ポイント'), `${lesson.id} awards a flag`);
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

test('all 45 lessons are solvable through packet, detail, evidence and answer controls; progress reloads', { timeout: 120000 }, () => {
  const app = createApp();
  let reload;
  try {
    const lessons = app.window.PcapData.lessons;
    assert.equal(lessons.length, 45);
    assert.equal(app.document.querySelectorAll('.lesson-link').length, 45, 'all lessons accessible from the map');
    const kinds = new Set();
    let answered = 0;
    for (const [index, lesson] of lessons.entries()) {
      solveLesson(app, lesson);
      lesson.tasks.forEach(task => kinds.add(task.kind));
      answered += lesson.tasks.length;
      assert.equal(Number(app.query('#top-count').textContent), index + 1);
      assert.equal(completed(saved(app)), index + 1);
    }
    assert.deepEqual([...kinds].sort(), ['choice', 'filter', 'order', 'packets', 'text']);
    assert.equal(answered, lessons.reduce((sum, lesson) => sum + lesson.tasks.length, 0), 'every individual task is exercised');
    app.click('[data-action="home"]');
    assert.equal(app.query('[role="progressbar"]').getAttribute('aria-valuenow'), '45');
    assert.ok(app.query('.hero-metrics').textContent.includes('4500ポイント'));
    assert.equal(app.document.querySelectorAll('.lesson-link.done').length, 45);

    // Learners may explore a different filter after winning a flag. The saved
    // completion proof must survive, even when their current view no longer
    // matches the original answer to a filter exercise.
    openLesson(app, 'ops-filter-1');
    applyFilter(app, 'frame.number == 1');
    assert.equal(completed(saved(app)), 45);
    const snapshot = new Map(app.storage);
    app.dom.window.close();
    reload = createRestoredApp(snapshot);
    assert.equal(reload.query('#top-count').textContent, '45');
    assert.equal(reload.document.querySelectorAll('.lesson-link.done').length, 45);
    openLesson(reload, 'ops-filter-1');
    assert.equal(reload.query('#filter-input').value, 'frame.number == 1');
    assert.ok(reload.query('#completion-area').textContent.includes('100ポイント'), 'completion remains after exploratory filter edit and reload');
    assert.equal(reload.errors.length, 0);
  } finally { app.dom.window.close(); reload?.dom.window.close(); }
});

// Run the document from scratch against the previously persisted storage map.
function createRestoredApp(storage) {
  return createApp({ storage, expectedFlags: completed(JSON.parse(storage.get(STORE))) });
}

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
