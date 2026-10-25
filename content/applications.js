'use strict';

// Each answer refers to actual tshark fields in the corresponding generated PCAP.
// transportPayload is used only while building the deliverable, never in the browser.
const { transportPayload } = require('../packet-tools');

const chapters = [
  { id: 'app-tcp', title: 'TCP：接続と会話', subtitle: '接続の始まり、バイトの確認、終了を追う', icon: '⇄' },
  { id: 'app-dns', title: 'DNS：名前を調べる', subtitle: 'A・AAAA・NXDOMAINとTCPでの問い合わせ', icon: '◎' },
  { id: 'app-dhcp', title: 'DHCP：ネットワーク設定', subtitle: 'DORAと配布されたIPv4設定を読む', icon: '⌘' },
  { id: 'app-ntp', title: 'NTP：時刻を問い合わせる', subtitle: '要求・応答、Stratum、観測範囲の限界', icon: '◷' },
  { id: 'app-http', title: 'HTTP：要求と結果', subtitle: 'GET・POST・ステータスと分割された応答', icon: '▤' },
  { id: 'app-tls', title: 'TLS：暗号化された通信', subtitle: 'ClientHelloと、見える情報・見えない情報', icon: '◇' },
];
const captures = [];
const lessons = [];
const client = '10.0.0.10';
const server = '10.0.0.80';
const resolver = '10.0.0.53';
const clientMac = '02:00:00:00:00:10';
const serverMac = '02:00:00:00:00:80';
const ev = (frame, field) => ({ frame, field });
const opt = (value, label) => ({ value, label });

function textTask(id, prompt, answer, frame, field, why, normalize = 'text') {
  return { id, kind: 'text', prompt, answer: String(answer), evidence: [ev(frame, field)], normalize, why };
}
function choiceTask(id, prompt, answer, options, evidence, why, evidenceMode = 'any') {
  return { id, kind: 'choice', prompt, answer, options, evidence, evidenceMode, why };
}
function selectTask(id, prompt, answer, why, kind = 'packets') {
  return { id, kind, prompt, answer, why };
}
function add(id, chapter, title, level, intro, mission, hints, explanation, packets, tasks, description) {
  const captureId = `${id}-capture`;
  const frames = packets.map(p => ({ ...p, smac: p.smac || linkMac(p.src), dmac: p.dmac || linkMac(p.dst) }));
  captures.push({ id: captureId, title: `${title}のキャプチャ`, description, packets: frames });
  lessons.push({ id, chapter, title, level, captureId, intro, mission, hints, explanation, tasks });
}
function linkMac(ip) {
  if (ip === client) return clientMac;
  if (ip === server) return serverMac;
  if (ip === '255.255.255.255') return 'ff:ff:ff:ff:ff:ff';
  if (String(ip).startsWith('10.0.0.')) return `02:00:00:00:00:${Number(ip.split('.').pop()).toString(16).padStart(2, '0')}`;
  return '02:00:00:00:00:01'; // At the client LAN capture point, remote IPv4 peers use the router MAC.
}
function tcp(src, dst, sport, dport, flags, seq, ack, payload = '') {
  return { type: 'tcp', src, dst, sport, dport, flags, seq, ack, payload,
    smac: linkMac(src), dmac: linkMac(dst) };
}
function handshake(src = client, dst = server, sport = 51000, dport = 80, cs = 1000, ss = 9000) {
  return [tcp(src, dst, sport, dport, 'S', cs, 0), tcp(dst, src, dport, sport, 'SA', ss, cs + 1), tcp(src, dst, sport, dport, 'A', cs + 1, ss + 1)];
}
function dnsPair(name, answers, { sport = 53000, dnsId = 100, qtype = 1, rcode = 0, src = client } = {}) {
  return [
    { type: 'dns', src, dst: resolver, sport, dport: 53, dnsId, name, qtype },
    { type: 'dns', src: resolver, dst: src, sport: 53, dport: sport, dnsId, name, qtype, response: true, answers, rcode },
  ];
}
function ntpPair({ src = client, dst = '10.0.0.123', sport = 53123, stratum = 2 } = {}) {
  return [
    { type: 'ntp', src, dst, sport, dport: 123, mode: 3, stratum: 0 },
    { type: 'ntp', src: dst, dst: src, sport: 123, dport: sport, mode: 4, stratum },
  ];
}
function httpExchange({ src = client, dst = server, sport = 51000, cs = 1000, ss = 9000, request, response }) {
  const qlen = Buffer.byteLength(request);
  const rlen = Buffer.byteLength(response);
  return [
    ...handshake(src, dst, sport, 80, cs, ss),
    tcp(src, dst, sport, 80, 'PA', cs + 1, ss + 1, request),
    tcp(dst, src, 80, sport, 'A', ss + 1, cs + 1 + qlen),
    tcp(dst, src, 80, sport, 'PA', ss + 1, cs + 1 + qlen, response),
    tcp(src, dst, sport, 80, 'A', cs + 1 + qlen, ss + 1 + rlen),
  ];
}
function response(status, reason, body, type = 'text/plain') {
  return `HTTP/1.1 ${status} ${reason}\r\nContent-Type: ${type}\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: keep-alive\r\n\r\n${body}`;
}
function dhcp(message, { xid = 0x12345678, mac = clientMac, ip = '10.20.0.42', serverIp = '10.20.0.1', router = '10.20.0.254', dns = '10.20.0.53' } = {}) {
  const fromServer = message === 2 || message === 5;
  return { type: 'dhcp', message, xid, clientMac: mac,
    src: fromServer ? serverIp : '0.0.0.0', dst: '255.255.255.255',
    smac: fromServer ? '02:00:00:20:00:01' : mac, dmac: 'ff:ff:ff:ff:ff:ff',
    ...(fromServer ? { yiaddr: ip, server: serverIp, router, dns, mask: '255.255.255.0' } : {}),
    ...(message === 3 ? { requested: ip, server: serverIp } : {}) };
}
function dora(options = {}) { return [1, 2, 3, 5].map(message => dhcp(message, options)); }
function hello({ src = client, dst = '198.51.100.80', sport = 51443, cs = 2000, ss = 10000, name = 'secure.test' } = {}) {
  const record = { type: 'tls', src, dst, sport, dport: 443, flags: 'PA', seq: cs + 1, ack: ss + 1, tlsKind: 'clientHello', serverName: name };
  return [...handshake(src, dst, sport, 443, cs, ss), record, tcp(dst, src, 443, sport, 'A', ss + 1, cs + 1 + transportPayload(record).length)];
}

// TCP -----------------------------------------------------------------------
{
  const noise = dnsPair('clock.test', ['10.0.0.123'], { sport: 53001, dnsId: 201 });
  const hs = handshake(client, server, 51010, 80);
  add('app-tcp-01', 'app-tcp', 'SYNから接続開始を読む', 'guided',
    'TCPはデータを送る前に、通常SYN → SYN/ACK → ACKで接続を始めます。DNSの行が混ざっていても、同じIP・ポートの組を追いましょう。',
    '接続を開始した端末と、3ウェイハンドシェイクの3パケットを特定してください。',
    ['表示フィルターに tcp と入力すると、TCPだけになります。', 'Flagsを開き、SYNが1でACKが0のパケットを探します。これが最初の要求です。', 'No.2 → No.4 → No.5の順です。開始側のIPはNo.2のInternet Protocol Version 4 → Source Addressを確認します。'],
    'No.2のSYNを10.0.0.10が送り、No.4で10.0.0.80がSYN/ACKを返し、No.5で端末がACKしています。ここまででTCP接続の成立を確認できますが、Webページの取得成功までは分かりません。',
    [noise[0], hs[0], noise[1], hs[1], hs[2]],
    [textTask('client', 'TCP接続を開始した端末のIPv4アドレスは？', client, 2, 'ip.src', '最初のSYNの送信元が、この接続を開始した側です。', 'ip'),
      selectTask('handshake', 'ハンドシェイクの3パケットを、開始から順に選んでください。', [2, 4, 5], 'SYN、SYN/ACK、ACKの順です。DNSの2行はこの接続には含みません。', 'order')],
    'DNSとTCPが混在する短いキャプチャ。TCPの3ウェイハンドシェイクをすべて収録。');
}
{
  const sport = 51020;
  const packets = [...handshake(client, server, sport, 9000),
    tcp(client, server, sport, 9000, 'PA', 1001, 9001, 'HELLO'),
    tcp(server, client, 9000, sport, 'A', 9001, 1006),
    { type: 'udp', src: '10.0.0.25', dst: '10.0.0.26', sport: 54000, dport: 54001, payload: 'status' },
    tcp(server, client, 9000, sport, 'PA', 9001, 1006, 'OK'),
    tcp(client, server, sport, 9000, 'A', 1006, 9003)];
  add('app-tcp-02', 'app-tcp', 'ACKは次にほしいバイト', 'practice',
    'TCPのSeqとAckは、バイトの位置を表します。この画面では相対番号を使い、SYNを0、その次を1として表示します。ACK番号は次に受信したいバイトの番号です。',
    '5バイトの送信と、その受信確認を対応づけてください。',
    ['10.0.0.10 → 10.0.0.80のTCPで、Lenが0より大きい行を探します。', 'No.4にはHELLOの5バイトが入っています。相対Seqは1です。', 'No.5のAcknowledgment Numberを確認します。1から5の5バイトを受け取った後、次にほしい番号は6です。'],
    'No.4は相対Seq=1から5バイトを送り、No.5はAck=6でそこまでの受信を確認しています。ACKはTCPの受信確認です。アプリが内容を処理し終えた、保存した、という証明ではありません。',
    packets,
    [textTask('length', '端末がNo.4で送ったTCPペイロードは何バイト？', '5', 4, 'tcp.len', 'TCP Segment Lenが5です。EthernetやIPヘッダーを含むフレーム全体の長さとは異なります。', 'number'),
      textTask('ack', 'その5バイトを確認したNo.5の相対ACK番号は？', '6', 5, 'tcp.ack', 'Seq=1から5バイトなので、次に期待するバイトは6です。', 'number'),
      selectTask('conversation', 'このTCP接続に属するパケットをすべて選んでください。', [1, 2, 3, 4, 5, 7, 8], '同じ接続はIP・ポートの組とTCP Streamで追えます。No.6は別のUDP通信です。')],
    'ポート9000の教材用TCP通信。HELLOの5バイトとOKの2バイトを送受信し、途中に無関係なUDPを収録。');
}
{
  const a = 51030, b = 51031;
  const packets = [...handshake(client, server, a, 9000),
    tcp(client, server, a, 9000, 'FA', 1001, 9001), tcp(server, client, 9000, a, 'A', 9001, 1002),
    tcp(server, client, 9000, a, 'FA', 9001, 1002), tcp(client, server, a, 9000, 'A', 1002, 9002),
    ...handshake(client, server, b, 9000, 3000, 12000),
    tcp(client, server, b, 9000, 'PA', 3001, 12001, 'PING'), tcp(server, client, 9000, b, 'RA', 12001, 3005)];
  add('app-tcp-03', 'app-tcp', 'FINとRSTを見分ける', 'challenge',
    'FINはその方向の送信を終了する通知です。RSTは接続のリセットを示します。フラグから観測された終了の仕方を説明し、原因は別に考えましょう。',
    '2つの接続から、FINとACKによる終了と、RSTによるリセットを探してください。',
    ['送信元ポート51030と51031で、2つの接続を分けます。', 'tcp.flags.fin == 1 と tcp.flags.reset == 1 を試すと、終了を示す行が見つかります。', '前半はNo.4 → 5 → 6 → 7で両方向を閉じています。後半のNo.12にはRSTが設定されています。'],
    '最初の接続はNo.4のFINをNo.5で確認し、逆方向もNo.6のFINとNo.7のACKで終了しています。2つ目はNo.12のRSTを観測しました。RSTだけで攻撃、サーバー故障、利用者の操作のどれかと断定することはできません。',
    packets,
    [selectTask('close', '前半の接続を終了する4パケットを順に選んでください。', [4, 5, 6, 7], 'FINは1つのシーケンス番号を使います。双方のFINと、それに対するACKを追います。', 'order'),
      selectTask('reset', 'RSTが設定されているパケットを選んでください。', [12], 'No.12のTCP FlagsでResetが設定されています。'),
      choiceTask('conclusion', 'No.12だけから言えることは？', 'reset-seen', [opt('reset-seen', 'この接続でRSTを観測した'), opt('attack', '必ず攻撃が起きた'), opt('power', 'サーバーの電源が落ちた')], [ev(12, 'tcp.flags.reset')], 'パケットはリセットを示しますが、リセットが起きた背景まではこのフラグだけでは分かりません。')],
    '同じ端末間の2つのTCP接続。1つはFINとACKで終了し、もう1つはデータ送信後にRSTを受信。');
}

// DNS -----------------------------------------------------------------------
{
  const d = dnsPair('portal.test', ['192.0.2.80'], { dnsId: 301 });
  const n = ntpPair();
  add('app-dns-01', 'app-dns', '名前とIPv4の答えを読む', 'guided',
    'DNSのQueryは問い合わせ、Answerは回答です。AレコードはIPv4アドレスを返します。IPヘッダーの送信元・宛先と、DNSの回答に入っているIPを区別しましょう。',
    '問い合わせた名前と、その名前に返されたIPv4アドレスを答えてください。',
    ['dns と入力してNTPを除き、2つのDNSパケットを見ます。', 'No.2のDomain Name System → Queries → Nameを開きます。', 'No.3は応答です。Answers内のAddressに返されたIPがあります。IPヘッダーの10.0.0.53はDNSサーバー自身です。'],
    'portal.testへのA問い合わせに対し、DNSサーバーは192.0.2.80を回答しています。DNSサーバーのアドレス10.0.0.53と、名前解決されたWebサーバーのアドレスは別です。この回答だけでは、Webサーバーへの接続成功は確認できません。',
    [n[0], d[0], d[1], n[1]],
    [textTask('name', '問い合わせた名前は？', 'portal.test', 2, 'dns.qry.name', '問い合わせ内容はDNSのQueriesにあります。'),
      textTask('address', 'DNS回答に入っているIPv4アドレスは？', '192.0.2.80', 3, 'dns.a', 'DNS AnswerのAレコードが返されたIPv4です。', 'ip')],
    'Aレコードの問い合わせと回答。別の時刻同期通信を混在させて、表示フィルターも練習。');
}
{
  const v6 = dnsPair('v6.portal.test', ['2001:db8:20::80'], { dnsId: 302, qtype: 28, sport: 53002 });
  const absent = dnsPair('missing.test', [], { dnsId: 303, rcode: 3, sport: 53003 });
  add('app-dns-02', 'app-dns', 'AAAAとNXDOMAIN', 'practice',
    'AAAAレコードはIPv6アドレスを返します。問い合わせ自体がIPv4で運ばれていても、回答にIPv6を含められます。NXDOMAINは問い合わせた名前が存在しないことを示す応答コードです。',
    'IPv6の回答と、名前が存在しないという回答を読み分けてください。',
    ['No.1とNo.2はv6.portal.test、No.3とNo.4はmissing.testの組です。', 'No.2のAnswersでAAAAを確認します。No.4はFlagsのReply codeを確認します。', 'IPv6の回答は2001:db8:20::80です。No.4のrcode=3はNXDOMAINを意味します。'],
    'v6.portal.testのAAAA回答は2001:db8:20::80です。missing.testにはNXDOMAINが返っています。NXDOMAINを、通信に応答がない状態や、存在する名前に特定の種類のレコードがない状態と混同しないようにします。',
    [...v6, ...absent, { type: 'udp', src: '10.0.0.30', dst: '10.0.0.31', sport: 55000, dport: 55001, payload: 'heartbeat' }],
    [textTask('aaaa', 'v6.portal.testに返されたIPv6アドレスは？', '2001:db8:20::80', 2, 'dns.aaaa', 'AAAAレコードのAddressを読みます。DNSパケットのIPヘッダーは今回IPv4です。', 'ip'),
      choiceTask('nxdomain', 'missing.testへの応答コードが示す内容は？', 'name-missing', [opt('name-missing', '問い合わせた名前が存在しない'), opt('no-packet', 'DNSの応答パケットが届いていない'), opt('web-error', 'Webサーバーが404を返した')], [ev(4, 'dns.flags.rcode')], 'No.4にはDNS応答があり、rcode=3です。これはHTTPのステータスコードではありません。')],
    'IPv4上のDNSでAAAA回答を受信する例と、別名へのNXDOMAIN応答。');
}
{
  const q = { type: 'dns', src: client, dst: resolver, sport: 53040, dport: 53, dnsId: 304, name: 'tcp-dns.test', qtype: 1, transport: 'tcp', flags: 'PA', seq: 4001, ack: 16001 };
  const a = { type: 'dns', src: resolver, dst: client, sport: 53, dport: 53040, dnsId: 304, name: 'tcp-dns.test', qtype: 1, response: true, answers: ['192.0.2.44'], transport: 'tcp', flags: 'PA', seq: 16001, ack: 4001 + transportPayload(q).length };
  const packets = [...dnsPair('udp-dns.test', ['192.0.2.33'], { dnsId: 305, sport: 53041 }),
    ...handshake(client, resolver, 53040, 53, 4000, 16000), q,
    tcp(resolver, client, 53, 53040, 'A', 16001, 4001 + transportPayload(q).length), a,
    tcp(client, resolver, 53040, 53, 'A', 4001 + transportPayload(q).length, 16001 + transportPayload(a).length)];
  add('app-dns-03', 'app-dns', 'DNSはTCPでも運ばれる', 'challenge',
    'DNSはUDPだけのプロトコルではありません。このキャプチャにはUDP上のDNSとTCP上のDNSが両方あります。プロトコルの階層を開いて確かめましょう。',
    'TCP上のDNSメッセージだけを表示し、回答されたIPを確認してください。',
    ['まずdnsで絞ると、問い合わせと応答が4行残ります。', 'TCP上だけを残すには dns && tcp のように条件を組み合わせます。', '残るのはNo.6とNo.8です。No.8のDNS Answersには192.0.2.44があります。'],
    'dns && tcpでNo.6とNo.8が残ります。No.3〜5のハンドシェイクやNo.7・9のACKはTCPですが、DNSメッセージを含みません。DNSがTCPを使う理由は複数あり、このキャプチャだけからUDPからの切り替えが起きたとは断定できません。',
    packets,
    [selectTask('filter', 'TCP上のDNSメッセージだけを残す表示フィルターを適用してください。', [6, 8], 'dns && tcpが一例です。同じパケット集合になる有効なフィルターも正解です。', 'filter'),
      textTask('reply', 'TCP上のDNS応答で返されたIPv4アドレスは？', '192.0.2.44', 8, 'dns.a', 'TCP接続の中で運ばれたDNS応答のAレコードです。', 'ip'),
      textTask('port', 'TCP上のDNS問い合わせの宛先ポートは？', '53', 6, 'tcp.dstport', 'No.6のTCP Destination Portを確認します。UDPのポート欄ではありません。', 'number')],
    '独立したUDPのDNS交換と、ハンドシェイクから収録したTCPのDNS交換。UDP応答切り詰めによるフォールバックを再現するものではない。');
}

// DHCPv4 --------------------------------------------------------------------
add('app-dhcp-01', 'app-dhcp', 'DORAで設定を受け取る', 'guided',
  'DHCPv4の代表的な初期取得はDiscover → Offer → Request → ACKです。Offerは提案、ACKはサーバーによる割り当て確認です。まだ自分のIPv4を持たない端末の0.0.0.0にも注目します。',
  '4つのメッセージを順番に選び、ACKされたIPv4アドレスを読み取ってください。',
  ['各パケットのDHCP → Option: (53) DHCP Message Typeを開きます。', 'Discover=1、Offer=2、Request=3、ACK=5です。4という値がACKではないことに注意します。', '順番はNo.1 → 2 → 3 → 4です。No.4のYour (client) IP addressに10.20.0.42があります。'],
  '端末の探索にサーバーが10.20.0.42を提案し、端末が要求、サーバーがACKしています。ACKパケットのYour IP addressが割り当て確認されたIPv4です。実際に端末OSが設定を適用したかは、このACKだけでは確認できません。',
  dora(),
  [selectTask('dora', 'Discover、Offer、Request、ACKの順にパケットを選んでください。', [1, 2, 3, 4], 'DHCP Message Typeの1、2、3、5を順に追います。', 'order'),
    textTask('allocated', 'サーバーがACKしたIPv4アドレスは？', '10.20.0.42', 4, 'dhcp.ip.your', 'ACKのYour (client) IP addressを読みます。', 'ip')],
  'DHCPv4の初期取得を4パケットで収録。DHCPリレーを挟まない同一セグメントの教材用通信。');
{
  const a = dora({ xid: 0x22220001, mac: clientMac, ip: '10.20.0.42' });
  const b = dora({ xid: 0x22220002, mac: '02:00:00:00:00:20', ip: '10.20.0.43', router: '10.20.0.253', dns: '10.20.0.54' });
  add('app-dhcp-02', 'app-dhcp', 'IP以外の配布設定を読む', 'practice',
    'DHCPはIPアドレスだけでなく、ルーターやDNSサーバーなども配布します。2台の取得が混在しているので、Your IP addressを確認して対象のACKを選びましょう。',
    '10.20.0.42へのACKで配布されたルーターとDNSサーバーを確認してください。',
    ['DHCP Message TypeがACKの行は2つあります。Your IP addressが10.20.0.42の行を探します。', 'No.7が対象のACKです。OptionsのRouterとDomain Name Serverを開きます。', 'Routerは10.20.0.254、Domain Name Serverは10.20.0.53です。No.8は別端末向けの値です。'],
    '対象のACKはNo.7です。Routerオプションは10.20.0.254、Domain Name Serverオプションは10.20.0.53を示します。DHCPサーバー、ルーター、DNSサーバーは同じ機器とは限りません。今回のDHCPサーバーは10.20.0.1です。',
    [a[0], b[0], a[1], b[1], a[2], b[2], a[3], b[3]],
    [textTask('router', '10.20.0.42に配布されたルーターのIPv4アドレスは？', '10.20.0.254', 7, 'dhcp.option.router', '対象ACKのRouterオプションを読みます。DHCPサーバーのIPとは別です。', 'ip'),
      textTask('dns', '同じACKに含まれるDNSサーバーのIPv4アドレスは？', '10.20.0.53', 7, 'dhcp.option.domain_name_server', 'Domain Name Serverオプションは、今後の名前解決に使うDNSサーバーの指定です。', 'ip')],
    '2台のDHCPv4取得が交互に現れる8パケット。異なるTransaction ID、クライアントMAC、割り当てIPを使用。');
}
{
  const common = { xid: 0x33330001, ip: '10.30.0.20', serverIp: '10.30.0.1', router: '10.30.0.254', dns: '10.30.0.53' };
  const other = { ...common, ip: '10.30.0.90', serverIp: '10.30.0.2' };
  add('app-dhcp-03', 'app-dhcp', '2つのOfferから選択を追う', 'challenge',
    'Discoverに複数のサーバーがOfferを返す場合があります。Offerを見ただけで最終的な割り当てを決めず、RequestのServer Identifierと最後のACKまで追いましょう。',
    '端末が選んだDHCPサーバーと、ACKされたIPv4アドレスを特定してください。',
    ['No.2とNo.3は同じDiscoverへの異なるOfferです。', 'No.4のRequestでDHCP Server Identifierを開き、端末が選んだサーバーを確認します。', 'Requestは10.30.0.1を選択しています。No.5のACKのYour IP addressは10.30.0.20です。'],
    '10.30.0.1と10.30.0.2がそれぞれ提案しましたが、端末はRequestのServer Identifierで10.30.0.1を選んでいます。No.5のACKで10.30.0.20が確認されました。複数のOfferだけを理由に、不正なDHCPサーバーがいるとは断定できません。',
    [dhcp(1, common), dhcp(2, common), { ...dhcp(2, other), smac: '02:00:00:30:00:02' }, dhcp(3, common), dhcp(5, common)],
    [textTask('chosen', 'Requestで選択されたDHCPサーバーは？', '10.30.0.1', 4, 'dhcp.option.dhcp_server_id', 'RequestのServer Identifierが選択されたサーバーを示します。', 'ip'),
      textTask('final', 'ACKされたIPv4アドレスは？', '10.30.0.20', 5, 'dhcp.ip.your', '最終的な確認はOfferではなくACKで行います。', 'ip'),
      selectTask('ack-only', '割り当て確認のACKパケットを選んでください。', [5], 'No.5のDHCP Message TypeはACKです。No.2と3は提案段階です。')],
    '1つのDiscoverに2つのOfferが返り、端末が一方のサーバーを選択してACKを受信する例。');
}

// NTP -----------------------------------------------------------------------
{
  const n = ntpPair({ dst: '10.0.0.123', sport: 54123 });
  const d = dnsPair('time.test', ['10.0.0.123'], { dnsId: 401, sport: 54001 });
  add('app-ntp-01', 'app-ntp', '時刻の要求と応答', 'guided',
    'NTPはネットワーク越しの時刻同期に使われます。ここではクライアントのMode 3とサーバーのMode 4を対応づけます。UDPの送信元・宛先ポートも確認しましょう。',
    '問い合わせ先の時刻サーバーと、NTP応答のパケットを特定してください。',
    ['ntp で絞ると2行が残ります。DNS回答のIPとNTPの宛先も比較できます。', 'No.3のNTP Flags → ModeはClient (3)、No.4はServer (4)です。', 'No.3のIPv4 Destinationは10.0.0.123です。応答として選ぶのはNo.4です。'],
    '端末は10.0.0.123にMode 3の要求を送り、Mode 4の応答を受信しています。UDPではTCPのようなハンドシェイクはありません。要求・応答があることと、TCPの接続があることを分けて考えます。',
    [d[0], d[1], n[0], n[1]],
    [textTask('server', 'NTP要求の宛先IPv4アドレスは？', '10.0.0.123', 3, 'ip.dst', 'No.3の宛先が、問い合わせた時刻サーバーです。', 'ip'),
      selectTask('reply', 'NTPのサーバー応答を選んでください。', [4], 'Mode=4と、要求に対応するIP・ポートの逆方向を確認します。'),
      textTask('mode', '選んだNTP応答のMode番号は？', '4', 4, 'ntp.flags.mode', 'この教材の通常のクライアント・サーバー交換では、サーバー応答はMode 4です。', 'number')],
    '名前解決に続くNTP要求・応答。日時値は教材用であり、現実の現在時刻や精度の判定には使わない。');
}
{
  add('app-ntp-02', 'app-ntp', 'Stratumは精度の保証ではない', 'practice',
    'Stratumは基準時計からの階層を表す値です。通常の同期されたサーバーでは1、2、3…と階層をたどりますが、Stratumの大小だけで時刻の誤差やサーバーの信頼性は判断できません。',
    '2台の応答のStratumを確認し、この数値から言えることを選んでください。',
    ['応答はNo.2とNo.4です。それぞれのNTP → Peer Clock Stratumを確認します。', '10.0.0.123の応答は2、10.0.0.124の応答は3です。', '数値は時計の階層です。「必ず正確」「必ず安全」といった結論は、この値だけでは出せません。'],
    '応答にはStratum 2と3が示されています。これは申告された時計の階層で、今回のパケットだけで実際の誤差は測れません。同期の良否を調べるときは時刻差、遅延、分散、複数の観測なども必要です。',
    [...ntpPair({ dst: '10.0.0.123', sport: 54201, stratum: 2 }), ...ntpPair({ dst: '10.0.0.124', sport: 54202, stratum: 3 })],
    [textTask('stratum', '10.0.0.123の応答のStratumは？', '2', 2, 'ntp.stratum', '対象サーバーから来た応答のPeer Clock Stratumを読みます。', 'number'),
      choiceTask('meaning', 'この2つのStratumから言えることは？', 'hierarchy', [opt('hierarchy', '申告された時計の階層が異なる'), opt('exact', 'Stratum 2の時計は必ず誤差ゼロ'), opt('safe', 'Stratum 3のサーバーは必ず安全')], [ev(2, 'ntp.stratum'), ev(4, 'ntp.stratum')], '階層は読めますが、誤差や安全性はこの値だけでは確定しません。', 'all')],
    '同じ端末が2台のNTPサーバーに問い合わせ、Stratum 2と3の応答を受信する例。時計精度の比較実験ではない。');
}
{
  const n1 = ntpPair({ dst: '10.0.0.123', sport: 54301 });
  const n2 = ntpPair({ src: '10.0.0.20', dst: '10.0.0.124', sport: 54302 });
  const d = dnsPair('portal.test', ['192.0.2.80'], { dnsId: 402, sport: 54303 });
  const packets = [{ ...n1[0], time: 0 }, { ...d[0], time: 0.1 }, { ...d[1], time: 0.12 },
    { ...n1[0], time: 5 }, { ...n2[0], time: 5.1 }, { ...n2[1], time: 5.12 }];
  add('app-ntp-03', 'app-ntp', '応答がない範囲を説明する', 'challenge',
    'キャプチャは通信の一部を、特定の場所と時間で記録したものです。応答が見つからないときは、観測できたことと原因の推測を分けて書きます。',
    '10.0.0.10のNTP要求を抽出し、応答の見え方から適切な報告を選んでください。',
    ['ntp && ip.addr == 10.0.0.10 で対象端末のNTPだけを残します。', '残るNo.1とNo.4はいずれもMode 3です。No.6の応答は別端末・別サーバーの通信です。', '正確な報告は「このキャプチャには、対象要求に対応する応答が見当たらない」です。サーバー停止と決めつけません。'],
    '10.0.0.10から10.0.0.123へのNTP要求を2回観測しましたが、対応する応答はこの記録にありません。フィルター、取得場所、記録時間、経路、損失などが影響する可能性があり、これだけでサーバー停止は断定できません。',
    packets,
    [selectTask('requests', '10.0.0.10から送信されたNTP要求だけを選んでください。', [1, 4], 'No.1とNo.4は対象端末のMode 3です。別端末のNo.5・6は含めません。'),
      choiceTask('report', 'キャプチャ全体を確認した後の報告として適切なのは？', 'not-observed', [opt('not-observed', 'この記録には、対象要求に対応する応答が見当たらない'), opt('down', '時刻サーバーの停止が証明された'), opt('success', '別端末の応答があるので対象要求も成功した')], [ev(1, 'ntp.flags.mode'), ev(4, 'ntp.flags.mode')], '選んだ2パケットは要求の存在を示します。応答が記録されていない原因の特定には、追加の観測が必要です。', 'all')],
    '対象端末の2回のNTP要求には応答が収録されていない。別端末のNTP交換とDNS交換も含む有限の観測窓。');
}

// HTTP ----------------------------------------------------------------------
{
  const request = 'GET /index.html HTTP/1.1\r\nHost: portal.test\r\nUser-Agent: pcaproom-easy\r\n\r\n';
  add('app-http-01', 'app-http', 'GETと200 OKを対応づける', 'guided',
    '平文HTTPでは、要求のMethod・Host・URIと応答のStatus Codeを読めます。TCP接続ができたかだけでなく、アプリがどんな結果を返したかまで確認します。',
    '要求されたパスと、その要求へのHTTPステータスコードを答えてください。',
    ['http で絞ると要求と応答が残ります。No.4はGET、No.6はHTTP/1.1 200 OKです。', '要求のRequest URIにはパスがあり、Hostには接続先の名前があります。', 'No.4のURIは/index.html、No.6のStatus Codeは200です。TCPのACK番号とは別の情報です。'],
    '端末はportal.testの/index.htmlをGETし、サーバーは200 OKと本文を返しています。200はこのHTTP要求の成功を示しますが、ページ内の画像を含むすべての取得や、画面表示の完了まで証明するものではありません。',
    httpExchange({ sport: 51101, request, response: response(200, 'OK', '<h1>Hello</h1>\n', 'text/html') }),
    [textTask('path', 'GETで要求されたパスは？', '/index.html', 4, 'http.request.uri', 'Request URIを読みます。Host名と合わせると要求先を整理できます。', 'exact'),
      textTask('status', 'この要求に対するHTTPステータスコードは？', '200', 6, 'http.response.code', 'HTTPのStatus Codeが200です。', 'number')],
    '1つのHTTP/1.1 GETと、Content-Lengthに一致する完全な200 OK応答。TCPハンドシェイクを含む。');
}
{
  const get = 'GET /old.txt HTTP/1.1\r\nHost: portal.test\r\n\r\n';
  const body = 'message=hello';
  const post = `POST /api/notes HTTP/1.1\r\nHost: portal.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
  const packets = [...httpExchange({ sport: 51102, request: get, response: response(404, 'Not Found', 'No such file\n') }),
    ...httpExchange({ sport: 51103, cs: 4000, ss: 18000, request: post, response: response(201, 'Created', '{"id":7}\n', 'application/json') })];
  add('app-http-02', 'app-http', 'POSTと404を混同しない', 'practice',
    '同じWebサーバーでも、要求ごとにMethodや結果は異なります。POSTの要求本文も、平文HTTPなら観測できます。ポートだけでなく、TCP接続と要求・応答の対応を追いましょう。',
    '2つの要求を読み分け、/old.txtの結果と/api/notesのMethodを特定してください。',
    ['http で絞ると、GET、404、POST、201の4行が残ります。', '/old.txtは送信元ポート51102、/api/notesは51103の接続です。', 'No.6は/old.txtへの404です。No.11の/api/notesへのMethodはPOSTで、No.13の結果は201です。'],
    'GET /old.txtには404、POST /api/notesには201が返りました。404でもTCP通信とHTTP応答は成立しています。404は要求したリソースが見つからなかったことを示し、それだけで攻撃やネットワーク断とは判断できません。POSTの本文はmessage=helloです。',
    packets,
    [textTask('method', '/api/notesへの要求Methodは？', 'POST', 11, 'http.request.method', '対象のURIと同じ要求にあるRequest Methodを確認します。', 'exact'),
      textTask('get-status', '/old.txtの取得に対するHTTPステータスコードは？', '404', 6, 'http.response.code', '同じTCP接続のGETと応答を組にします。別接続の201と取り違えないようにします。', 'number'),
      choiceTask('404-meaning', 'No.6から分かることは？', 'http-response', [opt('http-response', 'サーバーから404のHTTP応答を受け取った'), opt('tcp-failed', 'TCP接続が一度も成立しなかった'), opt('attack', '攻撃が起きたと確定した')], [ev(6, 'http.response.code')], '404というアプリの結果を観測しています。通信できないことと、要求したものが見つからないことは別です。')],
    '2つのHTTP/1.1接続。GETへの404と、本文を持つPOSTへの201。全メッセージはContent-Lengthを持つ完全な平文HTTP。');
}
{
  const sport = 51104, cs = 6000, ss = 20000;
  const request = 'GET /report.txt HTTP/1.1\r\nHost: portal.test\r\n\r\n';
  const complete = response(200, 'OK', 'packet-reading\n');
  const split = complete.indexOf('\r\n\r\n') + 6;
  const part1 = complete.slice(0, split), part2 = complete.slice(split);
  const qend = cs + 1 + Buffer.byteLength(request);
  const packets = [...handshake(client, server, sport, 80, cs, ss),
    tcp(client, server, sport, 80, 'PA', cs + 1, ss + 1, request), tcp(server, client, 80, sport, 'A', ss + 1, qend),
    tcp(server, client, 80, sport, 'PA', ss + 1, qend, part1),
    { type: 'udp', src: '10.0.0.30', dst: '10.0.0.31', sport: 56000, dport: 56001, payload: 'status' },
    tcp(server, client, 80, sport, 'PA', ss + 1 + Buffer.byteLength(part1), qend, part2),
    tcp(client, server, sport, 80, 'A', qend, ss + 1 + Buffer.byteLength(complete))];
  add('app-http-03', 'app-http', '分割された応答をつなぐ', 'challenge',
    '1つのHTTPメッセージが、複数のTCPセグメントに分かれることがあります。再構成されたHTTPの詳細と「ストリームを追う」を使い、パケット1行だけで判断しない練習をします。',
    '応答データを運ぶ2パケットを見つけ、再構成後のHTTP結果を答えてください。',
    ['サーバー10.0.0.80から端末へのTCPで、TCP Segment Lenが0より大きい行を探します。', 'No.6とNo.8が応答のバイトを運びます。No.7は無関係のUDPです。', 'No.8でHTTP応答が再構成され、Status Codeは200になります。ストリーム表示でも応答本文packet-readingを確認できます。'],
    '応答はNo.6とNo.8に分割されています。No.8まで届いたところで完全なHTTPメッセージとして再構成され、200 OKと本文を確認できます。途中に別通信が挟まっていても、同じTCP接続のシーケンス番号に沿って読みます。',
    packets,
    [selectTask('segments', 'HTTP応答のデータを運ぶサーバー側の2パケットを選んでください。', [6, 8], 'サーバー側かつTCPペイロードを持つNo.6とNo.8です。純粋なACKや無関係なUDPは含めません。'),
      textTask('reassembled', '再構成されたHTTP応答のステータスコードは？', '200', 8, 'http.response.code', '再構成が完了したNo.8のHTTP詳細を根拠にします。', 'number')],
    'HTTP応答を2つのTCPセグメントに分割。Content-Lengthは本文全体と一致し、再構成後にHTTPとして解析される。');
}

// TLS -----------------------------------------------------------------------
{
  add('app-tls-01', 'app-tls', 'ClientHelloの名前を読む', 'guided',
    'TLSのClientHelloには、SNIとして接続先の名前が含まれる場合があります。この教材では暗号化されていないClientHelloを収録しています。IPヘッダーの宛先とSNIの名前は別々に確認します。',
    'このClientHelloで送られたSNIと、パケットの宛先IPを答えてください。',
    ['No.4のTLS → Handshake Protocol: Client Helloを開きます。', 'Extension: server_nameの中のServer NameがSNIです。', 'SNIはsecure.testです。宛先IPは同じNo.4のIPv4 Destination Addressにある198.51.100.80です。'],
    '今回のClientHelloではSNI=secure.testを観測できます。これは要求されたサーバー名の情報で、URLのパスやHTTP本文ではありません。SNIが省略された通信や、ClientHelloの一部を暗号化する仕組みもあり、名前が必ず平文で見えるとは限りません。',
    [...hello(), { type: 'udp', src: '10.0.0.30', dst: '10.0.0.31', sport: 57000, dport: 57001, payload: 'status' }],
    [textTask('sni', 'このClientHelloのSNIに入っている名前は？', 'secure.test', 4, 'tls.handshake.extensions_server_name', 'ClientHelloのserver_name拡張を根拠にします。'),
      textTask('destination', 'このClientHelloの宛先IPv4アドレスは？', '198.51.100.80', 4, 'ip.dst', '宛先IPはIPv4ヘッダーから読めます。SNIの名前とは別の層の情報です。', 'ip')],
    '教材用の有効なTLS ClientHelloとそのTCP受信確認。完全なTLS接続や証明書検証の成功を示すキャプチャではない。');
}
{
  const src = '198.51.100.81', sport = 51543;
  const record = { type: 'tls', tlsKind: 'applicationData', src, dst: client, sport: 443, dport: sport, flags: 'PA', seq: 25001, ack: 7001 };
  const packets = [tcp(client, src, sport, 443, 'A', 7001, 25001), record,
    tcp(client, src, sport, 443, 'A', 7001, 25001 + transportPayload(record).length),
    { type: 'udp', src: '10.0.0.30', dst: '10.0.0.31', sport: 57002, dport: 57003, payload: 'status' }];
  add('app-tls-02', 'app-tls', '暗号化された本文の限界', 'practice',
    'この記録は通信の途中から始まり、TLS Application Dataの形をした観察用の不透明なデータを含みます。復号情報はありません。ヘッダーから分かる情報と、本文を読まないと分からない情報を分けます。',
    '送信元を確認し、HTTPのURLパスをこの記録から読めるか判断してください。',
    ['No.2を選びます。IPとTCPのヘッダーは見えますが、HTTPの要求行は表示されません。', 'TLSのRecord LayerでContent Typeを確認します。Application Dataは23です。', '送信元IPは198.51.100.81です。復号できる情報がないため、この記録からHTTPのパスを特定できません。'],
    'No.2の送信元IPは198.51.100.81で、TLSレコードのContent TypeはApplication Dataです。これだけではHTTPのMethod、パス、本文を読むことはできません。教材の不透明データは実セッションの暗号文を復号できる形で再現したものではなく、成功したTLS接続を証明するものでもありません。',
    packets,
    [textTask('sender', 'Application Dataレコードの送信元IPv4アドレスは？', '198.51.100.81', 2, 'ip.src', '暗号化された通信でも、ここで収録したIPヘッダーの送信元は読めます。', 'ip'),
      choiceTask('path-limit', '復号情報のないこの記録から、HTTPのURLパスを特定できる？', 'cannot-read', [opt('cannot-read', 'この記録だけでは特定できない'), opt('root-path', '必ず/であると分かる'), opt('all-readable', 'TCPの443番ポートを開けば全文が読める')], [ev(2, 'tls.record.content_type')], 'TLS Application Dataがあることと、暗号化されたアプリの内容が読めることは別です。')],
    '途中からの取得を模したTLS Application Dataレコード。ペイロードは教材用の不透明バイトであり、実セッションの鍵や復号可能な暗号文は含まない。');
}
{
  const withName = hello({ dst: '198.51.100.82', sport: 51643, cs: 8000, ss: 28000, name: 'known.test' });
  const withoutName = hello({ dst: '198.51.100.83', sport: 51644, cs: 10000, ss: 30000, name: '' });
  add('app-tls-03', 'app-tls', '名前が見えない通信もある', 'challenge',
    '2つのClientHelloを比較します。一方にはSNIがあり、もう一方にはありません。拡張がない場合も、宛先IPなど実際に観測できる情報で整理しましょう。',
    'SNIが記録されたパケットを選び、もう一方の通信で確認できる宛先IPを答えてください。',
    ['ClientHelloはNo.4とNo.9です。TLSの拡張一覧を比較します。', 'No.4にはserver_name=known.testがあります。No.9にはserver_name拡張がありません。', 'SNIを選ぶのはNo.4だけです。No.9のIPv4 Destinationは198.51.100.83で、名前を推測する必要はありません。'],
    'No.4にはknown.testというSNIがあり、No.9にはSNIがありません。後者でも宛先IP=198.51.100.83は確認できます。SNIの不在だけで異常と判断したり、IPからホスト名を一意に決めたりはできません。実際の通信では取得範囲や暗号化の仕組みも、名前の見え方に影響します。',
    [...withName, ...withoutName],
    [selectTask('visible-name', 'SNIのServer Nameフィールドが実際にあるパケットを選んでください。', [4], 'No.4にはserver_name拡張があります。No.9のClientHelloにはありません。'),
      textTask('nameless-ip', 'SNIのないClientHelloの宛先IPv4アドレスは？', '198.51.100.83', 9, 'ip.dst', '名前が見えなくても、No.9のIPv4ヘッダーは確認できます。', 'ip'),
      choiceTask('interpret', 'No.9について適切な説明は？', 'limited', [opt('limited', 'このClientHelloにはSNIがなく、宛先IPは確認できる'), opt('same-name', '必ずknown.testへの接続である'), opt('invalid', 'SNIがないため必ず不正な通信である')], [ev(9, 'tls.handshake.type')], 'ClientHelloを開いて拡張一覧を確認します。SNIは必ず存在するフィールドではありません。')],
    'SNIありとSNIなしの2つの有効な教材用ClientHello。ECHの暗号化自体を実装するものではない。');
}

module.exports = { chapters, captures, lessons };
