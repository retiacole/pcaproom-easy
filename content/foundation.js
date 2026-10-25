'use strict';

// All frames are synthetic teaching traffic. The packet builder produces the
// actual Ethernet/IP bytes and tshark supplies every displayed protocol field.
const chapters = [
  { id: 'base-ethernet', title: 'Ethernet', subtitle: '同じリンク上で届けるための宛先', icon: '▦' },
  { id: 'base-arp', title: 'ARP', subtitle: 'IPv4アドレスからMACアドレスを調べる', icon: '⇄' },
  { id: 'base-ip', title: 'IPv4 / IPv6', subtitle: '通信相手とパケットの寿命', icon: '◎' },
  { id: 'base-icmp', title: 'ICMP', subtitle: '疎通確認とエラー通知を読み分ける', icon: '↩' },
  { id: 'base-icmp6', title: 'ICMPv6 / NDP', subtitle: 'IPv6の疎通確認・近隣探索・ルーター通知', icon: '◇' },
  { id: 'base-udp', title: 'UDP', subtitle: 'データグラムのヘッダーとアプリの応答', icon: '↗' }
];

const captures = [
  {
    id: 'base-eth-addresses', title: 'Ethernetの送信元',
    description: '同じLANの端末10.10.1.20とサーバー10.10.1.30が短いUDPメッセージを交換しています。',
    packets: [
      { type: 'udp', src: '10.10.1.20', dst: '10.10.1.30', smac: '02:10:00:00:00:20', dmac: '02:10:00:00:00:30', sport: 51020, dport: 7000, payload: 'HELLO' },
      { type: 'udp', src: '10.10.1.30', dst: '10.10.1.20', smac: '02:10:00:00:00:30', dmac: '02:10:00:00:00:20', sport: 7000, dport: 51020, payload: 'WELCOME' },
      { type: 'icmp', src: '10.10.1.21', dst: '10.10.1.1', smac: '02:10:00:00:00:21', dmac: '02:10:00:00:00:01', icmpType: 8, icmpId: 101, icmpSeq: 1 }
    ]
  },
  {
    id: 'base-eth-broadcast', title: 'LAN全体に届けるフレーム',
    description: '通常のユニキャスト通信に、MACアドレスを問い合わせるARPが混ざっています。',
    packets: [
      { type: 'udp', src: '10.10.2.40', dst: '10.10.2.50', smac: '02:10:00:00:02:40', dmac: '02:10:00:00:02:50', sport: 51040, dport: 7001, payload: 'status' },
      { type: 'arp', op: 1, psrc: '10.10.2.40', pdst: '10.10.2.1', hwsrc: '02:10:00:00:02:40', smac: '02:10:00:00:02:40', dmac: 'ff:ff:ff:ff:ff:ff' },
      { type: 'arp', op: 2, psrc: '10.10.2.1', pdst: '10.10.2.40', hwsrc: '02:10:00:00:02:01', hwdst: '02:10:00:00:02:40', smac: '02:10:00:00:02:01', dmac: '02:10:00:00:02:40' },
      { type: 'udp', src: '10.10.2.50', dst: '10.10.2.40', smac: '02:10:00:00:02:50', dmac: '02:10:00:00:02:40', sport: 7001, dport: 51040, payload: 'ready' }
    ]
  },
  {
    id: 'base-eth-gateway', title: 'Webサーバーと次の転送先',
    description: '端末10.10.3.20/24は、ゲートウェイ10.10.3.1を使って別ネットワークの192.0.2.80へ接続します。端末側LANで採取した記録です。',
    packets: [
      { type: 'arp', op: 1, psrc: '10.10.3.20', pdst: '10.10.3.1', hwsrc: '02:10:00:00:03:20' },
      { type: 'arp', op: 2, psrc: '10.10.3.1', pdst: '10.10.3.20', hwsrc: '02:10:00:00:03:01', hwdst: '02:10:00:00:03:20' },
      { type: 'tcp', src: '10.10.3.20', dst: '192.0.2.80', smac: '02:10:00:00:03:20', dmac: '02:10:00:00:03:01', sport: 51320, dport: 80, flags: 'S', seq: 1000, ack: 0 },
      { type: 'tcp', src: '192.0.2.80', dst: '10.10.3.20', smac: '02:10:00:00:03:01', dmac: '02:10:00:00:03:20', sport: 80, dport: 51320, flags: 'SA', seq: 8000, ack: 1001 },
      { type: 'tcp', src: '10.10.3.20', dst: '192.0.2.80', smac: '02:10:00:00:03:20', dmac: '02:10:00:00:03:01', sport: 51320, dport: 80, flags: 'A', seq: 1001, ack: 8001 }
    ]
  },
  {
    id: 'base-arp-request', title: '誰のMACアドレスを知りたい？',
    description: '端末10.20.1.12が同じLANの10.20.1.1を問い合わせ、回答を受け取ります。',
    packets: [
      { type: 'arp', op: 1, psrc: '10.20.1.12', pdst: '10.20.1.1', hwsrc: '02:20:00:00:01:12' },
      { type: 'arp', op: 2, psrc: '10.20.1.1', pdst: '10.20.1.12', hwsrc: '02:20:00:00:01:01', hwdst: '02:20:00:00:01:12' },
      { type: 'icmp', src: '10.20.1.12', dst: '10.20.1.1', smac: '02:20:00:00:01:12', dmac: '02:20:00:00:01:01', icmpType: 8, icmpId: 201, icmpSeq: 1 },
      { type: 'icmp', src: '10.20.1.1', dst: '10.20.1.12', smac: '02:20:00:00:01:01', dmac: '02:20:00:00:01:12', icmpType: 0, icmpId: 201, icmpSeq: 1 }
    ]
  },
  {
    id: 'base-arp-answer', title: 'ARP応答の対応表',
    description: '端末10.20.2.25がプリンター10.20.2.60のMACアドレスを問い合わせます。別の端末のARPも含まれます。',
    packets: [
      { type: 'arp', op: 1, psrc: '10.20.2.26', pdst: '10.20.2.1', hwsrc: '02:20:00:00:02:26' },
      { type: 'arp', op: 1, psrc: '10.20.2.25', pdst: '10.20.2.60', hwsrc: '02:20:00:00:02:25' },
      { type: 'arp', op: 2, psrc: '10.20.2.60', pdst: '10.20.2.25', hwsrc: '02:20:00:00:02:60', hwdst: '02:20:00:00:02:25' },
      { type: 'arp', op: 2, psrc: '10.20.2.1', pdst: '10.20.2.26', hwsrc: '02:20:00:00:02:01', hwdst: '02:20:00:00:02:26' }
    ]
  },
  {
    id: 'base-arp-pair', title: '混ざったARPを組にする',
    description: '同じ端末10.20.3.15が、ファイルサーバー10.20.3.99とゲートウェイ10.20.3.1を続けて問い合わせます。',
    packets: [
      { type: 'arp', op: 1, psrc: '10.20.3.15', pdst: '10.20.3.99', hwsrc: '02:20:00:00:03:15' },
      { type: 'arp', op: 1, psrc: '10.20.3.15', pdst: '10.20.3.1', hwsrc: '02:20:00:00:03:15' },
      { type: 'arp', op: 2, psrc: '10.20.3.99', pdst: '10.20.3.15', hwsrc: '02:20:00:00:03:99', hwdst: '02:20:00:00:03:15' },
      { type: 'arp', op: 2, psrc: '10.20.3.1', pdst: '10.20.3.15', hwsrc: '02:20:00:00:03:01', hwdst: '02:20:00:00:03:15' },
      { type: 'udp', src: '10.20.3.15', dst: '198.51.100.10', smac: '02:20:00:00:03:15', dmac: '02:20:00:00:03:01', sport: 52015, dport: 7010, payload: 'gateway-ready' }
    ]
  },
  {
    id: 'base-ipv4-source', title: 'IPv4の送信元と宛先',
    description: '端末側LANで採取した、ローカルのpingと別ネットワークへのTCP接続です。',
    packets: [
      { type: 'icmp', src: '10.30.1.22', dst: '10.30.1.1', smac: '02:30:00:00:01:22', dmac: '02:30:00:00:01:01', icmpType: 8, icmpId: 301, icmpSeq: 1, ttl: 64 },
      { type: 'tcp', src: '10.30.1.21', dst: '203.0.113.40', smac: '02:30:00:00:01:21', dmac: '02:30:00:00:01:01', sport: 53021, dport: 80, flags: 'S', seq: 2000, ack: 0, ttl: 64 },
      { type: 'tcp', src: '203.0.113.40', dst: '10.30.1.21', smac: '02:30:00:00:01:01', dmac: '02:30:00:00:01:21', sport: 80, dport: 53021, flags: 'SA', seq: 9000, ack: 2001, ttl: 51 },
      { type: 'tcp', src: '10.30.1.21', dst: '203.0.113.40', smac: '02:30:00:00:01:21', dmac: '02:30:00:00:01:01', sport: 53021, dport: 80, flags: 'A', seq: 2001, ack: 9001, ttl: 64 }
    ]
  },
  {
    id: 'base-ipv6-hop', title: 'IPv6の宛先とHop Limit',
    description: '端末2001:db8:30::25がIPv6のサーバー2001:db8:30::80へUDPメッセージを送ります。Hop Limitを32に設定した例です。',
    packets: [
      { type: 'icmp', src: '10.30.2.25', dst: '10.30.2.1', icmpType: 8, icmpId: 302, icmpSeq: 1 },
      { type: 'udp', ipv6: true, src: '2001:db8:30::25', dst: '2001:db8:30::80', smac: '02:30:00:00:02:25', dmac: '02:30:00:00:02:80', sport: 53025, dport: 7020, hopLimit: 32, payload: 'ipv6 hello' },
      { type: 'udp', ipv6: true, src: '2001:db8:30::80', dst: '2001:db8:30::25', smac: '02:30:00:00:02:80', dmac: '02:30:00:00:02:25', sport: 7020, dport: 53025, hopLimit: 64, payload: 'ipv6 welcome' },
      { type: 'icmp', src: '10.30.2.1', dst: '10.30.2.25', icmpType: 0, icmpId: 302, icmpSeq: 1 }
    ]
  },
  {
    id: 'base-ip-transport', title: 'IPとその中身を分ける',
    description: 'IPv4とIPv6、UDPとICMPが混在しています。IPの種類と上位プロトコルを別々に確認しましょう。',
    packets: [
      { type: 'udp', src: '10.30.3.31', dst: '10.30.3.61', sport: 53131, dport: 62030, payload: 'ipv4-request' },
      { type: 'udp', ipv6: true, src: '2001:db8:31::31', dst: '2001:db8:31::61', sport: 53132, dport: 62030, payload: 'ipv6-request' },
      { type: 'icmp6', ipv6: true, src: '2001:db8:31::32', dst: '2001:db8:31::1', icmpType: 128, icmpId: 303, icmpSeq: 1 },
      { type: 'udp', src: '10.30.3.61', dst: '10.30.3.31', sport: 62030, dport: 53131, payload: 'ipv4-response' },
      { type: 'udp', ipv6: true, src: '2001:db8:31::61', dst: '2001:db8:31::31', sport: 62030, dport: 53132, payload: 'ipv6-response' },
      { type: 'icmp6', ipv6: true, src: '2001:db8:31::1', dst: '2001:db8:31::32', icmpType: 129, icmpId: 303, icmpSeq: 1 }
    ]
  },
  {
    id: 'base-icmp-echo', title: 'pingの要求と応答',
    description: '端末10.40.1.10から10.40.1.1へ、Sequence Numberが7と8のEcho Requestを送った記録です。',
    packets: [
      { type: 'icmp', src: '10.40.1.10', dst: '10.40.1.1', icmpType: 8, icmpId: 401, icmpSeq: 7, payload: 'ping-7', time: 0 },
      { type: 'udp', src: '10.40.1.11', dst: '10.40.1.50', sport: 54011, dport: 7040, payload: 'background', time: 0.002 },
      { type: 'icmp', src: '10.40.1.1', dst: '10.40.1.10', icmpType: 0, icmpId: 401, icmpSeq: 7, payload: 'ping-7', time: 0.004 },
      { type: 'icmp', src: '10.40.1.10', dst: '10.40.1.1', icmpType: 8, icmpId: 401, icmpSeq: 8, payload: 'ping-8', time: 1 },
      { type: 'icmp', src: '10.40.1.1', dst: '10.40.1.10', icmpType: 0, icmpId: 401, icmpSeq: 8, payload: 'ping-8', time: 1.004 }
    ]
  },
  {
    id: 'base-icmp-unreachable', title: 'UDPポートに届かない通知',
    description: '端末10.40.2.15が10.40.2.50のUDPポート7099へ送信し、宛先からICMP通知が返りました。',
    packets: [
      { type: 'udp', src: '10.40.2.15', dst: '10.40.2.50', sport: 54015, dport: 7099, payload: 'hello', time: 0 },
      { type: 'icmp', src: '10.40.2.50', dst: '10.40.2.15', icmpType: 3, code: 3, quoted: { src: '10.40.2.15', dst: '10.40.2.50', sport: 54015, dport: 7099, ttl: 64, payload: 'hello', frameIndex: 0 }, time: 0.003 },
      { type: 'icmp', src: '10.40.2.16', dst: '10.40.2.1', icmpType: 8, icmpId: 402, icmpSeq: 1, time: 0.01 },
      { type: 'icmp', src: '10.40.2.1', dst: '10.40.2.16', icmpType: 0, icmpId: 402, icmpSeq: 1, time: 0.014 }
    ]
  },
  {
    id: 'base-icmp-ttl', title: '途中のルーターからの通知',
    description: 'TTLを1に設定したUDPパケットを別ネットワークへ送信しました。最初のルーターが転送を中止し、ICMPを返す例です。',
    packets: [
      { type: 'udp', src: '10.40.3.20', dst: '203.0.113.90', smac: '02:40:00:00:03:20', dmac: '02:40:00:00:03:01', sport: 54020, dport: 33434, ttl: 1, payload: 'probe-1', time: 0 },
      { type: 'icmp', src: '10.40.3.1', dst: '10.40.3.20', smac: '02:40:00:00:03:01', dmac: '02:40:00:00:03:20', icmpType: 11, code: 0, quoted: { src: '10.40.3.20', dst: '203.0.113.90', sport: 54020, dport: 33434, ttl: 1, payload: 'probe-1', frameIndex: 0 }, time: 0.002 },
      { type: 'icmp', src: '10.40.3.21', dst: '10.40.3.1', icmpType: 8, icmpId: 403, icmpSeq: 1, time: 0.01 },
      { type: 'icmp', src: '10.40.3.1', dst: '10.40.3.21', icmpType: 0, icmpId: 403, icmpSeq: 1, time: 0.013 }
    ]
  },
  {
    id: 'base-icmp6-echo', title: 'IPv6でもpingを読む',
    description: '端末2001:db8:50::20が2001:db8:50::1へIPv6のEcho Requestを送りました。',
    packets: [
      { type: 'icmp6', ipv6: true, src: '2001:db8:50::20', dst: '2001:db8:50::1', icmpType: 128, icmpId: 501, icmpSeq: 3, time: 0 },
      { type: 'udp', ipv6: true, src: '2001:db8:50::21', dst: '2001:db8:50::60', sport: 55021, dport: 7050, payload: 'background', time: 0.001 },
      { type: 'icmp6', ipv6: true, src: '2001:db8:50::1', dst: '2001:db8:50::20', icmpType: 129, icmpId: 501, icmpSeq: 3, time: 0.003 }
    ]
  },
  {
    id: 'base-ndp-neighbor', title: 'IPv6の近隣を見つける',
    description: '同じリンクのfe80::20がルーターfe80::1を近隣探索します。別の近隣探索も混ざっています。',
    packets: [
      { type: 'icmp6', ipv6: true, src: 'fe80::20', dst: 'ff02::1:ff00:99', smac: '02:50:00:00:02:20', dmac: '33:33:ff:00:00:99', icmpType: 135, target: 'fe80::99', hopLimit: 255 },
      { type: 'icmp6', ipv6: true, src: 'fe80::20', dst: 'ff02::1:ff00:1', smac: '02:50:00:00:02:20', dmac: '33:33:ff:00:00:01', icmpType: 135, target: 'fe80::1', hopLimit: 255 },
      { type: 'icmp6', ipv6: true, src: 'fe80::99', dst: 'fe80::20', smac: '02:50:00:00:02:99', dmac: '02:50:00:00:02:20', icmpType: 136, target: 'fe80::99', hopLimit: 255 },
      { type: 'icmp6', ipv6: true, src: 'fe80::1', dst: 'fe80::20', smac: '02:50:00:00:02:01', dmac: '02:50:00:00:02:20', icmpType: 136, target: 'fe80::1', hopLimit: 255 },
      { type: 'icmp6', ipv6: true, src: 'fe80::20', dst: 'fe80::1', smac: '02:50:00:00:02:20', dmac: '02:50:00:00:02:01', icmpType: 128, icmpId: 502, icmpSeq: 1 }
    ]
  },
  {
    id: 'base-ndp-router', title: 'ルーターの存在を知らせるRA',
    description: 'ルーターfe80::1が全ノード宛てにRouter Advertisementを送信します。別端末のEchoと近隣探索も含みます。',
    packets: [
      { type: 'icmp6', ipv6: true, src: 'fe80::22', dst: 'fe80::1', smac: '02:50:00:00:03:22', dmac: '02:50:00:00:03:01', icmpType: 128, icmpId: 503, icmpSeq: 1 },
      { type: 'icmp6', ipv6: true, src: 'fe80::1', dst: 'ff02::1', smac: '02:50:00:00:03:01', dmac: '33:33:00:00:00:01', icmpType: 134, routerLifetime: 1800, prefix: '2001:db8:53::', hopLimit: 255 },
      { type: 'icmp6', ipv6: true, src: 'fe80::1', dst: 'fe80::22', smac: '02:50:00:00:03:01', dmac: '02:50:00:00:03:22', icmpType: 129, icmpId: 503, icmpSeq: 1 },
      { type: 'icmp6', ipv6: true, src: 'fe80::23', dst: 'ff02::1:ff00:1', smac: '02:50:00:00:03:23', dmac: '33:33:ff:00:00:01', icmpType: 135, target: 'fe80::1', hopLimit: 255 }
    ]
  },
  {
    id: 'base-udp-ports', title: 'UDPの送信元と宛先ポート',
    description: '端末10.60.1.18がUDPの簡単な応答サービス10.60.1.70:7070へ要求を送ります。',
    packets: [
      { type: 'udp', src: '10.60.1.18', dst: '10.60.1.70', sport: 56018, dport: 7070, payload: 'HELLO 18', time: 0 },
      { type: 'icmp', src: '10.60.1.19', dst: '10.60.1.1', icmpType: 8, icmpId: 601, icmpSeq: 1, time: 0.001 },
      { type: 'udp', src: '10.60.1.70', dst: '10.60.1.18', sport: 7070, dport: 56018, payload: 'OK 18', time: 0.003 },
      { type: 'icmp', src: '10.60.1.1', dst: '10.60.1.19', icmpType: 0, icmpId: 601, icmpSeq: 1, time: 0.004 }
    ]
  },
  {
    id: 'base-udp-length', title: 'UDP Lengthには何が含まれる？',
    description: '短いASCIIデータPINGとPONGを交換します。UDP LengthとEthernetフレーム全体の長さを区別する教材です。',
    packets: [
      { type: 'udp', src: '10.60.2.24', dst: '10.60.2.80', sport: 56024, dport: 7080, payload: 'PING' },
      { type: 'udp', src: '10.60.2.80', dst: '10.60.2.24', sport: 7080, dport: 56024, payload: 'PONG' },
      { type: 'udp', src: '10.60.2.25', dst: '10.60.2.80', sport: 56025, dport: 7080, payload: 'LONGER-MESSAGE' },
      { type: 'udp', src: '10.60.2.80', dst: '10.60.2.25', sport: 7080, dport: 56025, payload: 'ACK-LONGER' }
    ]
  },
  {
    id: 'base-udp-retry', title: 'UDPの上で要求・応答を作る',
    description: 'この教材のアプリは1秒待って同じ要求をもう一度送ります。採取記録には2回目の送信後の応答が1個だけ含まれています。',
    packets: [
      { type: 'udp', src: '10.60.3.35', dst: '10.60.3.75', sport: 56035, dport: 62075, payload: 'REQ 42', time: 0 },
      { type: 'icmp', src: '10.60.3.36', dst: '10.60.3.1', icmpType: 8, icmpId: 603, icmpSeq: 1, time: 0.2 },
      { type: 'udp', src: '10.60.3.35', dst: '10.60.3.75', sport: 56035, dport: 62075, payload: 'REQ 42', time: 1 },
      { type: 'udp', src: '10.60.3.75', dst: '10.60.3.35', sport: 62075, dport: 56035, payload: 'RES 42 OK', time: 1.01 },
      { type: 'icmp', src: '10.60.3.1', dst: '10.60.3.36', icmpType: 0, icmpId: 603, icmpSeq: 1, time: 1.02 }
    ]
  }
];

const lessons = [
  {
    id: 'base-ethernet-1', chapter: 'base-ethernet', title: 'フレームを送ったMACアドレス', level: 'guided', captureId: 'base-eth-addresses',
    intro: 'Ethernetは、同じリンク上でフレームを届けるための仕組みです。MACアドレスは「02:10:00:00:00:20」のように表示されます。一覧のSourceにIPアドレスが見えていても、Ethernetの詳細には別の送信元があります。',
    mission: 'パケット1を開き、Ethernet II → Sourceを根拠として選んでください。',
    hints: ['一覧でNo.1を選び、詳細のEthernet IIを開きます。', 'Sourceは送信元、Destinationは宛先です。Internet Protocolの欄ではなくEthernet IIを確認します。', 'eth.srcの値は02:10:00:00:00:20です。このフィールドを根拠に追加します。'],
    tasks: [
      { id: 'base-ethernet-1-src', prompt: 'パケット1の送信元MACアドレスは？', kind: 'text', answer: '02:10:00:00:00:20', normalize: 'mac', evidence: [{ frame: 1, field: 'eth.src' }], why: 'Ethernetの送信元はeth.srcです。IPアドレスやUDPのポート番号とは別の項目です。' }
    ],
    explanation: 'パケット1のEthernet送信元は02:10:00:00:00:20です。パケット2では送信元と宛先が逆になります。通信はEthernet、IP、UDPのように複数の層で構成され、各層に届け先の情報があります。'
  },
  {
    id: 'base-ethernet-2', chapter: 'base-ethernet', title: 'ブロードキャストを探す', level: 'practice', captureId: 'base-eth-broadcast',
    intro: 'Ethernetの宛先ff:ff:ff:ff:ff:ffはブロードキャストです。同じブロードキャストドメインの全体へ届けるときに使います。すべてのフレームがこの宛先になるわけではありません。',
    mission: 'Ethernetの宛先を見比べ、ブロードキャストのフレームだけを選びます。',
    hints: ['Ethernet II → Destinationを確認してください。', 'ARPというProtocol名だけで判断せず、eth.dstがff:ff:ff:ff:ff:ffかを見ます。ARP応答はこの教材ではユニキャストです。', 'パケット2だけがff:ff:ff:ff:ff:ff宛てです。'],
    tasks: [
      { id: 'base-ethernet-2-broadcast', prompt: 'Ethernetブロードキャストのパケットをすべて選んでください。', kind: 'packets', answer: [2], why: 'ブロードキャストかどうかはEthernet宛先で判断できます。パケット3のARP応答は特定の端末のMAC宛てです。' }
    ],
    explanation: '該当するのはパケット2です。ARP要求は相手のMACをまだ知らないため、この例ではEthernetブロードキャストで送ります。ブロードキャストはインターネット全体への一斉送信を意味しません。'
  },
  {
    id: 'base-ethernet-3', chapter: 'base-ethernet', title: 'IPの宛先とMACの宛先', level: 'challenge', captureId: 'base-eth-gateway',
    intro: '別ネットワークへ送る場合、端末は通常、最初にゲートウェイへフレームを渡します。この記録は端末側LANで採取したものです。Ethernetの宛先と、IPが示す通信相手をそれぞれ読んでみましょう。',
    mission: 'パケット3について、2つの層の宛先を回答します。',
    hints: ['パケット3のEthernet IIとInternet Protocol Version 4を開きます。', 'eth.dstは同じリンク上の次の届け先、ip.dstはIPパケットの宛先です。ARP応答も対応確認に使えます。', 'eth.dstは02:10:00:00:03:01、ip.dstは192.0.2.80です。'],
    tasks: [
      { id: 'base-ethernet-3-mac', prompt: 'パケット3の宛先MACアドレスは？', kind: 'text', answer: '02:10:00:00:03:01', normalize: 'mac', evidence: [{ frame: 3, field: 'eth.dst' }], why: 'このLANではゲートウェイのMACに渡します。遠くのWebサーバーのMACをARPで問い合わせているわけではありません。' },
      { id: 'base-ethernet-3-ip', prompt: '同じパケット3の宛先IPv4アドレスは？', kind: 'text', answer: '192.0.2.80', normalize: 'ip', evidence: [{ frame: 3, field: 'ip.dst' }], why: 'IP層の宛先は通信したいWebサーバーです。MACとIPは異なる層の届け先を表します。' }
    ],
    explanation: 'Ethernet宛先はゲートウェイの02:10:00:00:03:01、IPv4宛先は192.0.2.80です。ルーターを越えるとリンクのヘッダーは作り直されるため、採取場所によって見えるMACは変わります。IPの宛先もNATなどで変換される場合があるので、採取地点を意識しましょう。'
  },
  {
    id: 'base-arp-1', chapter: 'base-arp', title: 'ARP要求のTargetを読む', level: 'guided', captureId: 'base-arp-request',
    intro: 'ARPは、同じリンクで使うIPv4アドレスとMACアドレスの対応を調べるためのプロトコルです。要求のSenderは問い合わせた側、Targetは調べたい相手です。ARPの情報は、IPv4ヘッダーの中ではなくARP自身に入っています。',
    mission: 'パケット1のARP詳細を開き、Target IP addressを根拠にします。',
    hints: ['パケット1のAddress Resolution Protocolを開きます。', 'Sender IP addressは問い合わせ元です。調べたい相手はTarget IP addressにあります。', 'Target IP address（arp.dst.proto_ipv4）は10.20.1.1です。'],
    tasks: [
      { id: 'base-arp-1-target', prompt: 'パケット1は、どのIPv4アドレスのMACを問い合わせていますか？', kind: 'text', answer: '10.20.1.1', normalize: 'ip', evidence: [{ frame: 1, field: 'arp.dst.proto_ipv4' }], why: '問い合わせ対象はARPのTarget IP addressです。要求フレームのEthernet宛先ff:ff:ff:ff:ff:ffとは役割が異なります。' }
    ],
    explanation: 'パケット1は「10.20.1.1のMACアドレスは？」という要求です。ARP Opcode 1はRequest、2はReplyです。要求時のTarget MACは未確定なので、この例では00:00:00:00:00:00になっています。'
  },
  {
    id: 'base-arp-2', chapter: 'base-arp', title: '回答されたMACを確かめる', level: 'practice', captureId: 'base-arp-answer',
    intro: 'ARP応答では、SenderのIPとMACが回答する側の対応を示します。複数のARPが混ざると、直後にある応答が目的のものとは限りません。OpcodeとSender IPを確認してからMACを読みます。',
    mission: '10.20.2.60のARP応答を見つけ、回答されたIPとMACの2項目を根拠に追加します。',
    hints: ['ARP Opcodeが2（reply）のパケットを探します。', 'Sender IP addressが10.20.2.60の応答を使います。Target側は問い合わせた端末です。', 'パケット3のarp.src.proto_ipv4とarp.src.hw_macを両方選びます。回答MACは02:20:00:00:02:60です。'],
    tasks: [
      { id: 'base-arp-2-mac', prompt: '10.20.2.60について回答されたMACアドレスは？（IPとMACの両方を根拠に選択）', kind: 'text', answer: '02:20:00:00:02:60', normalize: 'mac', evidence: [{ frame: 3, field: 'arp.src.proto_ipv4' }, { frame: 3, field: 'arp.src.hw_mac' }], evidenceMode: 'all', why: '応答のSender IPとSender MACを組にすると、どのIPについての回答かまで示せます。別端末宛ての応答を取り違えないようにしましょう。' }
    ],
    explanation: 'パケット3は10.20.2.60が02:20:00:00:02:60であると通知しています。これは採取されたARP応答の主張を読んだ結果です。ARP単独で機器の正当性を認証できるわけではありません。'
  },
  {
    id: 'base-arp-3', chapter: 'base-arp', title: '一つのARP交換を追う', level: 'challenge', captureId: 'base-arp-pair',
    intro: 'ARPにはDNSのようなトランザクションIDがありません。要求と応答を対応づけるときは、問い合わせ元・問い合わせ対象・MACの向きを確認します。今回は2件の問い合わせが交互に見えています。',
    mission: '10.20.3.1についての要求と応答を、要求 → 応答の順に選びます。',
    hints: ['要求のTarget IPが10.20.3.1のものを探します。', 'その応答ではSender IPが10.20.3.1、Target IPが10.20.3.15です。', 'パケット2が要求、パケット4が応答です。この順序で選んでください。'],
    tasks: [
      { id: 'base-arp-3-order', prompt: '10.20.3.1を調べるARP要求 → その応答の順に選択してください。', kind: 'order', answer: [2, 4], why: 'パケット1と3は10.20.3.99についての交換です。目的のTarget/Sender IPを追うと2と4が対応します。' }
    ],
    explanation: 'パケット2が10.20.3.1を問い合わせ、パケット4が02:20:00:00:03:01と回答しています。続くパケット5はそのMACへ送られています。並び順だけでなく、アドレスの対応で会話を追うことが大切です。'
  },
  {
    id: 'base-ip-1', chapter: 'base-ip', title: 'IPv4の通信相手を読む', level: 'guided', captureId: 'base-ipv4-source',
    intro: 'IPv4アドレスは10.30.1.21のように4つの数で表示されます。IP層のSourceとDestinationはパケットの送信元と宛先です。EthernetのMACやTCPのポートとは別に読み取りましょう。',
    mission: 'パケット2のIPv4詳細で、送信元アドレスを確認します。',
    hints: ['No.2を選び、Internet Protocol Version 4を開きます。', 'Source Addressは送信元、Destination Addressは宛先です。', 'ip.srcの値は10.30.1.21です。eth.srcのMACではありません。'],
    tasks: [
      { id: 'base-ip-1-src', prompt: 'パケット2を送ったIPv4アドレスは？', kind: 'text', answer: '10.30.1.21', normalize: 'ip', evidence: [{ frame: 2, field: 'ip.src' }], why: 'IPv4のSource Addressが送信元です。返信パケット3では送信元と宛先が逆向きになります。' }
    ],
    explanation: '送信元は10.30.1.21、宛先は203.0.113.40です。IPv4のProtocol欄は中に入っている上位プロトコルを示し、このパケットではTCP（6）です。TTLは転送時に減る値で、ここに64とあるだけでは通過ルーターの総数やOSは確定できません。'
  },
  {
    id: 'base-ip-2', chapter: 'base-ip', title: 'IPv6とHop Limit', level: 'practice', captureId: 'base-ipv6-hop',
    intro: 'IPv6アドレスはコロン区切りで表され、「::」で連続する0を省略できます。IPv6のHop Limitは、IPv4のTTLと同様に転送のたびに減る上限です。値は秒数や応答時間ではありません。',
    mission: 'パケット2のIPv6宛先とHop Limitを、それぞれのフィールドから読み取ります。',
    hints: ['パケット2でInternet Protocol Version 6を開きます。', 'Destination AddressとHop Limitを確認します。IPv4のパケット1と混同しないようにしましょう。', '宛先は2001:db8:30::80、Hop Limitは32です。根拠はipv6.dstとipv6.hlimです。'],
    tasks: [
      { id: 'base-ip-2-dst', prompt: 'パケット2の宛先IPv6アドレスは？', kind: 'text', answer: '2001:db8:30::80', normalize: 'ip', evidence: [{ frame: 2, field: 'ipv6.dst' }], why: 'IPv6の宛先はipv6.dstです。アドレスの長さや表記が変わっても、送信元と宛先を読む手順は同じです。' },
      { id: 'base-ip-2-hop', prompt: 'パケット2で観測されたHop Limitはいくつですか？', kind: 'text', answer: '32', normalize: 'number', evidence: [{ frame: 2, field: 'ipv6.hlim' }], why: 'Hop Limitは観測地点で残っている転送上限です。32台のルーターをすでに通過した、という意味ではありません。' }
    ],
    explanation: 'IPv6の宛先は2001:db8:30::80、Hop Limitは32です。IPv6のNext Headerは次に続くヘッダーを示します。この例は拡張ヘッダーなしなので、UDP（17）が直接続きます。'
  },
  {
    id: 'base-ip-3', chapter: 'base-ip', title: 'IPv6のUDPだけを見分ける', level: 'challenge', captureId: 'base-ip-transport',
    intro: 'IPのバージョンと、その中に入るUDP・TCP・ICMPは別の観点です。IPv4でもIPv6でもUDPを運べます。一覧のProtocol欄だけに頼らず、詳細にどの層があるかを見てください。',
    mission: 'IPv6に続いてUDPヘッダーがあるパケットをすべて選びます。',
    hints: ['IPv6とUser Datagram Protocolの両方があるパケットを探します。', 'パケット1と4はUDPですがIPv4です。3と6はIPv6ですがICMPv6です。', '条件を満たすのはパケット2と5です。この例のipv6.nxtは17です。'],
    tasks: [
      { id: 'base-ip-3-select', prompt: 'IPv6で運ばれているUDPパケットをすべて選んでください。', kind: 'packets', answer: [2, 5], why: 'IPv6というネットワーク層の条件と、UDPというトランスポート層の条件を両方確認します。UDPという表示だけではIPの種類は確定しません。' }
    ],
    explanation: 'パケット2と5がIPv6＋UDPです。1と4はIPv4＋UDP、3と6はIPv6＋ICMPv6です。IPv4ではProtocol、IPv6ではNext Headerが次のヘッダーの種類を示します。IPv6に拡張ヘッダーがある場合、UDPまでの間に別のヘッダーが入ることもあります。'
  },
  {
    id: 'base-icmp-1', chapter: 'base-icmp', title: 'Echoの要求と応答を組にする', level: 'guided', captureId: 'base-icmp-echo',
    intro: 'IPv4のpingは通常、ICMP Echo Request（Type 8）とEcho Reply（Type 0）を使います。送信元・宛先の逆転に加え、IdentifierとSequence Numberを合わせると対応を追えます。複数回のpingを取り違えないようにしましょう。',
    mission: 'Sequence Numberが7の要求と応答を、送信順に選びます。',
    hints: ['Internet Control Message Protocolを開き、TypeとSequence Numberを見ます。', 'Type 8が要求、Type 0が応答です。Identifier 401、Sequence Number 7の組を探します。', 'パケット1が要求、パケット3がその応答です。4と5はSequence Number 8です。'],
    tasks: [
      { id: 'base-icmp-1-pair', prompt: 'Sequence Number 7のEcho Request → Echo Replyの順に選択してください。', kind: 'order', answer: [1, 3], why: 'Identifier、Sequence Number、アドレスの向きが対応しています。直後のUDPパケット2はpingの返事ではありません。' }
    ],
    explanation: 'パケット1と3が対応するEcho交換です。この時点ではICMPの往復を観測できたと言えますが、Webなど別サービスの利用可否までは分かりません。逆にEcho Replyが見えない場合も、制限・欠落・採取位置などの可能性があり、端末停止とは断定できません。'
  },
  {
    id: 'base-icmp-2', chapter: 'base-icmp', title: 'Destination Unreachableを読む', level: 'practice', captureId: 'base-icmp-unreachable',
    intro: 'ICMPはping以外に、通信できなかった理由を通知する役割も持ちます。TypeだけでなくCodeを合わせて読むと、より具体的な意味が分かります。エラー通知の中には、原因になった元パケットの一部も引用されます。',
    mission: 'パケット2の外側のICMP TypeとCodeを両方根拠に選び、通知の意味を答えます。',
    hints: ['パケット2のInternet Control Message Protocolを開きます。', 'Type 3はDestination Unreachableです。Code 3の意味も確認しましょう。', 'Type 3 / Code 3はPort Unreachableです。icmp.typeとicmp.codeの両方を根拠に選びます。'],
    tasks: [
      { id: 'base-icmp-2-meaning', prompt: 'パケット2は何を通知していますか？', kind: 'choice', answer: 'port-unreachable', options: [
        { value: 'echo-success', label: 'Echo Requestへの正常なEcho Reply' },
        { value: 'port-unreachable', label: '宛先ポートに到達できない（Port Unreachable）' },
        { value: 'ttl-expired', label: '転送中にTTLが尽きた（Time Exceeded）' },
        { value: 'tcp-established', label: 'TCP接続が成立した' }
      ], evidence: [{ frame: 2, field: 'icmp.type' }, { frame: 2, field: 'icmp.code' }], evidenceMode: 'all', why: 'Type 3だけでは到達不能の種類までは決まりません。Code 3を合わせてPort Unreachableと読めます。' }
    ],
    explanation: 'Type 3 / Code 3はPort Unreachableです。この例では、10.40.2.50から、UDPの宛先ポート7099に関する通知が返っています。端末全体が停止しているという結論にはなりません。詳細内にIPv4やUDPがもう一組見えるのは、元の通信が引用されているためです。'
  },
  {
    id: 'base-icmp-3', chapter: 'base-icmp', title: 'TTL超過を見抜く', level: 'challenge', captureId: 'base-icmp-ttl',
    intro: 'IPv4のTTLはルーターで転送されるたびに減ります。転送に必要なTTLが尽きると、ルーターはパケットを破棄してICMP Time Exceededを返す場合があります。tracerouteはこうした通知を利用して経路の手がかりを集めます。',
    mission: '送信パケットのTTLと、返ってきたICMPの理由を確認します。',
    hints: ['パケット1のIPv4 TTLを確認し、パケット2のICMP TypeとCodeを確認します。', 'Type 11はTime Exceededです。Code 0は転送中のTTL超過を表します。', 'パケット1のip.ttlは1。パケット2のicmp.typeは11、icmp.codeは0です。'],
    tasks: [
      { id: 'base-icmp-3-ttl', prompt: 'パケット1が送信された時点のTTLはいくつですか？', kind: 'text', answer: '1', normalize: 'number', evidence: [{ frame: 1, field: 'ip.ttl' }], why: '引用された元パケット内のTTLと混同せず、送信パケット1のIPv4ヘッダーを読みます。' },
      { id: 'base-icmp-3-reason', prompt: 'パケット2のICMP通知が示す理由は？', kind: 'choice', answer: 'transit-expired', options: [
        { value: 'port-unreachable', label: '宛先UDPポートに到達できない' },
        { value: 'transit-expired', label: '転送中にTTLが尽きた' },
        { value: 'echo-reply', label: 'Echo Requestに正常応答した' },
        { value: 'host-off', label: '宛先端末の電源が切れていると確定した' }
      ], evidence: [{ frame: 2, field: 'icmp.type' }, { frame: 2, field: 'icmp.code' }], evidenceMode: 'all', why: 'Type 11 / Code 0は転送中のTTL超過です。宛先のアプリや端末の状態についての通知ではありません。' }
    ],
    explanation: 'TTL 1の送信に対し、最初のルーターがType 11 / Code 0を返しています。この記録が示すのは、パケットが途中でTTL上限に達したことです。最終宛先203.0.113.90の稼働状態までは判断できません。'
  },
  {
    id: 'base-icmp6-1', chapter: 'base-icmp6', title: 'ICMPv6のEcho Reply', level: 'guided', captureId: 'base-icmp6-echo',
    intro: 'IPv6ではICMPv6を使います。Echo RequestはType 128、Echo ReplyはType 129で、IPv4のICMPとは番号が違います。送信元と宛先、Identifier、Sequence Numberを対応させる読み方は共通です。',
    mission: 'IPv6のEcho Replyを見つけ、該当パケットだけを選びます。',
    hints: ['ICMPv6の詳細でTypeを確認します。', 'Type 128は要求、129は応答です。パケット2はUDPなのでEcho応答ではありません。', 'パケット3がType 129のEcho Replyです。'],
    tasks: [
      { id: 'base-icmp6-1-reply', prompt: 'この記録のICMPv6 Echo Replyを選んでください。', kind: 'packets', answer: [3], why: 'IPv4のEcho ReplyはType 0ですが、ICMPv6では129です。プロトコル名とTypeを組にして読みます。' }
    ],
    explanation: 'パケット3がEcho Replyです。パケット1と3ではIPv6アドレスの向きが反転し、Identifier 501とSequence Number 3が一致します。ICMPv6はEchoに加えて、近隣探索などIPv6の基本動作にも使われます。'
  },
  {
    id: 'base-icmp6-2', chapter: 'base-icmp6', title: 'NSとNAで近隣を探す', level: 'practice', captureId: 'base-ndp-neighbor',
    intro: 'IPv6はARPを使わず、ICMPv6の近隣探索（NDP）を使います。Neighbor Solicitation（NS、Type 135）で相手を探し、Neighbor Advertisement（NA、Type 136）で応答できます。NSの宛先マルチキャストアドレスと、調べたいTarget Addressは別の項目です。',
    mission: 'fe80::1を探すNSと、それに対応するNAを追います。',
    hints: ['NSのTarget Addressを見て、fe80::1を探しているパケットを見つけます。', 'パケット2のIPv6宛先はff02::1:ff00:1ですが、NSのTarget Addressはfe80::1です。', 'パケット2がNS、パケット4が同じTarget AddressのNAです。要求 → 応答の順に選びます。'],
    tasks: [
      { id: 'base-icmp6-2-target', prompt: 'パケット2のNSが調べているTarget Addressは？', kind: 'text', answer: 'fe80::1', normalize: 'ip', evidence: [{ frame: 2, field: 'icmpv6.nd.ns.target_address' }], why: 'NSのTarget Addressが調査対象です。IPv6宛先ff02::1:ff00:1は、その問い合わせを届けるマルチキャストアドレスです。' },
      { id: 'base-icmp6-2-pair', prompt: 'fe80::1を探すNS → 対応するNAの順に選んでください。', kind: 'order', answer: [2, 4], why: 'Type 135と136、Target Address、送信先の対応を確認します。1と3はfe80::99についての交換です。' }
    ],
    explanation: 'パケット2と4がfe80::1についてのNS/NAです。この例のNSはSolicited-node multicast宛てに送られ、NAは問い合わせ元へユニキャストで返ります。NDPは近隣のリンク層アドレス解決や到達性確認などを担い、IPv6の基本動作を支えます。'
  },
  {
    id: 'base-icmp6-3', chapter: 'base-icmp6', title: 'RAが知らせるルーター情報', level: 'challenge', captureId: 'base-ndp-router',
    intro: 'Router Advertisement（RA、Type 134）は、ルーターが自分やネットワークの情報を知らせるICMPv6メッセージです。Router Lifetimeは、その送信元をデフォルトルーターとして扱える期間を秒で示します。IPv6ヘッダーのHop Limitとは別の値です。',
    mission: 'RAを見つけ、通知されたRouter Lifetimeを読み取ります。',
    hints: ['ICMPv6 Type 134のパケットを探します。', 'パケット2のICMPv6内にRouter lifetimeがあります。IPv6ヘッダーのHop Limit 255ではありません。', 'Router lifetime（icmpv6.nd.ra.router_lifetime）は1800秒です。'],
    tasks: [
      { id: 'base-icmp6-3-ra', prompt: 'Router Advertisementのパケットを選んでください。', kind: 'packets', answer: [2], why: 'ICMPv6 Type 134がRAです。EchoやNSもICMPv6なので、Protocol名だけでは区別できません。' },
      { id: 'base-icmp6-3-lifetime', prompt: 'このRAが通知するRouter Lifetimeは何秒ですか？', kind: 'text', answer: '1800', normalize: 'number', evidence: [{ frame: 2, field: 'icmpv6.nd.ra.router_lifetime' }], why: 'Router Lifetimeはデフォルトルーターの有効期間です。アドレスのリース時間、Prefixの有効期間、Hop Limitとは区別します。' }
    ],
    explanation: 'パケット2のRAはRouter Lifetime 1800秒を通知しています。この例の宛先ff02::1はリンク内の全ノードです。RAはプレフィックスなども通知でき、端末は条件が合えばSLAACでアドレスを構成できます。DHCPv6も設定配布に使われますが、IPv6のデフォルトルーター発見はRAの役割です。このRA一枚だけでは、各端末が実際に採用した設定までは分かりません。'
  },
  {
    id: 'base-udp-1', chapter: 'base-udp', title: 'UDPポートで向きを読む', level: 'guided', captureId: 'base-udp-ports',
    intro: 'UDPはデータグラム単位で情報を運びます。IPアドレスが端末の宛先を表し、UDPのポート番号がその端末内の通信先を区別する手がかりになります。UDP自体にはTCPのような接続開始の3段階の交換はありません。',
    mission: '要求パケット1と応答パケット3で、ポート番号がどう対応するか調べます。',
    hints: ['User Datagram Protocolを開き、Source PortとDestination Portを確認します。', 'パケット1は宛先7070へ送られています。返信ではサービス側の7070が送信元になります。', 'パケット1のudp.dstportは7070、パケット3のudp.dstportは56018です。'],
    tasks: [
      { id: 'base-udp-1-service', prompt: 'パケット1の宛先UDPポート番号は？', kind: 'text', answer: '7070', normalize: 'number', evidence: [{ frame: 1, field: 'udp.dstport' }], why: '宛先ポートはudp.dstportです。Source Port 56018は、この要求を送った側のポートです。' },
      { id: 'base-udp-1-reply', prompt: '応答パケット3の宛先UDPポート番号は？', kind: 'text', answer: '56018', normalize: 'number', evidence: [{ frame: 3, field: 'udp.dstport' }], why: '返信では要求元のポート56018が宛先になります。アドレスとポートの組を追うと、混ざった会話を区別できます。' }
    ],
    explanation: '要求は56018 → 7070、応答は7070 → 56018です。UDPヘッダーには送信元ポート・宛先ポート・長さ・チェックサムがあります。ポート番号だけでアプリを断定せず、実際のペイロードや通信の流れも確認しましょう。'
  },
  {
    id: 'base-udp-2', chapter: 'base-udp', title: 'ヘッダーとデータの長さ', level: 'practice', captureId: 'base-udp-length',
    intro: 'UDPヘッダーは8バイトです。UDPのLengthはヘッダーとUDPデータを合わせた長さで、EthernetやIPのヘッダーは含みません。一覧のLengthはフレーム全体なので、別の値になります。',
    mission: 'パケット1のUDP Lengthを読み、8バイトのヘッダーを引いてデータ長を求めます。',
    hints: ['パケット1のUser Datagram Protocol → Lengthを確認します。', 'UDP Lengthは12です。UDPヘッダー8バイトが含まれているので、データ部分は12 − 8です。', 'データ部分は4バイトです。計算の根拠としてパケット1のudp.lengthを選びます。'],
    tasks: [
      { id: 'base-udp-2-size', prompt: 'パケット1のUDPデータ部分は何バイトですか？（UDP Lengthを根拠に選択）', kind: 'text', answer: '4', normalize: 'number', evidence: [{ frame: 1, field: 'udp.length' }], why: 'udp.lengthの12バイトからUDPヘッダーの8バイトを引きます。フレーム全体のLengthから引くと、IPやEthernetも混ざってしまいます。' }
    ],
    explanation: 'UDP Length 12 − UDPヘッダー8 = データ4バイトです。教材のASCII文字列PINGは4バイトに対応します。Ethernetの最低長を満たすためのパディングが存在しても、UDPのデータ長には含まれません。'
  },
  {
    id: 'base-udp-3', chapter: 'base-udp', title: '応答や再試行は誰の仕事？', level: 'challenge', captureId: 'base-udp-retry',
    intro: 'UDP自体は、到達・順序・再送を保証しません。それでもUDPを使うアプリは、要求と応答、タイムアウト、再試行を独自に実装できます。この教材ではアプリが1秒後に同じ要求をもう一度送っています。',
    mission: '目的の通信だけを追い、観測された要求と応答の個数を確認します。',
    hints: ['10.60.3.35:56035から10.60.3.75:62075へ送られたUDPを探します。', 'パケット1と3が同じ方向への要求で、パケット4が逆方向の応答です。ICMPは別の通信です。', '要求として選ぶのは1と3。事実として選ぶのは「要求側2個、応答側1個」です。根拠には1・3・4のframe.numberを使います。'],
    tasks: [
      { id: 'base-udp-3-requests', prompt: '10.60.3.35:56035 → 10.60.3.75:62075のUDPパケットをすべて選んでください。', kind: 'packets', answer: [1, 3], why: 'IPとポートの向きを両方合わせて確認します。パケット4は同じ会話でも逆方向なので、要求側の集合には含めません。' },
      { id: 'base-udp-3-observation', prompt: 'この記録から確認できることは？（対象の3パケットのFrame Numberを根拠に選択）', kind: 'choice', answer: 'observed-count', options: [
        { value: 'observed-count', label: '要求側のUDPを2個、応答側のUDPを1個観測した' },
        { value: 'udp-auto-retry', label: 'UDPヘッダーの機能が必ず自動再送した' },
        { value: 'server-down', label: 'サーバーの電源が切れていたと確定した' },
        { value: 'tcp-before', label: '先にTCP接続を成立させる必要がある' }
      ], evidence: [{ frame: 1, field: 'frame.number' }, { frame: 3, field: 'frame.number' }, { frame: 4, field: 'frame.number' }], evidenceMode: 'all', why: '観測したパケット数と、その背後の原因を区別します。UDPに自動再送機能はなく、この教材の再試行はアプリが実装したものです。' }
    ],
    explanation: '要求側はパケット1と3、応答側は4です。応答が2回目の後に見えたことは分かりますが、この短い記録だけで最初の要求や応答がどこで失われたかは断定できません。UDPでもDNS、DHCP、NTPなどはアプリ側のルールで要求・応答を行います。'
  }
];

// Keep link-layer endpoints stable even in lessons that focus on upper layers.
// Explicit MACs describe gateways or shared-link examples and take precedence.
function endpointMac(address) {
  if (address.includes('.')) {
    return '02:00:' + address.split('.').map(n => Number(n).toString(16).padStart(2, '0')).join(':');
  }
  const [left, right] = address.split('::');
  const a = left ? left.split(':') : [];
  const b = right ? right.split(':') : [];
  const words = right !== undefined ? [...a, ...Array(8 - a.length - b.length).fill('0'), ...b] : a;
  const suffix = words.slice(-2).map(w => w.padStart(4, '0')).join('');
  return '02:06:' + suffix.match(/../g).join(':');
}
for (const capture of captures) {
  const knownMacs = new Map();
  for (const p of capture.packets) {
    if (p.src && p.smac) knownMacs.set(p.src, p.smac);
    if (p.dst && p.dmac && !p.dst.startsWith('ff')) knownMacs.set(p.dst, p.dmac);
    if (p.psrc && p.hwsrc) knownMacs.set(p.psrc, p.hwsrc);
  }
  for (const p of capture.packets) {
    if (p.type === 'arp') continue;
    if (!p.smac) p.smac = knownMacs.get(p.src) || endpointMac(p.src);
    if (!p.dmac) p.dmac = knownMacs.get(p.dst) || endpointMac(p.dst);
  }
}

module.exports = { chapters, captures, lessons };
