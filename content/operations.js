'use strict';
const chapters=[
 {id:'ops-view',title:'画面を読む',subtitle:'一覧から詳細へ。根拠を見つける最初の3歩。'},
 {id:'ops-filter',title:'表示フィルター',subtitle:'必要な通信を、自分の条件で絞り込む。'}
];
const basePackets=[
 {type:'dns',time:0,src:'10.0.0.10',dst:'10.0.0.53',name:'portal.test',dnsId:100,sport:53000},
 {type:'dns',time:0.024,src:'10.0.0.53',dst:'10.0.0.10',response:true,name:'portal.test',dnsId:100,dport:53000,answers:['198.51.100.20']},
 {type:'tcp',time:0.03,src:'10.0.0.10',dst:'198.51.100.20',sport:51000,dport:80,flags:'S',seq:1000},
 {type:'tcp',time:0.05,ttl:55,src:'198.51.100.20',dst:'10.0.0.10',sport:80,dport:51000,flags:'SA',seq:5000,ack:1001},
 {type:'tcp',time:0.051,src:'10.0.0.10',dst:'198.51.100.20',sport:51000,dport:80,flags:'A',seq:1001,ack:5001}
];
const filters=[
 {type:'dns',src:'10.0.0.10',dst:'10.0.0.53',name:'docs.test',dnsId:101,sport:53000},
 {type:'ntp',src:'10.0.0.10',dst:'192.0.2.123',mode:3,sport:53123},
 {type:'dns',src:'10.0.0.53',dst:'10.0.0.10',response:true,name:'docs.test',dnsId:101,dport:53000,answers:['198.51.100.30']},
 {type:'dns',src:'10.0.0.11',dst:'10.0.0.53',name:'mail.test',dnsId:102,sport:53001},
 {type:'dns',src:'10.0.0.53',dst:'10.0.0.11',response:true,name:'mail.test',dnsId:102,dport:53001,answers:['198.51.100.31']},
 {type:'ntp',ttl:55,src:'192.0.2.123',dst:'10.0.0.10',mode:4,stratum:2,sport:123,dport:53123},
 {type:'icmp',src:'10.0.0.12',dst:'10.0.0.1',icmpType:8,icmpId:7,icmpSeq:1},
 {type:'icmp',src:'10.0.0.1',dst:'10.0.0.12',icmpType:0,icmpId:7,icmpSeq:1}
];
const captures=[
 {id:'ops-first',title:'はじめての名前解決と接続',description:'端末10.0.0.10のインターフェースで、DNS問い合わせからTCP接続までを記録した架空の教材です。時刻はキャプチャ開始からの秒数です。',packets:basePackets},
 {id:'ops-mixed',title:'3台の端末が使うネットワーク',description:'同一LAN上のミラーポートで、3台の通信を記録した架空の教材です。時刻は相対秒です。',packets:filters}
];
const lessons=[
 {id:'ops-view-1',chapter:'ops-view',title:'最初の1パケットを開く',level:'guided',captureId:'ops-first',intro:'キャプチャは、ある場所で観測した通信の記録です。一覧の1行が1パケットに対応します。Sourceは送信元、Destinationは宛先です。行を選ぶと、下の詳細とバイト表示も同じパケットに切り替わります。',mission:'No. 1を選び、送信元IPアドレスを答えて、その項目を根拠に追加しましょう。',hints:['一覧のNo. 1を押します。','詳細の「Internet Protocol Version 4」を開き、Source Addressを探します。','ip.srcの値は10.0.0.10です。項目を選んでから「根拠に追加」を押します。'],explanation:'一覧は概要、詳細はその概要を裏づける項目です。No. 1のip.srcが10.0.0.10なので、このパケットの送信元は10.0.0.10です。IPだけで利用者や端末の持ち主までは特定できません。',tasks:[{id:'source',kind:'text',normalize:'ip',prompt:'No. 1の送信元IPアドレスは？',answer:'10.0.0.10',evidence:[{frame:1,field:'ip.src'}],why:'No. 1 → IPv4 → Source Addressに記録された値です。'}]},
 {id:'ops-view-2',chapter:'ops-view',title:'概要から詳細へ掘り下げる',level:'practice',captureId:'ops-first',intro:'DNSは名前について問い合わせるプロトコルです。Info列には要約が表示されますが、判断の根拠は詳細欄でも確かめられます。Query Nameは問い合わせた名前です。',mission:'No. 1のDNS詳細を開き、問い合わせ名を読みましょう。',hints:['No. 1のDomain Name Systemを開きます。','Queries配下に相当するdns.qry.nameを探します。','問い合わせ名はportal.testです。dns.qry.nameを根拠に追加します。'],explanation:'portal.testという名前の情報をDNSサーバーに問い合わせています。このパケットだけでは、名前解決に成功したか、その後Web接続できたかは分かりません。',tasks:[{id:'query',kind:'text',prompt:'問い合わせた名前は？',answer:'portal.test',evidence:[{frame:1,field:'dns.qry.name'}],why:'DNSのQuery Nameが問い合わせ対象の名前です。'}]},
 {id:'ops-view-3',chapter:'ops-view',title:'返事の向きを確かめる',level:'challenge',captureId:'ops-first',intro:'要求と応答では、送信元と宛先が入れ替わることがあります。見た目の並び順だけでなく、IPアドレスとプロトコルの情報を確認します。',mission:'DNSの返事を読み、返事を受け取る端末を特定しましょう。',hints:['DNS responseと表示されたNo. 2を選びます。','IPv4のDestination Addressを確認します。','No. 2のip.dstは10.0.0.10です。'],explanation:'No. 2はDNSサーバー10.0.0.53から端末10.0.0.10への応答です。No. 1とNo. 2の向きを比較すると、要求と応答の往復が分かります。',tasks:[{id:'destination',kind:'text',normalize:'ip',prompt:'DNS応答の宛先IPアドレスは？',answer:'10.0.0.10',evidence:[{frame:2,field:'ip.dst'}],why:'応答のDestination Addressが返事を受け取る端末です。'}]},
 {id:'ops-filter-1',chapter:'ops-filter',title:'DNSだけを表示する',level:'guided',captureId:'ops-mixed',intro:'表示フィルターは、読み込んだパケットのうち条件に合うものだけを表示します。元のキャプチャを削除する操作ではありません。プロトコル名dnsを入力するとDNSが含まれるパケットを表示できます。',mission:'表示フィルターにdnsを入力して適用しましょう。',hints:['画面上の「表示フィルター」に入力します。','dnsを入力して「適用」を押します。','No. 1・3・4・5の4件が表示されれば対象の範囲です。'],explanation:'表示対象はDNSを含む4パケットです。フィルターを解除すればNTPやICMPも再び見えます。これは収集時に使うキャプチャフィルターとは別の機能です。',tasks:[{id:'filter',kind:'filter',prompt:'DNSを含む4パケットだけを表示する',answer:[1,3,4,5],why:'DNSの要求と応答が残り、NTP・ICMPが除外されています。'}]},
 {id:'ops-filter-2',chapter:'ops-filter',title:'送信元とプロトコルを組み合わせる',level:'practice',captureId:'ops-mixed',intro:'ip.srcは送信元IPアドレスです。&&は「両方に当てはまる」を意味します。ip.addrは送信元または宛先なので、通信の向きを指定したいときはip.srcやip.dstを使います。',mission:'10.0.0.11が送信したDNSパケットだけを表示しましょう。',hints:['dnsとip.srcの2条件を組み合わせます。','比較はip.src == 10.0.0.11と書けます。','dns && ip.src == 10.0.0.11を適用するとNo. 4だけになります。'],explanation:'No. 4は10.0.0.11からDNSサーバーへの問い合わせです。No. 5は同じ端末への応答ですが、送信元はDNSサーバーなので対象外です。',tasks:[{id:'filter',kind:'filter',prompt:'10.0.0.11が送信したDNSだけを表示する',answer:[4],why:'送信元が指定端末で、DNSを含むNo. 4だけが表示されています。'}]},
 {id:'ops-filter-3',chapter:'ops-filter',title:'往復の通信を残す',level:'challenge',captureId:'ops-mixed',intro:'ip.addrは送信元・宛先のどちらかに一致します。条件の意味が同じなら、フィルターの書き方は一つではありません。No.は元のフレーム番号なので、絞り込んでも番号は変わりません。',mission:'10.0.0.10とDNSサーバーの往復だけを表示しましょう。',hints:['DNSと対象端末の両方で絞ります。','方向を限定しないip.addrを使います。','dns && ip.addr == 10.0.0.10でNo. 1・3を表示できます。'],explanation:'このデータではNo. 1とNo. 3が対象端末のDNSの往復です。UDPポート53で絞る別解も使えますが、実環境でポート番号だけからプロトコルを断定しないようにします。',tasks:[{id:'filter',kind:'filter',prompt:'10.0.0.10のDNSの往復だけを表示する',answer:[1,3],why:'問い合わせと応答の両方が表示されています。'}]}
];
// On the client LAN, off-link traffic goes through the gateway MAC.
const linkMac=ip=>ip?.startsWith('10.0.0.')?'02:00:00:00:00:'+ip.split('.').at(-1).padStart(2,'0'):'02:00:00:00:00:01';
for(const capture of captures)for(const p of capture.packets)if(!['dhcp','arp'].includes(p.type)){p.smac=p.smac||linkMac(p.src);p.dmac=p.dmac||linkMac(p.dst);}
module.exports={chapters,captures,lessons};
