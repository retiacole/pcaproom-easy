'use strict';

const chapters = [
  {id:'realworld-basics',title:'実物で役立つ読み方',subtitle:'Options・時刻・キャプチャ地点の違いを確かめる。'},
  {id:'realworld-investigation',title:'背景通信を含む卒業調査',subtitle:'284パケットから、調査する端末の通信を取り出す。'}
];
const mac = n => '02:00:00:00:00:' + n.toString(16).padStart(2,'0');
const gateway = mac(1);
const client = {src:'10.0.0.42',dst:'198.51.100.42',sport:51420,dport:80,smac:mac(42),dmac:gateway};
const server = {src:client.dst,dst:client.src,sport:80,dport:client.sport,smac:gateway,dmac:mac(42),ttl:57};

function exchange(c,s,path,host,status,body) {
  const request = `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: pcaproom-easy\r\nAccept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.8\r\nAccept-Language: ja,en;q=0.8\r\nConnection: keep-alive\r\n\r\n`;
  const response = `HTTP/1.1 ${status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: keep-alive\r\n\r\n${body}`;
  return [
    {type:'tcp',...c,flags:'S',seq:1000},
    {type:'tcp',...s,flags:'SA',seq:9000,ack:1001},
    {type:'tcp',...c,flags:'A',seq:1001,ack:9001},
    {type:'tcp',...c,flags:'PA',seq:1001,ack:9001,payload:request},
    {type:'tcp',...s,flags:'PA',seq:9001,ack:1001+Buffer.byteLength(request),payload:response},
    {type:'tcp',...c,flags:'A',seq:1001+Buffer.byteLength(request),ack:9001+Buffer.byteLength(response)}
  ];
}

const background = [];
for (let cycle=0;cycle<18;cycle++) {
  const host=60+cycle, address=`10.0.0.${host}`, hardware=mac(host), name=`printer-${cycle+1}.local`;
  const ssdpPort=52000+cycle;
  const settings={xid:0x5a130000+cycle,clientMac:hardware,hostName:`workstation-${cycle+1}`,server:'10.0.0.1',router:'10.0.0.1',dns:'10.0.0.53',mask:'255.255.255.0'};
  background.push(
    {type:'arp',op:1,psrc:address,pdst:'10.0.0.1',hwsrc:hardware},
    {type:'arp',op:2,psrc:'10.0.0.1',pdst:address,hwsrc:gateway,hwdst:hardware},
    {type:'dns',src:address,dst:'224.0.0.251',smac:hardware,sport:5353,dport:5353,dnsId:0,dnsFlags:0,name,edns:false,ttl:255},
    {type:'dns',src:'10.0.0.90',dst:'224.0.0.251',smac:mac(90),sport:5353,dport:5353,dnsId:0,dnsFlags:0x8400,dnsQuestion:false,name,response:true,answers:['10.0.0.90'],edns:false,ttl:255},
    {type:'udp',src:address,dst:'239.255.255.250',smac:hardware,sport:ssdpPort,dport:1900,ttl:2,payload:'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: upnp:rootdevice\r\n\r\n'},
    {type:'udp',src:'10.0.0.91',dst:address,smac:mac(91),dmac:hardware,sport:1900,dport:ssdpPort,payload:'HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: http://10.0.0.91/device.xml\r\nSERVER: ExampleOS/1.0 UPnP/1.1 Pcaproom/1.0\r\nST: upnp:rootdevice\r\nUSN: uuid:2c49d2d7-0424-4000-8000-000000000091::upnp:rootdevice\r\n\r\n'},
    {type:'icmp6',icmpType:135,src:`fe80::${host.toString(16)}`,dst:'ff02::1:ff00:1',smac:hardware,target:'fe80::1'},
    {type:'icmp6',icmpType:136,src:'fe80::1',dst:`fe80::${host.toString(16)}`,smac:gateway,dmac:hardware,target:'fe80::1',router:true},
    {type:'dhcp',message:1,xid:settings.xid,clientMac:hardware,hostName:settings.hostName},
    {type:'dhcp',message:2,yiaddr:address,...settings},
    {type:'dhcp',message:3,requested:address,xid:settings.xid,clientMac:hardware,hostName:settings.hostName,server:'10.0.0.1'},
    {type:'dhcp',message:5,yiaddr:address,...settings},
    {type:'ntp',src:address,dst:'192.0.2.123',smac:hardware,dmac:gateway,sport:54000+cycle,mode:3},
    {type:'ntp',src:'192.0.2.123',dst:address,smac:gateway,dmac:hardware,sport:123,dport:54000+cycle,mode:4,stratum:2,ttl:56},
    {type:'icmp6',icmpType:134,src:'fe80::1',dst:'ff02::1',smac:gateway,routerLifetime:1800,prefix:'2001:db8:1::/64'}
  );
}
const decoyClient={src:'10.0.0.22',dst:'198.51.100.22',smac:mac(22),dmac:gateway,sport:51220,dport:80};
const decoyServer={src:decoyClient.dst,dst:decoyClient.src,smac:gateway,dmac:mac(22),sport:80,dport:decoyClient.sport,ttl:55};
const decoy=exchange(decoyClient,decoyServer,'/health','monitor.test','200 OK','OK\n');
const target=exchange(client,server,'/reports/latest','reports.test','404 Not Found','Not Found\n');
// Disperse the relevant frames through unrelated LAN traffic. The decoy TCP
// connection starts first, so tshark assigns it stream 0 and the target stream 1.
const insertions=new Map([
  [40,[['dns-query',{type:'dns',src:client.src,dst:'10.0.0.53',smac:mac(42),dmac:mac(53),name:'reports.test',dnsId:0x4242,sport:53420}]]],
  [57,[['dns-answer',{type:'dns',src:'10.0.0.53',dst:client.src,smac:mac(53),dmac:mac(42),name:'reports.test',dnsId:0x4242,response:true,dport:53420,answers:[client.dst]}]]],
  [80,[['decoy-syn',decoy[0]]]], [81,[['decoy-synack',decoy[1]]]], [82,[['decoy-ack',decoy[2]]]],
  [96,[['decoy-get',decoy[3]]]], [100,[['decoy-response',decoy[4]]]], [103,[['decoy-final',decoy[5]]]],
  [130,[['target-syn',target[0]]]], [131,[['target-synack',target[1]]]], [132,[['target-ack',target[2]]]],
  [180,[['target-get',target[3]]]], [207,[['target-response',target[4]]]], [208,[['target-final',target[5]]]]
]);
const lan=[], frame={};
for(let i=0;i<background.length;i++) {
  for(const [label,p] of insertions.get(i)||[]) { frame[label]=lan.length+1;lan.push(p); }
  lan.push(background[i]);
}
for(let i=0;i<lan.length;i++)lan[i].time=i*.1;
const dnsFrames=[frame['dns-query'],frame['dns-answer']];
const targetFrames=['target-syn','target-synack','target-ack','target-get','target-response','target-final'].map(k=>frame[k]);
const getFrames=[frame['decoy-get'],frame['target-get']];

const captures=[
  {id:'realworld-tcp-options',title:'TCPのOptionsと相対番号',description:'端末10.0.0.42のインターフェースで記録した架空のTCP接続です。SYNでMSS・SACK・Window Scale・Timestampsを提示し、双方がTimestampsに合意した後のACKにも時刻情報が付きます。',packets:target.slice(0,3).map((p,i)=>({...p,time:[0,.024,.025][i]}))},
  {id:'realworld-extra-records',title:'DNSとDHCPの追加情報',description:'LANのミラーポートで、別端末のDHCP設定とDNS問い合わせを記録した教材です。DNSのOPTは応答アドレスとは異なる追加情報です。',packets:[
    {type:'dhcp',message:1,xid:0x31415926,clientMac:mac(42),hostName:'workstation-42'},
    {type:'dhcp',message:2,xid:0x31415926,clientMac:mac(42),yiaddr:'10.0.0.42',server:'10.0.0.1',mask:'255.255.255.0',router:'10.0.0.1',dns:'10.0.0.53'},
    {type:'dhcp',message:3,xid:0x31415926,clientMac:mac(42),hostName:'workstation-42',requested:'10.0.0.42',server:'10.0.0.1'},
    {type:'dhcp',message:5,xid:0x31415926,clientMac:mac(42),yiaddr:'10.0.0.42',server:'10.0.0.1',mask:'255.255.255.0',router:'10.0.0.1',dns:'10.0.0.53'},
    {type:'dns',src:'10.0.0.42',dst:'10.0.0.53',smac:mac(42),dmac:mac(53),name:'reports.test',dnsId:0x4242,sport:53420},
    {type:'dns',src:'10.0.0.53',dst:'10.0.0.42',smac:mac(53),dmac:mac(42),name:'reports.test',dnsId:0x4242,response:true,dport:53420,answers:['198.51.100.42']}
  ]},
  {id:'realworld-time-padding',title:'時刻と54バイト・60バイトの違い',description:'キャプチャ地点の違いを比べるため、同じ接続の記録を組み合わせた教材です。No. 1・3は端末の送信処理内でパディング前に得た記録、No. 2はLAN上でパディングを含めて得た記録を表します。FCSは全フレームに含まれません。比較用にTCP Optionsを省いています。',packets:[
    {type:'tcp',...client,flags:'S',seq:1000,tcpOptions:false,padEthernet:false,time:0},
    {type:'tcp',...server,flags:'SA',seq:9000,ack:1001,tcpOptions:false,time:.125},
    {type:'tcp',...client,flags:'A',seq:1001,ack:9001,tcpOptions:false,padEthernet:false,time:.175}
  ]},
  {id:'realworld-lan',title:'背景通信のあるLAN調査',description:'架空のLANミラーポートで約28秒間を観測した教材です。ARP・mDNS・SSDP・ICMPv6・別端末のDHCP設定・NTPの背景通信270パケットと、DNS2パケット、2本のHTTP接続12パケットを含みます。調査対象は10.0.0.42です。',packets:lan}
];

const lessons=[
  {id:'realworld-options',chapter:'realworld-basics',title:'TCP Optionsと生の番号',level:'guided',captureId:'realworld-tcp-options',intro:'実際のSYNでは、MSSやSACK Permitted、Window Scale、TimestampsなどのOptionsをよく見かけます。組み合わせはOSや設定で異なります。Info列が長くても、目的の項目を詳細から一つずつ探せます。',mission:'No. 1のMSSを読み、相対シーケンス番号と生の値を比べましょう。',hints:['No. 1のTCP詳細にあるMSS Valueと2種類のSequence Numberを探します。','MSSはTCPデータの最大サイズの提案です。ヘッダーを含むフレーム長とは違います。','tcp.options.mss_valは1460です。tcp.seqは0ですが、tcp.seq_rawには大きな32bit値があります。'],explanation:'このSYNのMSSは1460です。Window Scaleは7（倍率128）、SACK PermittedとTimestampsも含まれます。Wiresharkの相対Seq=0は表示上の基準で、パケット内の生の初期シーケンス番号はtcp.seq_rawで確認できます。双方のSYNでTimestampsを合意したこの接続では、その後のACKにもTimestamp optionがあります。',tasks:[
    {id:'mss',kind:'text',normalize:'number',prompt:'No. 1が提示するMSSは何バイト？',answer:'1460',evidence:[{frame:1,field:'tcp.options.mss_val'}],why:'TCP OptionのMSS Valueを読み取ります。'},
    {id:'relative',kind:'choice',prompt:'No. 1のSequence NumberとSequence Number (raw)を比べると？',options:[{value:'both-zero',label:'相対表示も生の値も0で、SYN/ACKから番号を付け始める。'},{value:'relative',label:'相対表示は0で、生の値には別の大きな32bit値が入っている。'},{value:'mss',label:'相対表示は1460で、生の値は送信元ポート番号と同じ。'}],answer:'relative',evidence:[{frame:1,field:'tcp.seq'},{frame:1,field:'tcp.seq_raw'}],evidenceMode:'all',why:'表示の基準値と、実際にヘッダーへ格納された番号を区別します。'}
  ]},
  {id:'realworld-extra',chapter:'realworld-basics',title:'Answer以外の追加情報',level:'practice',captureId:'realworld-extra-records',intro:'DNSのAdditional recordsやDHCPのOptionsには、主な結果を補う情報があります。項目の数が増えても、AnswerやYour IP Addressと混同せず、必要な設定値を探しましょう。',mission:'DNSのOPTで提示したUDPペイロードサイズと、DHCP ACKの更新開始時刻を読みましょう。',hints:['DNS問い合わせはNo. 5、DHCP ACKはNo. 4です。','DNSのOPTと、DHCPのOption 58を探します。Option 51は全リース時間です。','dns.rr.udp_payload_sizeは1232、dhcp.option.renewal_time_valueは1800秒です。'],explanation:'No. 5のAdditional RRs=1はEDNS0のOPTで、AnswerのIPアドレスが1件あるという意味ではありません。1232は受信可能なDNS UDPペイロードサイズの提示です。DHCP ACKはlease=3600秒、renewal=1800秒、rebinding=3150秒を配布します。DiscoverにはClient identifier・Host Name・Vendor class・Maximum message sizeも入っています。',tasks:[
    {id:'edns',kind:'text',normalize:'number',prompt:'No. 5のOPTで提示するUDP payload sizeは？',answer:'1232',evidence:[{frame:5,field:'dns.rr.udp_payload_size'}],why:'OPTはAnswerとは別の追加情報で、サイズの提示を含みます。'},
    {id:'renewal',kind:'text',normalize:'number',prompt:'No. 4のRenewal Time Value（更新を開始するまでの秒数）は？',answer:'1800',evidence:[{frame:4,field:'dhcp.option.renewal_time_value'}],why:'Option 58の値です。Lease TimeやRebinding Timeと区別します。'}
  ]},
  {id:'realworld-time',chapter:'realworld-basics',title:'時刻とキャプチャ地点を読む',level:'challenge',captureId:'realworld-time-padding',intro:'時刻列は相対秒・絶対時刻（UTC）・前フレームからの差に切り替えられます。実物のWiresharkのArrival Timeはローカル時刻で表示される設定もあります。UTC Arrival TimeやEpoch Arrival Timeと照合すれば、別のログと同じ基準で比べられます。',mission:'時刻列を切り替えてNo. 2を読み、54バイトと60バイトの理由を説明しましょう。',hints:['「前フレームとの差」に切り替えてNo. 2を選びます。差の基準はフィルター前の記録順です。','No. 2のFrameには時間差、EthernetにはPaddingがあります。No. 1のFrame Lengthと比べます。','No. 2のframe.time_deltaは0.125秒、eth.paddingは6バイトです。No. 1はframe.lenが54です。'],explanation:'No. 2のUTC時刻は2026-01-01 00:00:00.125で、前フレームとの差は0.125秒です。TCP Optionsなし・データなしならEthernet 14+IPv4 20+TCP 20=54バイト。LAN上ではFCSを除く最小60バイトまで6バイトのパディングが入ります。端末の送信処理内ではその追加前に54バイトとして記録されることがあります。この比較用キャプチャは複数地点の記録を組み合わせています。',tasks:[
    {id:'delta',kind:'text',normalize:'number',prompt:'No. 2の、前の収録フレームからの時間差は何秒？',answer:'0.125',evidence:[{frame:2,field:'frame.time_delta'}],why:'表示を絞った後の前の行ではなく、元のキャプチャで直前のフレームとの差です。'},
    {id:'padding',kind:'choice',prompt:'この教材でNo. 1が54バイト、No. 2が60バイトなのは？',options:[{value:'tcp-data',label:'No. 2だけTCPペイロードを6バイト含み、No. 1にはアプリケーションデータがない。'},{value:'fcs',label:'No. 2には4バイトのFCSと2バイトのパディングが含まれ、No. 1は両方を除いて記録されている。'},{value:'padding',label:'No. 2には6バイトのEthernetパディングがあり、No. 1はその追加前に記録されている。'}],answer:'padding',evidence:[{frame:1,field:'frame.len'},{frame:2,field:'eth.padding'}],evidenceMode:'all',why:'Frame LengthとEthernet Paddingの実デコード結果を対にして確認します。'}
  ]},
  {id:'realworld-dns',chapter:'realworld-investigation',title:'284件から名前解決を探す',level:'guided',captureId:'realworld-lan',intro:'担当者から「10.0.0.42でreports.testを開くとエラーになる」と相談されました。LANには別の端末の設定や機器発見も流れています。まず対象端末のDNSの往復を取り出します。背景通信を消す必要はありません。',mission:'10.0.0.42のDNSだけを表示し、応答のAレコードを答えましょう。',hints:['dnsだけでは機器発見の通信と見分けにくいことがあります。端末のIP条件も使います。','ip.addrは要求と応答の両方に一致します。','dns && ip.addr == 10.0.0.42で2件が残ります。応答のdns.aを根拠にします。'],explanation:`対象の名前解決はNo. ${dnsFrames.join('・')}です。reports.testには198.51.100.42のAレコードが返りました。このLANのmDNS・SSDP・ARPなどを一件ずつ読む代わりに、調査目的に合う条件で範囲を狭められます。名前解決の成功とHTTPの成功は別に確認します。`,tasks:[
    {id:'filter',kind:'filter',prompt:'10.0.0.42のDNSの往復2件だけを表示する',answer:dnsFrames,expectedFilter:'dns && ip.addr == 10.0.0.42',why:'表示結果に対象端末の問い合わせと応答が残っています。'},
    {id:'address',kind:'text',normalize:'ip',prompt:'reports.testに返ったAレコードのIPは？',answer:'198.51.100.42',evidence:[{frame:frame['dns-answer'],field:'dns.a'}],why:'DNSのAnswerを根拠に、次に調べる接続先を特定します。'}
  ]},
  {id:'realworld-stream',chapter:'realworld-investigation',title:'接続を1本に絞って追う',level:'practice',captureId:'realworld-lan',intro:'名前解決の次に、10.0.0.42と198.51.100.42のTCP接続を調べます。tcp.streamはWiresharkがそのキャプチャ内で付ける接続番号です。番号はキャプチャごとに変わるので、対象のパケットの詳細から読み取ります。',mission:'対象のTCPストリーム6件だけを表示し、ストリームを追跡してHTTPの結果を確認しましょう。',hints:['まずtcp && ip.addr == 10.0.0.42で接続を探します。','対象のTCP詳細でStream indexを読みます。別端末のHTTPはstream 0です。','tcp.stream == 1を適用します。「会話を追う」で要求と応答を見て、HTTP response codeを根拠にします。'],explanation:'対象のStream indexは1です。6パケットに絞るとSYNから要求・応答までの流れが見えます。HTTPは404 Not Foundで、/reports/latestに対して要求先の資源が見つからないという応答です。200を返した別端末のstream 0を混ぜて結論を出さないことが大切です。',tasks:[
    {id:'filter',kind:'filter',prompt:'10.0.0.42のHTTP接続に属するTCP 6件だけを表示する',answer:targetFrames,expectedFilter:'tcp.stream == 1',why:'対象の接続を握手から応答確認まで取り出せています。'},
    {id:'status',kind:'text',normalize:'number',prompt:'対象のTCP接続で返ったHTTP応答コードは？',answer:'404',evidence:[{frame:frame['target-response'],field:'http.response.code'}],why:'対象ストリームのHTTP応答を根拠にします。'}
  ]},
  {id:'realworld-contains',chapter:'realworld-investigation',title:'文字列検索から要求を特定する',level:'challenge',captureId:'realworld-lan',intro:'frame contains "GET"は、収録されたフレームのバイトに大文字GETがあるものを探します。プロトコルを問わない検索なので、GETがあればHTTP要求とは限りません。見つけた後に送信元やHTTPのフィールドで確かめます。分割された文字列や暗号化された本文には別の手段が必要です。',mission:'GETを含む2件を表示し、対象端末が要求したパスを根拠付きで報告しましょう。',hints:['表示フィルターにframe contains "GET"を入力します。大小文字を区別します。','2件の送信元を比べ、10.0.0.42から出た要求を選びます。','対象のhttp.request.uriは/reports/latestです。別端末の/healthと混同しないようにします。'],explanation:`No. ${getFrames.join('・')}にGETのバイト列があります。対象端末10.0.0.42の要求はGET /reports/latestで、別端末はGET /healthです。バイト検索は発見の入口です。送信元・URI・応答コードを同じ接続として確認すると「名前解決後、/reports/latestに対して404が返った」と報告できます。`,tasks:[
    {id:'filter',kind:'filter',prompt:'大文字のGETというバイト列を含む2件だけを表示する',answer:getFrames,expectedFilter:'frame contains "GET"',why:'プロトコル名ではなく、実際のフレームバイトを検索しています。'},
    {id:'path',kind:'text',normalize:'exact',prompt:'10.0.0.42がHTTPで要求したパスは？',answer:'/reports/latest',evidence:[{frame:frame['target-get'],field:'http.request.uri'}],why:'対象端末のHTTP Request URIを、別接続の要求から区別します。'}
  ]}
];

module.exports={chapters,captures,lessons};
