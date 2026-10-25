'use strict';
const chapters=[{id:'grad',title:'卒業調査',subtitle:'プロトコルをつないで、分かったことを説明する。'}];
const request='GET /guide HTTP/1.1\r\nHost: portal.test\r\nUser-Agent: pcaproom-easy\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: ja,en-US;q=0.8,en;q=0.6\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\n\r\n';
const response='HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\nWelcome';
const captures=[
 {id:'grad-connect',title:'新しい端末がネットワークにつながる',description:'端末が参加するLANのミラーポートで記録した架空の教材です。DHCPv4による初回設定から名前解決までを含みます。',packets:[
  {type:'dhcp',message:1,xid:900,clientMac:'02:00:00:00:00:45'},
  {type:'dhcp',message:2,xid:900,clientMac:'02:00:00:00:00:45',yiaddr:'10.0.0.45',mask:'255.255.255.0',server:'10.0.0.1',router:'10.0.0.1',dns:'10.0.0.53'},
  {type:'dhcp',message:3,xid:900,clientMac:'02:00:00:00:00:45',requested:'10.0.0.45',server:'10.0.0.1'},
  {type:'dhcp',message:5,xid:900,clientMac:'02:00:00:00:00:45',yiaddr:'10.0.0.45',mask:'255.255.255.0',server:'10.0.0.1',router:'10.0.0.1',dns:'10.0.0.53'},
  {type:'arp',op:1,psrc:'10.0.0.45',pdst:'10.0.0.53',hwsrc:'02:00:00:00:00:45'},
  {type:'arp',op:2,psrc:'10.0.0.53',pdst:'10.0.0.45',hwsrc:'02:00:00:00:00:53',hwdst:'02:00:00:00:00:45'},
  {type:'dns',src:'10.0.0.45',dst:'10.0.0.53',smac:'02:00:00:00:00:45',dmac:'02:00:00:00:00:53',name:'docs.test',dnsId:901,sport:53045},
  {type:'dns',src:'10.0.0.53',dst:'10.0.0.45',smac:'02:00:00:00:00:53',dmac:'02:00:00:00:00:45',name:'docs.test',dnsId:901,response:true,dport:53045,answers:['192.0.2.80']}
 ]},
 {id:'grad-failure',title:'疎通できるのにサービスが使えない',description:'端末10.0.0.21で記録した、ping・名前解決・TCP接続試行の教材です。この記録にはサーバー内部のログは含まれません。',packets:[
  {type:'icmp',src:'10.0.0.21',dst:'192.0.2.80',icmpType:8,icmpId:21,icmpSeq:1},
  {type:'icmp',src:'192.0.2.80',dst:'10.0.0.21',icmpType:0,icmpId:21,icmpSeq:1},
  {type:'dns',src:'10.0.0.21',dst:'10.0.0.53',name:'service.test',dnsId:921,sport:53210},
  {type:'dns',src:'10.0.0.53',dst:'10.0.0.21',response:true,name:'service.test',dnsId:921,dport:53210,answers:['192.0.2.80']},
  {type:'tcp',src:'10.0.0.21',dst:'192.0.2.80',sport:52021,dport:8080,flags:'S',seq:100},
  {type:'tcp',src:'192.0.2.80',dst:'10.0.0.21',sport:8080,dport:52021,flags:'RA',seq:0,ack:101}
 ]},
 {id:'grad-web',title:'Webの結果と見える範囲',description:'端末10.0.0.30のインターフェースで記録したHTTPアクセスと、別接続のTLS ClientHelloです。TLSの復号情報はありません。ClientHello後の通信はこのキャプチャには収録していません。',packets:[
  {type:'dns',src:'10.0.0.30',dst:'10.0.0.53',name:'portal.test',dnsId:930,sport:53300},
  {type:'dns',src:'10.0.0.53',dst:'10.0.0.30',response:true,name:'portal.test',dnsId:930,dport:53300,answers:['198.51.100.20']},
  {type:'tcp',src:'10.0.0.30',dst:'198.51.100.20',sport:53080,dport:80,flags:'S',seq:1000},
  {type:'tcp',src:'198.51.100.20',dst:'10.0.0.30',sport:80,dport:53080,flags:'SA',seq:8000,ack:1001},
  {type:'tcp',src:'10.0.0.30',dst:'198.51.100.20',sport:53080,dport:80,flags:'A',seq:1001,ack:8001},
  {type:'tcp',src:'10.0.0.30',dst:'198.51.100.20',sport:53080,dport:80,flags:'PA',seq:1001,ack:8001,payload:request},
  {type:'tcp',src:'198.51.100.20',dst:'10.0.0.30',sport:80,dport:53080,flags:'PA',seq:8001,ack:1001+Buffer.byteLength(request),payload:response},
  {type:'tcp',src:'10.0.0.30',dst:'198.51.100.20',sport:53080,dport:80,flags:'A',seq:1001+Buffer.byteLength(request),ack:8001+Buffer.byteLength(response)},
  {type:'tcp',src:'10.0.0.30',dst:'198.51.100.20',sport:53443,dport:443,flags:'S',seq:3000},
  {type:'tcp',src:'198.51.100.20',dst:'10.0.0.30',sport:443,dport:53443,flags:'SA',seq:9000,ack:3001},
  {type:'tcp',src:'10.0.0.30',dst:'198.51.100.20',sport:53443,dport:443,flags:'A',seq:3001,ack:9001},
  {type:'tls',src:'10.0.0.30',dst:'198.51.100.20',sport:53443,dport:443,seq:3001,ack:9001,tlsKind:'clientHello',serverName:'secure.test'}
 ]}
];
const lessons=[
 {id:'grad-1',chapter:'grad',title:'端末がつながるまで',level:'challenge',captureId:'grad-connect',intro:'新しい端末をLANに接続しました。担当者から「設定と名前解決が進んだか、記録から確認してほしい」と依頼されています。ここでは設定の受領とDNSの応答までを確認します。',mission:'割り当てられたIP、DNSサーバー、名前解決の結果を根拠付きでまとめましょう。',hints:['DHCP ACK、ARP、DNS responseの順に読みます。','ACKのYour IP AddressとDNS option、DNSのAnswersを探します。','No. 4のdhcp.ip.yourとdhcp.option.domain_name_server、No. 8のdns.aが根拠です。'],explanation:'DHCP ACKで10.0.0.45とDNSサーバー10.0.0.53が配布され、ARPでDNSサーバーのMACを調べた後、docs.testのAレコード192.0.2.80が返りました。このキャプチャにはWebアクセスの結果はありません。',tasks:[
  {id:'assigned',kind:'text',normalize:'ip',prompt:'ACKで割り当てられた端末のIPは？',answer:'10.0.0.45',evidence:[{frame:4,field:'dhcp.ip.your'}],why:'ACKのYour IP Addressが割り当てられたIPです。'},
  {id:'dns-server',kind:'text',normalize:'ip',prompt:'配布されたDNSサーバーのIPは？',answer:'10.0.0.53',evidence:[{frame:4,field:'dhcp.option.domain_name_server'}],why:'DHCPのDNS Server optionで配布されています。'},
  {id:'resolved',kind:'text',normalize:'ip',prompt:'docs.testのAレコードとして返ったIPは？',answer:'192.0.2.80',evidence:[{frame:8,field:'dns.a'}],why:'DNS応答のAnswerに記録されたIPv4アドレスです。'}
 ]},
 {id:'grad-2',chapter:'grad',title:'どこまで成功している？',level:'challenge',captureId:'grad-failure',intro:'「pingには応答があるのに、service.test:8080へ接続できない」という相談です。通信の各段階を分けて観察し、記録以上の原因を決めつけない報告を作ります。',mission:'疎通・名前解決・TCP接続の結果を順に確認しましょう。',hints:['ICMP Echo Reply、DNS Answer、SYNに対するTCP応答を確認します。','No. 6ではSYN/ACKではなくRSTが返っています。','ICMPはNo. 2、DNSはNo. 4、TCP RSTはNo. 6が根拠です。サービス停止かFWかの断定はできません。'],explanation:'Echo ReplyとDNSのAレコード応答が観測されていますが、TCP/8080へのSYNに対してRST/ACKが返り、この試行は接続成立に至っていません。待受サービスがない、途中の機器が拒否した等の内部理由は、このPCAPだけでは確定できません。',tasks:[
  {id:'ping',kind:'choice',prompt:'pingについて確認できることは？',options:[{value:'reply',label:'192.0.2.80からEcho Replyを受信している'},{value:'all',label:'192.0.2.80からDestination Unreachableを受信している'},{value:'none',label:'Echo Requestはあるが、対応するReplyは記録されていない'}],answer:'reply',evidence:[{frame:2,field:'icmp.type'}],why:'No.2はEcho Replyです。疎通の証拠ですが、アプリの正常動作までは示しません。'},
  {id:'name',kind:'text',normalize:'ip',prompt:'service.testのAレコードは？',answer:'192.0.2.80',evidence:[{frame:4,field:'dns.a'}],why:'名前解決の応答には192.0.2.80が返っています。'},
  {id:'connection',kind:'choice',prompt:'TCP接続について報告できることは？',options:[{value:'reset',label:'SYNに対してRST/ACKが返り、この接続試行は成立していない。'},{value:'ok',label:'SYNに対してSYN/ACKが返り、最後のACKまで記録されている。'},{value:'stopped',label:'SYNに対してFIN/ACKが返り、通常の切断手順を開始している。'}],answer:'reset',evidence:[{frame:6,field:'tcp.flags.reset'}],why:'No.6はRST/ACKです。SYN/ACKやFIN/ACKとは異なります。RSTが観測されたことと、その内部原因は分けて報告します。'}
 ]},
 {id:'grad-3',chapter:'grad',title:'通信を根拠付きで説明する',level:'challenge',captureId:'grad-web',intro:'同じ端末の平文HTTPとTLS接続開始が収録されています。HTTPの結果を読み、TLSでは観測できる範囲に絞って説明しましょう。必要に応じてTCPストリームを追跡できます。',mission:'要求されたパス、HTTPの応答コード、別接続のTLSで判断できる範囲を答えましょう。',hints:['httpで絞ると要求と応答を探しやすくなります。TLSを見るときはフィルターを解除します。','HTTPはNo. 6とNo. 7、TLS ClientHelloはNo. 12です。','/guide、200がHTTPの結果です。TLS ClientHelloのSNIはsecure.testですが、URLパスや表示完了は分かりません。'],explanation:'portal.testにGET /guideが送られ、200 OKとWelcomeという本文が返っています。別接続ではsecure.testをSNIに含むTLS ClientHelloを観測できますが、それ以降は収録されていないため、TLS成立・URLパス・ページ表示の成否は確認できません。',tasks:[
  {id:'path',kind:'text',normalize:'exact',prompt:'HTTPで要求したパスは？',answer:'/guide',evidence:[{frame:6,field:'http.request.uri'}],why:'HTTP Request URIで確認できます。'},
  {id:'status',kind:'text',normalize:'number',prompt:'HTTP応答コードは？',answer:'200',evidence:[{frame:7,field:'http.response.code'}],why:'このHTTP要求には200 OKが返っています。'},
  {id:'limit',kind:'choice',prompt:'TLS接続について、記録から言えることは？',options:[{value:'sni',label:'ClientHelloのSNIはsecure.test。その後のTLS通信は記録されていない。'},{value:'same',label:'ClientHelloのSNIはportal.test。その後のTLS通信は記録されていない。'},{value:'complete',label:'ClientHelloのSNIはsecure.test。その後にServerHelloも記録されている。'}],answer:'sni',evidence:[{frame:12,field:'tls.handshake.extensions_server_name'}],why:'No.12で観測できるSNIはsecure.testです。portal.testは別の平文HTTPのHostで、ClientHello後のTLS通信はこの記録にはありません。URLのパスや接続完了も判断できません。'}
 ]}
];
// On the client LAN, off-link traffic goes through the gateway MAC.
const linkMac=ip=>ip?.startsWith('10.0.0.')?'02:00:00:00:00:'+ip.split('.').at(-1).padStart(2,'0'):'02:00:00:00:00:01';
for(const capture of captures)for(const p of capture.packets)if(!['dhcp','arp'].includes(p.type)){p.smac=p.smac||linkMac(p.src);p.dmac=p.dmac||linkMac(p.dst);if(/^(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(p.src||''))p.ttl=p.ttl??55;}
// Vary the displayed answer position deterministically; saved answers use value.
let choiceIndex=0;
for(const lesson of lessons)for(const task of lesson.tasks){if(task.kind!=='choice')continue;const shift=choiceIndex++%task.options.length;task.options=[...task.options.slice(shift),...task.options.slice(0,shift)];}
module.exports={chapters,captures,lessons};
