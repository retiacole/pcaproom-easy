'use strict';
const fs=require('node:fs'),path=require('node:path');
const {buildCapture}=require('./packet-tools');
const E=require('./src/engine');
const modules=['operations','foundation','applications','graduation','realworld'].map(n=>require('./content/'+n));
const chapters=modules.flatMap(m=>m.chapters),lessons=modules.flatMap(m=>m.lessons),specs=modules.flatMap(m=>m.captures);
const glossary=[
 ['パケット／フレーム','ネットワーク上を流れるデータのまとまり。この教材はEthernetフレームを1行ずつ表示し、内部のIPやTCPなどを展開します。'],
 ['キャプチャ','特定の場所・時間で観測して記録した通信。記録にない通信が実際になかったとは限りません。'],
 ['Source／Destination','そのパケットの送信元／宛先。要求と応答では逆向きになります。'],
 ['MACアドレス','同じリンク内でフレームを届けるためのアドレス。ルーターを越えるIPの宛先とは役割が違います。'],
 ['IPアドレス','IP通信の送信元・宛先を示すアドレス。IPv4とIPv6では表記やヘッダーが異なります。'],
 ['ポート番号','TCPやUDPで、通信先のサービスや通信の組を区別する番号。ポート番号だけで実際のアプリを確定しないようにします。ICMPにはTCP/UDPのようなポートはありません。'],
 ['Ethernet','LANで使われるリンク層の通信方式。MACアドレスやEtherTypeを読みます。'],
 ['ARP','同じIPv4リンク上で、IPv4アドレスに対応するMACアドレスを調べる仕組み。離れたサーバーには通常、まずゲートウェイのMACを使って送ります。'],
 ['TTL／Hop Limit','ルーターを通過すると減少する値。ループし続けることを防ぎます。経過秒数ではありません。'],
 ['ICMP／ICMPv6','IP通信の制御やエラー通知に使われます。pingのEchoだけでなく到達不能なども含みます。'],
 ['NDP／RA','IPv6の近隣探索とルーター発見の仕組み。ICMPv6を使用し、IPv4のARPとは異なります。RAはルーターやプレフィックスなどを通知します。IPv6ではSLAACやDHCPv6などの設定方法もあります。'],
 ['UDP','データグラムを送るトランスポート。UDP自体はTCPのような接続確立や順序・再送保証を持ちません。アプリが独自に要求応答や再試行を行うことはあります。'],
 ['TCP','順序のあるバイトストリームを提供するトランスポート。SYN等で接続を開始し、シーケンス番号・ACKで通信を管理します。'],
 ['SYN／ACK／FIN／RST','TCPのフラグ。SYNは接続開始、ACKは確認応答、FINは片方向の送信終了、RSTは接続のリセットなどを表します。文脈と合わせて読みます。'],
 ['TCP Stream','同じTCP接続のデータを組み立てて読む表示。1つのアプリメッセージが複数パケットに分かれることがあります。暗号化データは追跡しただけでは復号できません。'],
 ['DNS','名前と情報を対応づける仕組み。AはIPv4、AAAAはIPv6のレコードです。UDPとTCPの両方で使われます。暗号化されたDNSもあります。'],
 ['DHCP','端末にIPやDNSサーバーなどを配布する仕組み。ここではDHCPv4の初回取得を練習します。IPv6のDHCPv6はメッセージ形式も異なります。'],
 ['NTP','時刻を同期するプロトコル。ModeやStratumなどを確認します。応答があるだけで端末の時計が正常だと断定はできません。'],
 ['HTTP','要求と応答でリソースをやり取りするプロトコル。この教材の平文例はTCP上のHTTP/1.1です。応答コードと正当な業務かどうかは別の判断です。'],
 ['TLS／SNI','TLSは通信を保護する仕組み。SNIはClientHelloで接続先名を知らせる情報で、常に観測できるとは限りません。URLのパスや本文が見えるとは限りません。'],
 ['QUIC／HTTP/3','UDPを使うQUIC上でHTTP/3が動作します。「Webは必ずTCP」とは限りません。この初版では用語の紹介にとどめています。'],
 ['表示フィルター','読み込んだパケットから、条件に合うものを表示する機能。元の記録は消えません。収集時のキャプチャフィルターとは構文も用途も異なります。'],
 ['再構成されたフィールド','複数パケットを組み立てて解析した情報。選択中の1フレームのバイト列には対応位置がない場合があります。']
].map(([term,description])=>({term,description}));
fs.mkdirSync(path.join(__dirname,'captures'),{recursive:true});
const captures=specs.map((s,i)=>{const c=buildCapture(s);fs.writeFileSync(path.join(__dirname,'captures',c.id+'.pcap'),Buffer.from(c.pcapBase64,'base64'));process.stdout.write(`Capture ${i+1}/${specs.length}: ${c.id}\n`);return c;});
const data={version:'0.3.0',chapters,captures,lessons,glossary,translations:{en:require('./content/en')}};
const errors=[...E.validateData(data),...require('./content/validate-translations')(data,data.translations.en)];if(errors.length)throw new Error(errors.join('\n'));
const js='globalThis.PcapData='+JSON.stringify(data)+';';
fs.writeFileSync(path.join(__dirname,'src/data.js'),js);
if(process.argv.includes('--data-only'))process.exit(0);
let html=fs.readFileSync(path.join(__dirname,'src/shell.html'),'utf8');
// Keep the supplied artwork inside the standalone file for fully offline help.
const helpArtwork=fs.readFileSync(path.join(__dirname,'assets/help-ending.png'));
html=html.replace('src="assets/help-ending.png"',()=>`src="data:image/png;base64,${helpArtwork.toString('base64')}"`);
for(const [key,file]of Object.entries({CSS:'style.css',DATA:'data.js',ENGINE:'engine.js',I18N:'i18n.js',APP:'app.js'})){
 let content=fs.readFileSync(path.join(__dirname,'src',file),'utf8');if(key!=='CSS')content=content.replace(/<\/script/gi,'<\\/script');html=html.replace('/*__'+key+'__*/',()=>content);
}
if(/\/\*__\w+__\*\//.test(html))throw new Error('Unreplaced build marker');
fs.writeFileSync(path.join(__dirname,'pcaproom-easy.html'),html);
console.log(`Built ${lessons.length} lessons, ${captures.length} captures; ${(Buffer.byteLength(html)/1024/1024).toFixed(2)} MiB`);
