'use strict';

// One self-contained case uses the existing capture without changing its bytes
// or the completion proofs of the first 51 lessons.
const spec=require('./realworld').captures.find(c=>c.id==='realworld-lan');
const request=spec.packets.findIndex(p=>p.src==='10.0.0.42'&&p.payload?.startsWith('GET /reports/latest '))+1;
const response=spec.packets.findIndex(p=>p.payload?.startsWith('HTTP/1.1 404 '))+1;
const chapter='log-correlation';
const chapters=[{id:chapter,title:'通信とログを照合する',subtitle:'同じ要求を別の記録で確かめ、事実と未確認事項を伝える。'}];
const en={chapters:{[chapter]:{title:'Correlate packets and logs',subtitle:'Follow one request across records, then report findings and open questions.'}},lessons:{}};
const cards=[
 {id:'scope',title:'収集条件',body:'担当者から「10.0.0.42でreports.testのレポートを開けない」と連絡がありました。PCAPは2026-01-01 00:00:00〜00:00:28.300 UTCのLANミラーポートの記録です。今回の対象はNAT・プロキシを経由せず、時計は100ミリ秒以内で同期しています。アクセスログは応答処理終了時のJSTを秒単位で切り捨てて記録し、監査ログはアプリ処理時刻をUTCで記録します。同時刻の完全一致ではなく、時刻範囲・送信元・Host・Method・URI・応答を照合してください。アクセスログはPCAPの前後も含みます。サーバーがサービス内で一意に付けたrequest_idでアクセスと監査を結べますが、このPCAPのHTTPヘッダーにはそのIDはありません。',rows:[]},
 {id:'access',title:'アクセスログ（JST）',body:'Web受付が記録した合成ログです。bytesは応答本文のバイト数。A1〜A4はこの資料の行番号で、パケット番号ではありません。',rows:[
  {id:'A1',text:'10.0.0.42 [01/Jan/2026:08:59:55 +0900] host=reports.test "GET /reports/latest HTTP/1.1" status=200 bytes=90 request_id=req-report-old'},
  {id:'A2',text:'10.0.0.22 [01/Jan/2026:09:00:10 +0900] host=monitor.test "GET /health HTTP/1.1" status=200 bytes=3 request_id=req-health-022'},
  {id:'A3',text:'10.0.0.42 [01/Jan/2026:09:00:21 +0900] host=reports.test "GET /reports/latest HTTP/1.1" status=404 bytes=10 request_id=req-report-042'},
  {id:'A4',text:'10.0.0.42 [01/Jan/2026:09:00:35 +0900] host=reports.test "GET /reports/help HTTP/1.1" status=200 bytes=250 request_id=req-help-042'}]},
 {id:'audit',title:'アプリ監査ログ（UTC）',body:'action=report_readはレポート取得処理、result=not_foundは対象レポートなし、reason=report_missingは要求先のレポートがその時点で見つからなかったというアプリの記録です。生成処理や削除操作の記録は提供されていません。',rows:[
  {id:'B1',text:'2025-12-31T23:59:54.800Z service=reports request_id=req-report-old action=report_read result=success'},
  {id:'B2',text:'2026-01-01T00:00:21.700Z service=reports request_id=req-report-042 action=report_read result=not_found reason=report_missing'},
  {id:'B3',text:'2026-01-01T00:00:10.400Z service=monitor request_id=req-health-022 action=healthcheck result=success'},
  {id:'B4',text:'2026-01-01T00:00:34.800Z service=reports request_id=req-help-042 action=help_read result=success'}]}
];
const englishCards=[
 {title:'Collection context',body:'A user reports that 10.0.0.42 cannot open the report on reports.test. The PCAP covers a LAN mirror port from 2026-01-01 00:00:00 to 00:00:28.300 UTC. The target uses a direct connection without NAT or a proxy; clocks are synchronized within 100 milliseconds. Access logs record response-completion time in JST, truncated to whole seconds. Audit logs record application-processing time in UTC. Correlate a time range, source, Host, Method, URI, and response rather than demanding identical timestamps. Access logs also include events before and after the capture. The server assigns a request_id unique within its service to join access and audit records; this PCAP does not contain that ID in HTTP headers.'},
 {title:'Access logs (JST)',body:'Synthetic records from the web frontend. bytes is the response-body byte count. A1–A4 are document row IDs, not packet numbers.'},
 {title:'Application audit logs (UTC)',body:'action=report_read is a report retrieval operation. result=not_found and reason=report_missing record that the requested report was not found at that time. No report-generation or deletion records are provided.'}
];
const lessons=[];
function add(id,level,ja,english,tasks,englishTasks,referenceCount=3){
 lessons.push({id,chapter,level,captureId:'realworld-lan',...ja,tasks,referenceCards:cards.slice(0,referenceCount),...(level==='challenge'?{reflection:true}:{})});
 en.lessons[id]={...english,tasks:englishTasks,referenceCards:englishCards.slice(0,referenceCount)};
}
add('correlation-packets','guided',{
 title:'要求と応答を取り出す',intro:'最後の調査は、通信とサーバー側の記録をつなぎます。まず自分で対象の要求と応答を選びます。tcp.streamはこのキャプチャ内の接続番号です。同じ接続に複数のHTTP要求がある場合もあるため、Host・Method・URIを確かめます。',
 mission:'対象端末のGET要求と、その応答を根拠付きで確認しましょう。',
 hints:['http && ip.addr == 10.0.0.42で対象のHTTPを絞ります。','要求の送信元とURI、対応する応答コードを確認します。',`要求はNo. ${request}、応答はNo. ${response}です。`],
 explanation:'10.0.0.42がreports.testへGET /reports/latestを送り、404が返っています。別端末の/healthへの200や、SSDPのHTTPに似た表記と混同しません。404の内部理由は、この段階では未確認です。'
},{title:'Find the request and response',intro:'This final case joins traffic with server records. First select the target request and response yourself. tcp.stream identifies a connection within this capture, not an HTTP request. A connection can carry multiple requests; verify Host, Method, and URI.',mission:'Identify the target GET request and its response with packet evidence.',hints:['Use http && ip.addr == 10.0.0.42 to isolate the target HTTP traffic.','Check the request source and URI, then the matching response code.',`The request is No. ${request}; the response is No. ${response}.`],explanation:'10.0.0.42 sends GET /reports/latest to reports.test and receives 404. Do not mix in the other client’s /health 200 or HTTP-like SSDP messages. The internal reason for 404 is still unknown.'},[
 {id:'request',kind:'text',normalize:'exact',prompt:'10.0.0.42が要求したURIは？ 送信元とURIの両方を根拠にしてください。',answer:'/reports/latest',evidence:[{frame:request,field:'ip.src'},{frame:request,field:'http.request.uri'}],evidenceMode:'all',why:'対象端末の要求とパスを同じパケットで確認します。'},
 {id:'response',kind:'text',normalize:'number',prompt:'その要求に返ったHTTP応答コードは？',answer:'404',evidence:[{frame:response,field:'http.response.code'}],why:'対象要求への応答が404であることを確認します。内部原因とは区別します。'}
],[{prompt:'Which URI did 10.0.0.42 request? Add both the source and URI as evidence.',why:'Verify the target source and path in the same request packet.'},{prompt:'Which HTTP status code was returned for that request?',why:'The response is 404. This is separate from its internal cause.'}],1);

add('correlation-logs','practice',{
 title:'時刻と要求IDでログを結ぶ',intro:'PCAPの絶対時刻はUTC、アクセスログはJST（UTC+9時間）です。要求・アプリ処理・応答終了は別の時点であり、秒の端数も異なります。まず複数項目でアクセス行を選び、そのrequest_idで監査へ進みます。',mission:'資料のアクセス行と監査行を選び、対象の要求を2種類のログで確かめましょう。',
 hints:['時刻表示を絶対時刻（UTC）へ変更し、対象の応答とアクセス行を比べます。','09:00:21 JSTは00:00:21 UTCの秒です。送信元・Host・GET・URI・404も合わせます。','アクセスはA3、同じreq-report-042を記録する監査はB2です。'],
 explanation:'No. '+response+'は00:00:21.900 UTC。A3は処理終了時刻を秒単位で切り捨てた09:00:21 JSTなので、時刻の完全一致は要求しません。IP・Host・Method・URI・404を照合してA3を選び、req-report-042からB2へ進みます。PCAPにrequest_idがあると仮定しません。'
},{title:'Join logs by time and request ID',intro:'PCAP absolute time is UTC; access logs use JST (UTC+9). A request, application processing, and response completion happen at different instants and with different precision. Match an access row using several fields, then follow its request_id to the audit.',mission:'Choose the access and audit rows that describe the target request.',hints:['Switch the packet time display to absolute UTC and compare the response with the access rows.','09:00:21 JST is the 00:00:21 UTC second. Also match source, Host, GET, URI, and 404.','Choose A3, then B2 with the same req-report-042.'],explanation:`No. ${response} is at 00:00:21.900 UTC. A3 records completion as 09:00:21 JST, truncated to seconds, so exact timestamps need not match. Match IP, Host, Method, URI, and 404 to A3, then use req-report-042 to find B2. Do not assume request_id is present in the PCAP.`},[
 {id:'access-row',kind:'choice',prompt:'対象の要求に対応するアクセス行は？ PCAPのURIと応答時刻も根拠にしてください。',options:cards[1].rows.map(r=>({value:r.id,label:r.id})),answer:'A3',evidence:[{frame:request,field:'http.request.uri'},{frame:response,field:'frame.time_epoch'}],evidenceMode:'all',why:'時刻範囲と送信元・Host・Method・URI・応答が対応するA3です。A1は同じURIでもキャプチャより前です。'},
 {id:'audit-row',kind:'choice',prompt:'アプリ処理結果を確認する、アクセス行と監査行の正しい組は？',options:[{value:'A3-B1',label:'A3 → B1'},{value:'A2-B3',label:'A2 → B3'},{value:'A3-B2',label:'A3 → B2'},{value:'A4-B4',label:'A4 → B4'}],answer:'A3-B2',why:'A3とB2はservice=reportsに属する同じreq-report-042を記録します。B2のnot_found / report_missingを確認できます。'}
],[{prompt:'Which access row matches the target? Add the PCAP URI and response timestamp as evidence.',why:'A3 matches the time range, source, Host, Method, URI, and response. A1 has the same URI but precedes the capture.',options:{A1:'A1',A2:'A2',A3:'A3',A4:'A4'}},{prompt:'Which access/audit pair confirms the application result?',why:'A3 and B2 share req-report-042 within the reports service. B2 records not_found / report_missing.',options:{'A3-B1':'A3 → B1','A2-B3':'A2 → B3','A3-B2':'A3 → B2','A4-B4':'A4 → B4'}}]);

add('correlation-report','challenge',{
 title:'事実と未確認事項を引き継ぐ',intro:'通信の結果とアプリの記録を根拠に、次の担当者が動ける報告を選びます。404やreport_missingだけで、生成失敗・削除・攻撃・利用者の画面表示を断定しません。',mission:'言える範囲と次の確認を選び、必要なら自分の引継ぎメモも残しましょう。',
 hints:['PCAPが示すHTTP応答と、B2が示すアプリの結果を分けて整理します。','レポートがない理由を説明する、生成・削除の記録はありません。','根拠No. '+response+'・A3・B2を示し、生成処理などの記録をアプリ担当者へ確認する報告を選びます。'],
 explanation:'確認済みはGET /reports/latestへの404と、同じ要求のreport_missingです。未生成・削除などの原因は未確認です。アプリ担当者へ生成処理と保存・削除の記録を依頼します。これは任意の短い引継ぎ練習で、ほかのroomの履修は不要です。自由記述は保存・模範比較用で、文章の意味は自動採点しません。'
},{title:'Hand off findings and open questions',intro:'Use packet observations and application records to choose a useful handoff. Neither 404 nor report_missing alone establishes generation failure, deletion, an attack, or what the user saw on screen.',mission:'Choose a supported conclusion and next check. Optionally write your own handoff note.',hints:['Separate the HTTP response in the PCAP from the application outcome in B2.','No generation or deletion records explain why the report is missing.',`Choose a report citing No. ${response}, A3, and B2 and asking the application owner for generation and storage/deletion records.`],explanation:'The confirmed findings are a 404 for GET /reports/latest and report_missing for the same request. Whether the report was never generated or later deleted is unknown. Ask the application owner for generation and storage/deletion records. This optional handoff exercise is self-contained. Free text is saved for comparison, not automatically graded for meaning.'},[
 {id:'limit',kind:'choice',prompt:'PCAPとA3・B2を合わせて、どこまで言えますか？',options:[
  {value:'dns',label:'DNS応答がないため要求は届かず、404は端末側の名前解決失敗を示している。'},
  {value:'missing',label:'要求に404が返り、同じ要求の監査でもレポートなしを記録。生成・削除の原因は未確認。'},
  {value:'deleted',label:'要求に404が返り、同じ要求の監査がreport_missingなので、不正な削除が完了した。'}],answer:'missing',evidence:[{frame:response,field:'http.response.code'}],why:'HTTP応答とアプリの結果を説明できますが、原因や悪意はこれだけでは確定しません。'},
 {id:'handoff',kind:'choice',prompt:'根拠と未確認事項を残し、次の担当者へ渡す報告は？',options:[
  {value:'close',label:'No. '+response+'・A3・B2で404とレポートなしを確認。HTTP応答はあるのでサービスは正常と判断し、利用者の再試行だけでクローズする。'},
  {value:'investigate',label:'No. '+response+'・A3・B2で対象要求の404とレポートなしを確認。原因は未確認。アプリ担当者へ生成処理と保存・削除の記録を依頼する。'},
  {value:'isolate',label:'No. '+response+'・A3・B2で404とレポートなしを確認。不正削除が原因と判断し、追加ログを待たず対象端末の隔離を依頼する。'}],answer:'investigate',why:'事実・出典・未確認の原因・確認先と必要資料を残す報告です。任意メモはこの4点で自己比較できます。'}
],[{prompt:'What can the PCAP together with A3 and B2 establish?',why:'You can report the HTTP and application outcomes, but cannot establish the cause or malicious intent.',options:{dns:'No DNS reply arrived, so the request never reached the server and 404 indicates a client name-resolution failure.',missing:'The request received 404 and its audit records a missing report. Generation/deletion causes remain unverified.',deleted:'The request received 404 and its audit says report_missing, so an unauthorized deletion completed.'}},{prompt:'Which handoff preserves evidence and uncertainty and identifies the next check?',why:'The handoff retains facts, sources, the unknown cause, and the owner and records needed next. Compare your optional note against these four points.',options:{close:`No. ${response}, A3, and B2 confirm 404 and a missing report. Because HTTP responded, declare the service healthy, ask the user to retry, and close the case.`,investigate:`No. ${response}, A3, and B2 confirm 404 and a missing report for the target request. The cause is unknown. Ask the application owner for generation and storage/deletion records.`,isolate:`No. ${response}, A3, and B2 confirm 404 and a missing report. Conclude unauthorized deletion and request device isolation without seeking further logs.`}}]);

module.exports={chapters,captures:[],lessons,en};
