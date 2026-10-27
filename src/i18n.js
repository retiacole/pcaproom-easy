(function(root){
'use strict';
const STORE='pcaproom-easy.language.v1';
let locale='ja';
try{if(localStorage.getItem(STORE)==='en')locale='en';}catch{}
const messages={
'本文へ':'Skip to content','ガイド付き':'Guided','練習':'Practice','自力で確認':'Independent',
'pcaproom-easy 学習マップ':'pcaproom-easy learning map','用語帳':'Glossary','使い方':'How to use','保存':'Save','読込':'Load',
'通信の中身を、':'Read network traffic,','ひとつずつ読み解く。':'one packet at a time.','一覧からパケットを選び、詳細を開いて、根拠を残す。':'Select a packet, explore its details, and collect evidence.',
'続きから練習する':'Continue learning','最初のパケットを開く':'Open your first packet','時間制限なし · 間違えても減点なし':'No time limit · No penalties for mistakes','プロトコルテーマ':' protocol topics','ポイント':' points',
'パケットを読む流れ':'Steps for reading a packet','届け先のMAC':'Destination MAC','送信元と宛先':'Source and destination','ポートと長さ':'Ports and length','名前の問い合わせ':'Name query',
'1つのパケットに、複数のプロトコル。':'One packet, multiple protocols.','階層をたどると、通信の意味が見えてきます。':'Follow the layers to understand the exchange.',
'ガイドに沿って操作':'Follow a guide','別のデータで練習':'Practice on new data','自分で根拠を選ぶ':'Choose your own evidence',
'基礎から、ひとつの調査へ。':'From the basics to an investigation.','どの章からでも練習できます。':'Start with any chapter.','初めてなら01から。':'New here? Try chapter 01.','全体の進捗':'Overall progress',
'1問 1フラグ / 100pt · ヒントと解説つき':'1 lesson = 1 flag / 100pt · Hints and explanations included',
'問題を選ぶ':'Choose a lesson','パケット解析':'Packet analysis','パケット一覧':'Packet list','会話を追う':'Follow stream','PCAP保存':'Save PCAP','表示フィルター':'Display filter',
'表示フィルター 例：dns && ip.addr == 10.0.0.10':'Display filter, e.g. dns && ip.addr == 10.0.0.10','適用':'Apply','解除':'Clear','早見表':'Reference',
'時刻表示':'Time display','開始からの秒数':'Seconds since start','絶対時刻（UTC）':'Absolute time (UTC)','前フレームとの差（秒）':'Previous-frame delta (s)','相対時刻（秒）':'Relative time (s)',
'差分はフィルター前の記録で計算':'Delta uses original capture order','基本項目だけ表示':'Show basic fields','すべての項目を表示':'Show all fields','プロトコルの階層':'Protocol layers',
'詳細の項目を選ぶと、ここに根拠候補が表示されます。':'Select a detail field to see a candidate for evidence.','この項目で絞る':'Filter by this field','根拠に追加':'Add evidence',
'Packet Bytes · 16進数と文字':'Packet Bytes · Hex and text','項目を選ぶとフィールド名が表示されます。':'Select a field to see its name.','問題と回答':'Lesson and answer','今回のミッション':'Your mission',
'背景通信の中から探してみる':'Search through background traffic','ここまでのフィルターを、284パケットのLAN調査で使ってみましょう。':'Use these filters in a LAN investigation with 284 packets.',
'背景通信のあるキャプチャへ →':'Open the busy LAN capture →','Wiresharkで確かめる（任意）':'Verify in Wireshark (optional)','同じPCAPと表示フィルターを使って、残るNo.を比べましょう。':'Use the same PCAP and display filter to compare the remaining frame numbers.',
'確認の手順を開く':'Open verification steps','← 学習マップ':'← Learning map','← 前の問題':'← Previous lesson','次の問題 →':'Next lesson →','回答':'Answer','選択済み':'Selected','選ぶ':'Select',
'条件に合うパケットはありません。フィルターを変更するか解除してください。':'No packets match. Change or clear the filter.','表示対象のパケットがありません。':'No packets to display.','Options · TCPの追加情報':'Options · Additional TCP information',
'選択項目は解析で生成・再構成された情報のため、このフレーム上の対応位置はありません。':'This field was generated or reassembled by analysis and has no corresponding byte range in this frame.',
'詳細の項目を選ぶと、対応するバイトを強調します。':'Select a detail field to highlight its corresponding bytes.','先頭256バイトだけ表示':'Show first 256 bytes',
'パケットから読み取った値を入力':'Enter the value you read from the packet','未選択':'Nothing selected',
'一覧の「選ぶ」で回答に追加します。追加した順番が回答になります。間違えた番号は外して選び直せます。':'Use Select in the packet list. Selection order is your answer; remove and reselect packets to change it.',
'一覧の「選ぶ」で回答に追加します。順番は問いません。':'Use Select in the packet list. Order does not matter.',
'上の表示フィルターで条件を適用してから答え合わせします。同じ表示範囲になる書き方も正解です。':'Apply a display filter above, then check your answer. Equivalent expressions selecting the same packets are accepted.',
'設問を選ぶ':'Choose a question','根拠 （指定の根拠をすべて集める）':'Evidence (collect all required fields)','根拠 （回答を裏づける項目）':'Evidence (fields supporting your answer)',
'詳細欄で項目を選び、「根拠に追加」。':'Select a field in the details, then click Add evidence.','答え合わせ':'Check answer','次の設問 →':'Next question →','この設問は正解です':'Correct answer','もう一度、確かめよう':'Check once more',
'① 回答':'① Answer','② 根拠を追加':'② Add evidence','必須':'Required','入力済み':'Entered','未入力':'Not entered','未追加':'Not added',
'根拠を選ぶ':'Choose evidence','根拠を追加・変更':'Add or change evidence','回答と根拠を答え合わせ':'Check answer and evidence','答えの根拠を選ぶ':'Choose evidence for your answer',
'回答の根拠になる詳細行を選び、「根拠に追加」を押してください。':'Select a detail row that supports your answer, then click Add evidence.',
'行を選択中です。この行を根拠にするには、追加ボタンを押してください。':'A row is selected. Click its add button to use it as evidence.',
'この行は今の設問に追加済みです。':'This row has been added to the current question.',
'回答と、その答えを読み取った根拠の両方が必要です。':'Both your answer and the evidence you read it from are required.',
'Packet Detailsで該当する詳細行を選び、「根拠に追加」を押してください。':'Select the relevant row in Packet Details, then click Add evidence.',
'回答を裏づける行を1件以上追加してください。':'Add at least one row that supports your answer.',
'根拠がまだ追加されていません':'Evidence has not been added yet',
'追加済みは正解を示すものではありません。答え合わせで確認できます。':'Added does not mean correct. Check your answer to verify the evidence.',
'解説を閉じる／開く':'Hide / show explanation','答えと読み方を見る':'View answer and explanation','答えと読み方':'Answer and explanation',
'解説を見ただけではクリアになりません。自分で値と根拠を選んで確かめましょう。':'Viewing the explanation does not complete the lesson. Select the answer and evidence yourself to verify it.',
'次の問題へ →':'Go to next lesson →','学習マップで進捗を確認 →':'View progress on the learning map →','⚑ フラグ獲得！ +100ポイント':'⚑ Flag captured! +100 points',
'表示フィルターのエラーを解消してから答え合わせしてください。':'Fix the display filter error before checking your answer.','閉じる':'Close','閉じる ×':'Close ×',
'進捗ファイルを保存しました。':'Progress file saved.','同じ教材をWiresharkで開けるPCAPを保存しました。':'Saved the same capture as a PCAP you can open in Wireshark.',
'自動保存を読み込めませんでした。保存ファイルがある場合は「読込」から復元できます。':'Autosave could not be loaded. Use Load to restore an exported progress file.',
'自動保存が使えません。「保存」から進捗JSONを残してください。':'Autosave is unavailable. Use Save to export your progress as JSON.',
'パケットを読む、4つの操作':'Four steps for reading packets','1. 一覧からパケットを選ぶ':'1. Select a packet from the list',
'No.のボタンを押すと詳細が切り替わります。Sourceは送信元、Destinationは宛先です。時刻表示は、開始からの秒数・絶対時刻（UTC）・前フレームとの差に切り替えられます。差分はフィルター適用前の直前フレームから計算します。':'Click a No. button to open its details. Source is the sender; Destination is the recipient. Switch time between seconds since start, absolute UTC, and previous-frame delta. Deltas use the immediately preceding captured frame before filtering.',
'2. 詳細で項目を選ぶ':'2. Select a detail field',
'2. 詳細行を選んで根拠に追加する':'2. Select a detail row and add it as evidence',
'「根拠を選ぶ」でPacket Detailsへ移動できます。プロトコルを開き、答えを読み取った詳細行をクリックして、行の近くの追加ボタンを押します。行を選んだだけでは根拠に追加されません。「この項目で絞る」でフィルターを作り、「すべての項目を表示」で基本表示にない項目も読めます。':'Choose evidence takes you to Packet Details. Expand a protocol, click the row supporting your answer, then use the add button beside that row. Selecting a row alone does not add evidence. Filter by this field drafts a filter; Show all fields reveals fields hidden in the basic view.',
'プロトコル名を開き、必要な項目をクリックします。「根拠に追加」で今の設問に結びつけます。画面下のステータス欄でフィールド名を確認し、「この項目で絞る」で条件を入力欄に作れます。基本表示にない項目は「すべての項目を表示」で読めます。':'Expand a protocol and select a field. Add evidence attaches it to the current question. The status area shows its field name. Filter by this field drafts a filter. Show all fields reveals fields hidden in the basic view.',
'3. 回答と根拠をそろえる':'3. Provide an answer and evidence',
'根拠が必要な設問では、「① 回答」と「② 根拠を追加」の両方をそろえて答え合わせします。追加した根拠のNo.・項目名・値を確認してください。複数設問の問題はすべて正解すると1フラグです。番号を選ぶ問題では一覧の「選ぶ」を使います。':'For questions requiring evidence, complete both ① Answer and ② Add evidence before checking. Review the packet number, field name, and value of each added row. Complete every question in a lesson to earn one flag. For packet-selection questions, use Select in the list.',
'回答を入力・選択して答え合わせします。複数の設問がある問題は、すべて正解すると1フラグです。番号を選ぶ問題では一覧の「選ぶ」を使います。':'Enter or select an answer and check it. Complete every question in a lesson to earn one flag. For packet-selection questions, use Select in the list.',
'4. フィルターや会話の追跡を使う':'4. Use filters and stream following',
'表示フィルターは表示を絞るだけで、元のデータを消しません。「会話を追う」は同じTCP接続の内容をまとめます。暗号化された通信を復号する機能ではありません。':'Display filters narrow the view without deleting data. Follow stream assembles one TCP connection; it does not decrypt encrypted traffic.',
'学習と保存':'Learning and progress','教材の範囲':'Scope of the material',
'すべて架空の教材です。実ネットワークへの送信・キャプチャ・外部通信は行いません。実際のPCAPを教材として同梱し、Wireshark由来の解析結果を表示しています。表示フィルターは学習用の対応範囲に限られます。任意PCAPの読込やライブキャプチャには対応していません。':'All scenarios are fictional. The app sends no network traffic and performs no live capture or external communication. Embedded PCAPs supply Wireshark-decoded fields. Display filters support a teaching subset; arbitrary PCAP import and live capture are unavailable.',
'IPv6、QUIC／HTTP/3等の補足は用語帳も参照できます。TLSの一部には構造学習用の合成データを含み、実際の暗号セッションの復号教材ではありません。':'The glossary adds context for IPv6 and QUIC / HTTP/3. Some TLS data is synthetic for learning structure, not for decrypting a real session.',
'DNSを含む通信':'Packets containing DNS','UDP。DNS・DHCP・NTPも含む':'UDP, including DNS, DHCP, and NTP','TCP。HTTPやTLSも含む':'TCP, including HTTP and TLS','TCPの同じ接続だけを表示':'One TCP connection',
'そのフレームのバイト列にGETを含む（大文字・小文字を区別）':'Captured frame bytes contain GET (case-sensitive)','ICMPまたはICMPv6':'ICMP or ICMPv6','送信元または宛先が指定IPv4':'Source or destination matches this IPv4 address','指定端末からのDNS':'DNS from this client','送信元または宛先UDPポートが53':'UDP source or destination port 53',
'SYNフラグが立っている':'SYN flag set','DNS応答':'DNS responses','HTTP応答コードが404':'HTTP response code 404','問い合わせ名にtestを含む':'Query name contains test',
'表示フィルター早見表':'Display filter reference','使う条件を選ぶと入力欄に入ります。値は今の教材に合わせて編集してから適用してください。':'Select an example to place it in the input. Adjust values to the current capture before applying.',
'この教材で使える構文':'Supported syntax',
'プロトコル名・フィールド名、==、!=、>、<、>=、<=、contains、&& / and、|| / or、! / not、かっこ。文字列は二重引用符で囲みます。比較の右辺は値を指定してください。正規表現、集合、CIDR、関数、フィールド同士の比較は対応していません。学習用の対応範囲はWireshark全体の一部です。':'Protocol and field names; ==, !=, >, <, >=, <=, contains, && / and, || / or, ! / not, and parentheses. Use double quotes for strings and a value on the right of a comparison. Regular expressions, sets, CIDR, functions, and field-to-field comparisons are unsupported. This is a subset of Wireshark syntax.',
'未対応のフィールドや構文はエラーとして表示します。エラー時は直前に適用できた表示が残ります。':'Unsupported fields or syntax produce an error while preserving the last successfully applied view.',
'条件を入力しました。「適用」で表示を絞れます。':'Filter drafted. Click Apply to narrow the view.',
'この型は値の比較に未対応のため、項目の存在条件を入力しました。「適用」で絞れます。':'Value comparison is unsupported for this type. A field-presence filter was drafted; click Apply.',
'同じPCAPをWiresharkで読む':'Read the same PCAP in Wireshark','「PCAP保存」で':'Use Save PCAP to save','を保存し、Wiresharkで開きます。':'and open it in Wireshark.','表示フィルターに':'Enter','を入力します。':'in the display filter.',
'この画面ではフィルター未適用です。両方に同じ表示フィルターを指定して比較できます。':'No filter is applied here. Apply the same display filter in both apps to compare.',
'同じ詳細項目を選び、Wiresharkのステータスバーでフィールド名も確かめます。':'Select the same detail field and verify its name in the Wireshark status bar.',
'時刻を突き合わせるときはWiresharkの表示形式をUTCに合わせます。Wiresharkはローカル時刻も表示でき、設定や版により表示文字列・名前解決が異なります。No.とフィールド値を比較してください。':'Set Wireshark time display to UTC when correlating timestamps. Local time, text formatting, and name resolution depend on settings and version. Compare frame numbers and field values.',
'分からない言葉は、その都度確認できます。':'Look up unfamiliar terms whenever you need them.',
'このキャプチャにはTCPストリームがありません。UDPやICMPのやり取りは一覧で要求と応答を対応づけて読みます。':'This capture has no TCP streams. Match UDP or ICMP requests and responses in the packet list.',
'TCPストリームを追う':'Follow TCP stream','ストリーム':'Stream','開始側 → 相手側':'Initiator → Peer','相手側 → 開始側':'Peer → Initiator','アプリケーションデータなし':'No application data','このストリームには、収録された TCP ペイロードがありません。':'No TCP payload was recorded for this stream.',
'この接続にはアプリケーションデータが収録されていません。':'No application data was recorded for this connection.',
'暗号化データは追跡しても平文にはなりません。パケットに含まれる文字列をコードとして実行することはありません。':'Following encrypted data does not make it plaintext. Packet strings are never executed as code.',
'保存ファイルは5MB以内にしてください。':'The progress file must be no larger than 5 MB.','保存した進捗を読み込む':'Load saved progress','続行すると、現在の進捗をJSONでバックアップしてから読み込みます。':'Continuing downloads a JSON backup of your current progress before loading the file.',
'バックアップして読み込む':'Back up and load','キャンセル':'Cancel','読み込めませんでした':'Could not load the file','現在の進捗は変更していません。':'Your current progress has not changed.','今の設問に根拠を追加しました。':'Evidence added to this question.','進捗を読み込みました。':'Progress loaded.',
'文字列の終わりに " を付けてください。':'Close the string with a double quote (").','フィルターは2000文字以内で入力してください。':'Keep the filter within 2,000 characters.','閉じかっこ ) が必要です。':'A closing parenthesis ) is required.','比較する値を入力してください。':'Enter a value to compare.',
'frame contains の検索語は二重引用符で囲んでください。':'Enclose the search text for frame contains in double quotes.','検索語の文字を確認してください。':'Check the characters in the search text.','検索語を入力してください。':'Enter search text.',
'この教材では、右辺にはIP・数値・引用符付きの文字列を指定してください。':'Use an IP address, number, or quoted string on the right side.','この項目は数値（またはtrue / false）で比較してください。':'Compare this field with a number or true / false.','大小の比較には数値を指定してください。':'Use a number for an ordering comparison.','条件の間には && または || を入れてください。':'Place && or || between conditions.',
'表示フィルターの入力を確認してください。':'Check the display filter input.','表示されているパケットの範囲を確認しましょう。':'Check which packets are visible.','選んだパケットと順番を確認しましょう。':'Check the selected packets and their order.','回答と、パケットに記録された値を見比べてみましょう。':'Compare your answer with the recorded packet values.',
'根拠のパケットと項目を確認しましょう。別の通信の値が混ざっていないかも見てください。':'Check the evidence packets and fields. Make sure they belong to the intended exchange.','回答を裏づける項目を詳細欄から選び、「根拠に追加」を押してください。':'Select a supporting field in the details and click Add evidence.','パケットに記録された内容と一致しています。':'Your answer matches the recorded packet data.',
'pcaproom-easyの保存ファイルではないか、対応していない版です。':'This is not a supported pcaproom-easy progress file.'
};
Object.assign(messages,{"ここまできたら、次のおすすめ": "Ready for another room?", "通信の根拠を使う練習の次は、SOCroomで判断・連絡・報告をまとめて練習できます。移動は任意です。このroomの練習や復習も、そのまま続けられます。": "After practicing packet evidence, try SOCroom for decisions, communication, and reporting. Moving is optional. You can continue practicing and reviewing in this room.", "SOCroomを開く ↗": "Open SOCroom ↗", "自分の引継ぎメモ（任意）": "Your handoff note (optional)", "事実・出典・未確認事項・次の確認先と資料を、短く書いてみましょう。": "Briefly record facts, sources, open questions, and the owner and records to check next.", "メモは進捗と一緒に保存します。文章の意味は自動採点しません。解説を開き、4つの観点で自己比較できます。": "Your note is saved with progress. Its meaning is not automatically graded. Open the explanation and compare these four aspects yourself.", "メモをテキスト保存": "Save note as text"});
Object.assign(messages,{'関連資料を読む ↓':'Read related records ↓','設問へ戻る ↑':'Back to the question ↑'});
Object.assign(messages,{'オフラインでは、入手済みのsocroom.htmlを同じフォルダに置いて開けます。':'Offline, place your downloaded socroom.html in the same folder to open it.','調査に使う操作を確かめる（任意）':'Review investigation skills (optional)','初めてなら学習マップの01から。操作に慣れている人は、下の課題で方向・絞り込み・接続・名前解決・応答・観測の限界を確かめ、背景通信の調査とログ照合へ進めます。全章を続けたり、分からない所だけ戻ったりして構いません。順番や全問完了は必須ではありません。':'If you are new, start with chapter 01. If you know the interface, use these lessons to review direction, filtering, connections, name resolution, responses, and visibility limits, then investigate background traffic and correlate logs. You may continue through every chapter or revisit only unfamiliar topics. Neither this order nor completing every lesson is required.'});
const patterns=[
[/^(.*?)（再構成したデータ）$/,(_,s)=>`${s} (reassembled data)`],
[/^ARP・UDP・ICMPからWeb通信まで、(\d+)の小さな練習。$/,(_,n)=>`${n} short exercises, from ARP, UDP, and ICMP to web traffic.`],
[/^\/ (\d+) フラグ$/,(_,n)=>`/ ${n} flags`],
[/^PCAProom-easy v(.+) · すべて架空の教材 · ブラウザ内で完結$/,(_,v)=>`PCAProom-easy v${v} · Fictional scenarios · Runs entirely in your browser`],
[/^パケット(\d+)を選択$/,(_,n)=>`Select packet ${n}`],[/^(\d+)番目$/,(_,n)=>`Position ${n}`],
[/^表示 (\d+) \/ 全 (\d+) パケット(.*)$/,(_,a,b,s)=>`Showing ${a} / ${b} packets${s.includes('適用中')?' · Filter applied':' · Original capture preserved'}`],
[/^⚑ (\d+) \/ (\d+) · (.*?) · Ethernet PCAP$/,(_,a,b,s)=>`⚑ ${a} / ${b} · ${translate(s)} · Ethernet PCAP`],
[/^ほか(\d+)項目を表示$/,(_,n)=>`Show ${n} more fields`],
[/^選択項目: オフセット (\d+) から (\d+) バイト$/,(_,a,b)=>`Selected field: ${b} bytes at offset ${a}`],
[/^全(\d+)バイトを表示$/,(_,n)=>`Show all ${n} bytes`],[/^No\. (\d+)を回答から外す$/,(_,n)=>`Remove No. ${n} from answer`],
[/^設問 (\d+)(.*)$/,(_,n,s)=>`Question ${n}${s}`],[/^根拠(\d+)を外す$/,(_,n)=>`Remove evidence ${n}`],
[/^この行を設問(\d+)の根拠に追加$/,(_,n)=>`Add this row as evidence for question ${n}`],
[/^設問(\d+)に追加済み$/,(_,n)=>`Added to question ${n}`],
[/^(\d+)件追加済み$/,(_,n)=>`${n} ${n==='1'?'row':'rows'} added`],
[/^必要な根拠：(\d+)件$/,(_,n)=>`Evidence required: ${n} ${n==='1'?'row':'rows'}`],
[/^ヒント (\d+)(.*)$/,(_,n,s)=>`Hint ${n}${s}`],[/^根拠：(.*)$/,(_,s)=>`Evidence: ${s.replaceAll('、',', ')}`],
[/^この問題のフラグを獲得済みです。100ポイント。(.*)$/,(_,s)=>`You have earned this lesson's flag. 100 points. ${s.includes('ヒント')?'Your hint and explanation usage is recorded.':'You read the evidence independently.'}`],
[/^(\d+)問・各100ポイント。時間制限や誤答・ヒントによる減点はありません。解説を見ただけではクリアになりません。進捗は可能ならこのブラウザに保存しますが、HTMLの移動やブラウザ変更に備え「保存」からJSONも残してください。「読込」では現在の進捗をバックアップしてから置き換えます。$/,(_,n)=>`${n} lessons, 100 points each. No time limit or penalties for mistakes or hints. Reading an explanation alone does not complete a lesson. Progress is saved in this browser when possible. Also export JSON with Save before moving the HTML or changing browsers. Load backs up current progress before replacing it.`],
[/^残るNo.を比較します。この画面は(\d+)件：$/,(_,n)=>`Compare the remaining frame numbers. This view has ${n}:`],
[/^No\. (.*?) · 送信方向ごとにシーケンス順で組み立てています。要求応答の時系列は一覧でも確認してください。$/,(_,n)=>`No. ${n.replaceAll('・',', ')} · Each direction is assembled in sequence order. Use the packet list to check request/response timing.`],
[/^現在の進捗（(\d+)問クリア）を、ファイルの進捗（(\d+)問クリア）に置き換えます。$/,(_,a,b)=>`Replace current progress (${a} completed lessons) with the file's progress (${b} completed lessons).`],
[/^「(.*?)」は、この教材の表示フィルターでは使えません。$/,(_,s)=>`“${s}” is not supported in this display filter.`],
[/^「(.*?)」は未対応か、この教材に存在しない項目です。フィルター早見表も確認できます。$/,(_,s)=>`“${s==='入力の末尾'?'end of input':s}” is unsupported or absent from this capture. See the filter reference.`]
];
function translate(value){if(locale==='ja')return String(value);const s=String(value),trim=s.trim();if(Object.hasOwn(messages,trim))return s.replace(trim,messages[trim]);for(const [re,fn]of patterns)if(re.test(trim))return s.replace(trim,trim.replace(re,fn));return s;}
const origins=new WeakMap();
function apply(scope=document){
 const walker=document.createTreeWalker(scope,NodeFilter.SHOW_TEXT);
 let node;while((node=walker.nextNode())){
  if(node.parentElement?.closest('script,style,textarea,noscript,[data-language-name],.field,.hex-grid,code,pre')||!node.textContent.trim())continue;
  const previous=origins.get(node),source=previous&&node.textContent===previous.shown?previous.source:node.textContent,shown=translate(source);
  if(shown!==node.textContent)node.textContent=shown;
  origins.set(node,{source,shown});
 }
 for(const element of scope.querySelectorAll('[aria-label],[placeholder],[title]'))for(const name of ['aria-label','placeholder','title'])if(element.hasAttribute(name)){
  const all=origins.get(element)||{},previous=all[name],value=element.getAttribute(name),source=previous&&value===previous.shown?previous.source:value,shown=translate(source);
  if(shown!==value)element.setAttribute(name,shown);all[name]={source,shown};origins.set(element,all);
 }
 document.documentElement.lang=locale;
 document.title=locale==='en'?'pcaproom-easy — Your first steps in packet reading':'pcaproom-easy — パケットを読む、最初の一歩';
 document.querySelector('meta[name="description"]').content=locale==='en'?`Open packets, read details, and choose evidence. ${root.PcapData.lessons.length} offline networking lessons.`:`パケットを開いて、読んで、根拠を選ぶ。${root.PcapData.lessons.length}問のオフラインネットワーク入門。`;
 const select=document.getElementById('language-select');if(select)select.value=locale;
}
function localize(data){if(locale==='ja')return data;const en=data.translations.en;return {...data,
 chapters:data.chapters.map(c=>({...c,...en.chapters[c.id]})),
 captures:data.captures.map(c=>({...c,...en.captures[c.id]})),
 lessons:data.lessons.map(l=>{const tr=en.lessons[l.id];return {...l,...tr,...(l.referenceCards?{referenceCards:l.referenceCards.map((c,i)=>({...c,title:tr.referenceCards[i].title,body:tr.referenceCards[i].body}))}:{}),tasks:l.tasks.map((t,i)=>({...t,prompt:tr.tasks[i].prompt,why:tr.tasks[i].why,...(t.options?{options:t.options.map(o=>({...o,label:tr.tasks[i].options[o.value]}))}:{})}))};}),
 glossary:en.glossary
};}
function setLocale(value){locale=value==='en'?'en':'ja';try{localStorage.setItem(STORE,locale);}catch{}return locale;}
function streamText(segment){if(locale==='ja')return segment.text;let text=segment.text||'';if(segment.binary)text=text.replace(/^\[バイナリデータ\]/,'[Binary data]');return text.replace(/\n\[未収録 (\d+) bytes\]\n/g,'\n[Not captured: $1 bytes]\n');}
root.PcapI18n={translate,apply,localize,setLocale,streamText,get locale(){return locale;},STORE};
})(globalThis);
