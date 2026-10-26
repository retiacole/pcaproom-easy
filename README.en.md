<p align="center">
  <img src="docs/images/pcaproom-banner.png" width="960" alt="Pixel art of the pcaproom-easy character praying in a cathedral with stained-glass windows">
</p>

# pcaproom-easy v0.3.0

English | [日本語](README.md)

**[Play Now](https://retiacole.github.io/pcaproom-easy/)** · [Offline HTML](https://github.com/retiacole/pcaproom-easy/blob/main/pcaproom-easy.html)

<img src="docs/images/pcaproom-character.png" align="right" width="120" alt="The pcaproom-easy character in white and blue, holding a staff and a book">

**Read packets. Follow the evidence.**

An offline introduction to reading network packets: **51 lessons, 95 questions**, and 12 protocol topics in a Wireshark-style interface. Open packets, read their details, and support answers with selected evidence.

<br clear="right">

## Start learning

1. Open **[Play Now](https://retiacole.github.io/pcaproom-easy/)** to start in your browser. For offline use, open [Offline HTML](https://github.com/retiacole/pcaproom-easy/blob/main/pcaproom-easy.html), choose **Download raw file**, and open the saved HTML in your browser. Downloading and extracting the repository ZIP also works.
2. Choose **English** from the **Language** menu in the HTML header. Japanese remains available in the same menu.
3. Choose **Open your first packet**, or select any lesson on the learning map.
4. Click a packet number, expand its protocol details, select a field, and choose **Add evidence**.
5. Enter or select your answer and choose **Check answer**. Complete every question in a lesson to earn its flag.

No installation, server setup, or account is needed. Open the online version directly in your browser, or use the saved HTML without an Internet connection. Use a browser with JavaScript and HTML dialog support. The single HTML file embeds all teaching data, styles, and scripts.

## Language and progress

English covers all lesson introductions, missions, questions, options, hints, explanations, capture descriptions, the glossary, controls, help, and feedback. The language choice is remembered when browser storage is available.

Switch languages during a lesson without losing answers, evidence, the selected question, packet or field, a draft filter, time display, hint usage, or earned flags. Packet bytes, decoded technical fields, filter syntax, answer values, and progress records are shared across languages. A saved JSON progress file works in either language, including existing v0.1 and v0.2 progress.

Progress uses `pcaproom-easy.progress.v1`; language uses the separate key `pcaproom-easy.language.v1`. Other room applications' storage is not accessed. Browser handling of local HTML storage varies, and moving the file or changing browsers can create a separate storage area. Use **Save** to keep a portable JSON copy and **Load** to restore it. Import shows a confirmation and downloads a backup of current progress before replacement. Invalid files and cancellation leave current progress unchanged.

## Curriculum

| Section | Topics | Lessons |
| --- | --- | ---: |
| Operations | Packet list, details, evidence, display filters | 6 |
| Foundations | Ethernet, ARP, IPv4/IPv6, ICMP, ICMPv6/NDP, UDP | 18 |
| Reading exchanges | TCP, DNS, DHCPv4, NTP, HTTP, TLS | 18 |
| Final investigations | Joining a network, connection failure, web results and visibility | 3 |
| Real-capture skills | TCP options/raw numbers, DNS/DHCP extras, timestamps/padding | 3 |
| Busy-LAN investigation | Filter 284 packets to investigate DNS, TCP, and HTTP | 3 |

There are 17 chapters with three lessons each. Guided exercises lead into practice and independent work. Every lesson includes three hints and an answer explanation. Each completed lesson earns one flag and 100 points: **51 flags and 5,100 points** total. There is no time limit and no penalty for mistakes or hints. Reading an explanation alone does not award a flag. Earned flags remain when you edit answers during review.

## Features

- Packet list, expandable protocol details, basic/all-fields display, and byte-range highlighting.
- TCP options including MSS, SACK Permitted, Window Scale, and Timestamps.
- Relative time, absolute UTC, and previous-frame delta. Deltas follow original capture order before filtering.
- Field-name status and **Filter by this field** to prepare a comparison or field-presence expression.
- Display filtering with syntax reference; an invalid filter preserves the last successfully applied view.
- Directional TCP stream reassembly in sequence order with retransmissions deduplicated.
- Text answers, choices, packet sets, ordered selections, and filter-result questions, with evidence checks.
- Exact PCAP downloads for optional comparisons in real Wireshark.
- Glossary, hints, explanations, and progress export/import.

### Filter support

Supported: protocol/field presence; `==`, `!=`, `>`, `<`, `>=`, `<=`, `contains`; `&&` / `and`, `||` / `or`, `!` / `not`; parentheses. Examples include `dns`, `udp`, `ip.addr == 10.0.0.10`, `tcp.flags.syn == 1`, `tcp.stream == 1`, and `frame contains "GET"`.

`frame contains` searches captured frame bytes case-sensitively using UTF-8 text in double quotes. It does not search a reassembled message or plaintext hidden by encryption. Regular expressions, sets, CIDR, functions, and field-to-field comparisons are unsupported. This is a learning subset of Wireshark filters. Filter questions accept any valid expression producing the required packet set.

## Capture data and observation limits

The app includes **45 synthetic PCAPs and 537 frames** with fictional addresses, names, and contents. It performs no live capture or external communication and does not import arbitrary PCAP files. Builds generate actual PCAP bytes and embed fields, displays, and byte positions decoded by tshark. Playing the HTML does not require tshark.

The shared busy-LAN capture mixes 270 background ARP, mDNS, SSDP, ICMPv6/NDP, other-client DHCP, and NTP packets with the target DNS and two HTTP connections. Exercises distinguish DNS success, ping reachability, TCP setup, and HTTP outcomes rather than inferring total service health from one stage.

TLS examples teach structure and visibility limits. Opaque Application Data is synthetic teaching data, not decryptable ciphertext from a real session. A short TLS 1.2 ClientHello illustrates SNI; modern ClientHellos can be much longer, and SNI is not always visible. DHCPv6 and QUIC/HTTP/3 are introduced in the glossary without dedicated packet exercises.

Typical TCP SYNs carry options and deterministic raw 32-bit sequence numbers. When both SYNs negotiate Timestamps, subsequent non-RST segments include them. Ordinary DNS carries EDNS0 OPT; mDNS does not. DHCP includes identification, maximum message size, and renewal/rebinding settings. MACs are fictional locally administered addresses.

Normal Ethernet frames are padded to 60 bytes excluding FCS. A comparison lesson intentionally omits TCP options and combines 54-byte sender-side records before padding with a 60-byte LAN record. Embedded decoding uses UTC and C locale; Wireshark may display local time or different names/formatting. Compare frame numbers and field values.

## Build and verify

Development requires Node.js 22+, Python 3 (standard library), and tshark. The tested tshark version is 4.6.7.

```sh
npm run build
npm install
npm test
```

Defaults are `/usr/bin/python3` and `/usr/local/bin/tshark`. Set `PCAPROOM_PYTHON` and `PCAPROOM_TSHARK` to override their paths. Decoding uses a temporary Wireshark profile with `TZ=UTC` and `LC_ALL=C`, without user settings or TLS keys.

- `content/`: canonical lesson, answer, and packet specifications. `en.js` contains presentation-only English overlays; `validate-translations.js` checks coverage and prohibits technical-data overrides.
- `packet-tools.js`, `decode-pcap.py`: PCAP generation, reassembly, and tshark decoding.
- `src/engine.js`: filtering, grading, and progress validation.
- `src/app.js`, `src/i18n.js`, `src/style.css`, `src/shell.html`: interface and language handling.
- `src/data.js`, `captures/`, `pcaproom-easy.html`: generated deliverables.
- `tests/`: packet, engine, and DOM integration checks.

The 47 automated tests cover packet checksums, all 51 lessons and 95 questions through the UI in both Japanese and English, evidence requirements, all flags, legacy progress, reload/import, time modes, PCAP bytes, stream reassembly, language persistence, translation coverage, and state preservation during switching. Tests also compare new filters with tshark and verify deterministic decoding across timezone/locale settings. DOM tests do not validate actual browser rendering or download UI.

jsdom is required only for tests. To reuse an existing installation, set `PCAPROOM_JSDOM_MODULE` to its module path. To test the shipped HTML directly, set `PCAPROOM_HTML` to that file's path.

## License

MIT. Answers are included in the source. This is a self-study tool, not a server-authenticated exam or anti-cheating system.

<p align="center">
  <img src="assets/help-ending.png" width="100%" alt="The room series companions journey through the sky on a great bird">
</p>
