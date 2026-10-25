#!/usr/bin/env python3
"""Decode authored PCAP bytes with an isolated Wireshark profile, using only stdlib."""
import csv
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


def main():
    file, tshark = sys.argv[1:3]
    with tempfile.TemporaryDirectory(prefix='pcaproom-wireshark-') as profile:
        env = dict(os.environ)
        # Never read or modify the user's Wireshark preferences, key files, or plugins.
        env['WIRESHARK_CONFIG_DIR'] = profile
        env['WIRESHARK_PLUGIN_DIR'] = os.path.join(profile, 'plugins')
        env['SSLKEYLOGFILE'] = ''
        env.pop('WIRESHARK_DATA_DIR', None)
        def run(args):
            return subprocess.run([tshark] + args, env=env, check=True, capture_output=True, text=True).stdout
        field_types = {}
        for line in run(['-G', 'fields']).splitlines():
            columns = line.split('\t')
            if len(columns) >= 4 and columns[0] == 'F':
                field_types[columns[2]] = columns[3]
        base = ['-n', '-2', '-r', file, '-o', 'tcp.relative_sequence_numbers:TRUE', '-o', 'tcp.check_checksum:TRUE', '-o', 'udp.check_checksum:TRUE', '-o', 'ip.check_checksum:TRUE']
        pdml = ET.fromstring(run(base + ['-T', 'pdml']))
        cols = list(csv.reader(io.StringIO(run(base + ['-T', 'fields', '-E', 'separator=\t', '-E', 'quote=d', '-e', '_ws.col.Source', '-e', '_ws.col.Destination', '-e', '_ws.col.Protocol', '-e', '_ws.col.Info'])), delimiter='\t', quotechar='"'))

        def scalar(field):
            key = field.get('name', '')
            typ = field_types.get(key, '')
            value = field.get('show', field.get('value', ''))
            if typ.startswith(('FT_UINT', 'FT_INT')) or typ in ('FT_BOOLEAN', 'FT_FRAMENUM'):
                try:
                    return int(value, 16 if value.startswith('0x') else 10)
                except ValueError:
                    pass
            if typ in ('FT_FLOAT', 'FT_DOUBLE', 'FT_RELATIVE_TIME'):
                try:
                    return float(value)
                except ValueError:
                    pass
            if typ == 'FT_BYTES':
                return field.get('value', value).replace(':', '')
            return value

        packets = []
        for index, packet in enumerate(pdml.findall('packet')):
            fields, layers = {}, []
            def append(key, value):
                fields.setdefault(key, []).append(value)
            for proto in packet.findall('proto'):
                name = proto.get('name', '')
                if name == 'geninfo':
                    continue
                append(name, True)
                layer = {'name':name, 'label':proto.get('showname', name), 'fields':[]}
                # A reassembled upper-layer PDU has its own tvbuff starting at zero.
                # Those offsets cannot highlight bytes in this physical Ethernet frame.
                reassembled = name not in ('frame', 'eth', 'geninfo') and int(proto.get('pos', '0')) < 14
                if reassembled:
                    layer['label'] += '（再構成したデータ）'
                for node in proto.iter('field'):
                    key = node.get('name', '')
                    if not key:
                        continue
                    if node.get('show') is None and node.get('value') is None:
                        continue
                    value = scalar(node)
                    append(key, value)
                    if node.get('hide') == 'yes':
                        continue
                    display = node.get('showname', node.get('show', key))
                    entry = {'key':key, 'label':display.split(': ', 1)[0], 'value':value, 'display':display}
                    if not reassembled and not key.startswith('tcp.reassembled.') and node.get('pos') is not None and node.get('size') is not None:
                        entry['offset'] = int(node.get('pos'))
                        entry['length'] = int(node.get('size'))
                    layer['fields'].append(entry)
                layers.append(layer)
            # Preserve explicit generated aliases even on versions that omit them from PDML.
            for alias, sources in {'ip.addr':['ip.src','ip.dst'], 'ipv6.addr':['ipv6.src','ipv6.dst'], 'tcp.port':['tcp.srcport','tcp.dstport'], 'udp.port':['udp.srcport','udp.dstport'], 'eth.addr':['eth.src','eth.dst']}.items():
                if alias not in fields:
                    values = [v for k in sources for v in fields.get(k, [])]
                    if values:
                        fields[alias] = values
            row = cols[index] + [''] * 4
            packets.append({'number':int(fields['frame.number'][0]), 'time':float(fields['frame.time_relative'][0]), 'src':row[0], 'dst':row[1], 'protocol':row[2], 'length':int(fields['frame.len'][0]), 'info':row[3], 'layers':layers, 'fields':fields})
        print(json.dumps({'packets':packets}, ensure_ascii=False, separators=(',',':')))


if __name__ == '__main__':
    main()
