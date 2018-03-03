#!/usr/bin/env python
# -*- coding: utf-8 -*-

import yaml
from collections import OrderedDict

from common import *

LINKTYPE_ETHERNET = 1

TYPE_IPV4 = 0x0800

PROTOCOL_TCP = 6
PROTOCOL_UDP = 17


def ethernet_header_read(reader):
    info = OrderedDict()
    info['destination'] = reader.read_bytes(6)
    info['source'] = reader.read_bytes(6)
    info['type'] = reader.read_fmt('>H')
    return info


def ethernet_header_pack(writer, info):
    writer.pack_bytes(info['destination'])
    writer.pack_bytes(info['source'])
    writer.pack_fmt('>H', info['type'])


def ipv4_header_read(reader):
    info = OrderedDict()
    temp = reader.read_fmt('B')
    info['version'] = temp >> 4
    info['header_length'] = temp & 0x0F
    info['dsf'] = HexInt(reader.read_fmt('>B'))
    info['total_length'] = reader.read_fmt('>H')
    info['identification'] = HexInt(reader.read_fmt('>H'))
    temp = reader.read_fmt('>H')
    info['flags'] = HexInt(temp >> 13)
    info['flagment_offset'] = temp & 0x1FFF
    info['ttl'] = reader.read_fmt('>B')
    info['protocol'] = reader.read_fmt('>B')
    info['header_checksum'] = HexInt(reader.read_fmt('>H'))
    info['source'] = [x for x in reader.read_bytes(4)]
    info['destination'] = [x for x in reader.read_bytes(4)]
    return info


def ipv4_header_pack(writer, info):
    temp = info['version'] << 4
    temp = temp | info['header_length']
    writer.pack_fmt('B', temp)
    writer.pack_fmt('>B', info['dsf'])
    writer.pack_fmt('>H', info['total_length'])
    writer.pack_fmt('>H', info['identification'])
    temp = info['flags'] << 13
    temp = temp | info['flagment_offset']
    writer.pack_fmt('>H', temp)
    writer.pack_fmt('>B', info['ttl'])
    writer.pack_fmt('>B', info['protocol'])
    writer.pack_fmt('>H', info['header_checksum'])
    writer.pack_bytes(info['source'])
    writer.pack_bytes(info['destination'])



def udp_header_read(reader):
    info = OrderedDict()
    info['source_port'] = reader.read_fmt('>H')
    info['destination_port'] = reader.read_fmt('>H')
    info['length'] = reader.read_fmt('>H')
    info['checksum'] = HexInt(reader.read_fmt('>H'))
    return info


def udp_header_pack(writer, info):
    writer.pack_fmt('>H', info['source_port'])
    writer.pack_fmt('>H', info['destination_port'])
    writer.pack_fmt('>H', info['length'])
    writer.pack_fmt('>H', info['checksum'])



def tcp_header_read(reader):
    info = OrderedDict()
    info['source_port'] = reader.read_fmt('>H')
    info['destination_port'] = reader.read_fmt('>H')
    info['seq_num'] = reader.read_fmt('>L')
    info['ack_num'] = reader.read_fmt('>L')
    temp = reader.read_fmt('>H')
    info['header_length'] = temp >> 12
    info['flags'] = temp & 0x1FF
    info['window_size'] = reader.read_fmt('>H')
    info['checksum'] = HexInt(reader.read_fmt('>H'))
    info['urgent_pointer'] = reader.read_fmt('>H')

    if info['header_length'] > 5:
        info['options'] = UnflowList()
        options_end = reader.stream.tell() + 4 * (info['header_length'] - 5)
        while reader.stream.tell() < options_end:
            option_code = reader.read_fmt('>B')
            if option_code == 0:
                info['options'].append('end')
                break
            elif option_code == 1:
                info['options'].append('nop')
                continue

            option_size = reader.read_fmt('>B')
            if option_code == 2:
                info['options'].append({ 'max_segment_size': reader.read_fmt('>H') })
                assert option_size == 4
            elif option_code == 3:
                info['options'].append({ 'window_scale': reader.read_fmt('>B') })
                assert option_size == 3
            elif option_code == 4:
                info['options'].append('sack_permitted')
                assert option_size == 2
            elif option_code == 8:
                info['options'].append({ 'timestamps': [reader.read_fmt('>L'), reader.read_fmt('>L')] })
                assert option_size == 10
            else:
                reader.stream.seek(-2, RELATIVE)
                tcp_options.append(reader.read_bytes(option_size))

    return info


def tcp_header_pack(writer, info):
    writer.pack_fmt('>H', info['source_port'])
    writer.pack_fmt('>H', info['destination_port'])
    writer.pack_fmt('>L', info['seq_num'])
    writer.pack_fmt('>L', info['ack_num'])
    temp = info['header_length'] << 12
    temp = temp | info['flags']
    writer.pack_fmt('>H', temp)
    writer.pack_fmt('>H', info['window_size'])
    writer.pack_fmt('>H', info['checksum'])
    writer.pack_fmt('>H', info['urgent_pointer'])

    if 'options' not in info:
        return

    for option in info['options']:
        if option == 'end':
            writer.pack_fmt('>B', 0)
            break
        elif option == 'nop':
            writer.pack_fmt('>B', 1)
            continue
        elif option == 'sack_permitted':
            writer.pack_fmt('>B', 4)
            writer.pack_fmt('>B', 2)
            continue
        elif isinstance(option, list):
            writer.pack_bytes(option)
            continue

        option_key = next(iter(option))
        option_value = option[option_key]
        if option_key == 'max_segment_size':
            writer.pack_fmt('>B', 2)
            writer.pack_fmt('>B', 4)
            writer.pack_fmt('>H', option_value)
        elif option_key == 'window_scale':
            writer.pack_fmt('>B', 3)
            writer.pack_fmt('>B', 3)
            writer.pack_fmt('>B', option_value)
        elif option_key == 'timestamps':
            writer.pack_fmt('>B', 8)
            writer.pack_fmt('>B', 10)
            writer.pack_fmt('>L', option_value[0])
            writer.pack_fmt('>L', option_value[1])
