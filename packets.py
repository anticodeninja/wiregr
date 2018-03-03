#!/usr/bin/env python
# -*- coding: utf-8 -*-

import yaml
from collections import OrderedDict

def ethernet_header_pack(writer, info):
    writer.pack_bytes(info['destination'])
    writer.pack_bytes(info['source'])
    writer.pack_fmt('>H', info['type'])

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

def udp_header_pack(writer, info):
    writer.pack_fmt('>H', info['source_port'])
    writer.pack_fmt('>H', info['destination_port'])
    writer.pack_fmt('>H', info['length'])
    writer.pack_fmt('>H', info['checksum'])

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
