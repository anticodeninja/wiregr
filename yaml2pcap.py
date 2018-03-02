#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import datetime
import yaml
import struct
import sys
from collections import OrderedDict

from common import *

class Packer:

    def __init__(self, input_file, output_file, endianess):
        self.__configure_endianess(endianess)

        if input_file != '-':
            self.__input_file = open(input_file, 'r')
        else:
            self.__input_file = sys.stdin

        if output_file != '-':
            self.__output_file = open(output_file, 'wb')
        else:
            self.__output_file = sys.stdout

        self.__interfaces = []

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.__input_file != sys.stdin:
            self.__input_file.close()
        if self.__output_file != sys.stdout:
            self.__output_file.close()

    def pack(self):
        lines = []
        for line in self.__input_file:
            line = line.strip('\n\r')
            if len(line) > 0:
                lines.append(line)
                continue

            info = yaml.load('\n'.join(lines), Loader=CustomLoader)
            lines = []

            self.__pack(self.fmt_uint32, info['block_type'])
            start_offset = self.__output_file.tell()
            self.__pack(self.fmt_uint32, 0)

            payload_offset = self.__output_file.tell()
            if info['block_type'] == 0x0A0D0D0A:
                self.__pack_section_header(info)
            elif info['block_type'] == 0x00000001:
                self.__pack_interface_description_block(info)
            elif info['block_type'] == 0x00000005:
                self.__pack_interface_statistic_block(info)
            elif info['block_type'] == 0x00000006:
                self.__pack_enhanced_packet_block(info)
            else:
                self.__pack_unknown_payload(info)
            block_total_length = self.__output_file.tell() - payload_offset + 12

            end_offset = self.__output_file.tell()
            self.__output_file.seek(start_offset, ABSOLUTE)
            self.__pack(self.fmt_uint32, block_total_length)
            self.__output_file.seek(end_offset, ABSOLUTE)
            self.__pack(self.fmt_uint32, block_total_length)

    def __pack_section_header(self, info):
        self.__pack(self.fmt_uint32, info['magic'])
        self.__pack(self.fmt_uint16, info['major_version'])
        self.__pack(self.fmt_uint16, info['minor_version'])
        self.__pack(self.fmt_uint64, info['section_length'])
        self.__pack_options(info['options'], {
            'shb_hardware': (2, self.__pack_utf8),
            'shb_os': (3, self.__pack_utf8),
            'shb_userappl': (4, self.__pack_utf8)
        })


    def __pack_interface_description_block(self, info):
        interface_param = InterfaceParam()
        interface_param.link_type = info['link_type']
        if 'if_tsresol' in info['options']:
            interface_param.tsresol = info['options']['if_tsresol']['base'] ** (-info['options']['if_tsresol']['power'])
        self.__interfaces.append(interface_param)

        self.__pack(self.fmt_uint16, info['link_type'])
        self.__pack(self.fmt_uint16, 0) # RESERVED
        self.__pack(self.fmt_uint32, info['snapshot_length'])
        self.__pack_options(info['options'], {
            'if_name': (2, self.__pack_utf8),
            'if_description': (3, self.__pack_utf8),
            'if_tsresol': (9, self.__pack_tsresol),
            'if_filter': (11, self.__pack_utf8),
            'if_os': (12, self.__pack_utf8)
        })


    def __pack_enhanced_packet_block(self, info):
        interface_param = self.__interfaces[info['interface_id']]

        self.__pack(self.fmt_uint32, info['interface_id'])
        self.__pack_timestamp(interface_param.tsresol, info['datetime'])
        self.__pack(self.fmt_uint32, info['captured_length'])
        self.__pack(self.fmt_uint32, info['packet_length'])

        if 'ethernet_data' in info:
            self.__pack_aligned(lambda: self.__pack_ethernet_data(info), 4)
        else:
            self.__pack_unknown_payload(info)

        if 'options' in info:
            self.__pack_options(info['options'], {
                'ebp_flags': (2, lambda x: self.__pack(self.fmt_uint32, x)),
                'ebp_hash': (3, lambda x: self.__output_file.write(bytes(x))),
                'epb_dropcount': (4, lambda x: self.__pack(self.fmt_uint64, x)),
            })


    def __pack_interface_statistic_block(self, info):
        self.__pack(self.fmt_uint32, info['interface_id'])
        self.__pack_timestamp(10 ** -6, info['datetime'])

        self.__pack_options(info['options'], {
            'isb_starttime': (2, lambda x: self.__pack_timestamp(10 ** -6, x)),
            'isb_endtime': (3, lambda x: self.__pack_timestamp(10 ** -6, x)),
            'isb_ifrecv': (4, lambda x: self.__pack(self.fmt_uint64, x)),
            'isb_ifdrop': (5, lambda x: self.__pack(self.fmt_uint64, x)),
        })


    def __pack_ethernet_data(self, info):
        ethernet_data = info['ethernet_data']
        self.__output_file.write(bytes(ethernet_data['destination']))
        self.__output_file.write(bytes(ethernet_data['source']))
        self.__pack('>H', ethernet_data['type'])

        if 'ipv4_data' in info:
            self.__pack_type_ipv4(info)
        else:
            self.__pack_unknown_payload(info)


    def __pack_type_ipv4(self, info):
        ipv4_data = info['ipv4_data']
        temp = ipv4_data['version'] << 4
        temp = temp | ipv4_data['header_length']
        self.__pack('B', temp)
        self.__pack('>B', ipv4_data['dsf'])
        self.__pack('>H', ipv4_data['total_length'])
        self.__pack('>H', ipv4_data['identification'])
        temp = ipv4_data['flags'] << 13
        temp = temp | ipv4_data['flagment_offset']
        self.__pack('>H', temp)
        self.__pack('>B', ipv4_data['ttl'])
        self.__pack('>B', ipv4_data['protocol'])
        self.__pack('>H', ipv4_data['header_checksum'])
        self.__output_file.write(bytes(ipv4_data['source']))
        self.__output_file.write(bytes(ipv4_data['destination']))

        if 'tcp_data' in info:
            self.__pack_protocol_tcp(info)
        elif 'udp_data' in info:
            self.__pack_protocol_udp(info)
        else:
            self.__pack_unknown_payload(info)


    def __pack_protocol_tcp(self, info):
        tcp_data = info['tcp_data']
        self.__pack('>H', tcp_data['source_port'])
        self.__pack('>H', tcp_data['destination_port'])
        self.__pack('>L', tcp_data['seq_num'])
        self.__pack('>L', tcp_data['ack_num'])
        temp = tcp_data['header_length'] << 12
        temp = temp | tcp_data['flags']
        self.__pack('>H', temp)
        self.__pack('>H', tcp_data['window_size'])
        self.__pack('>H', tcp_data['checksum'])
        self.__pack('>H', tcp_data['urgent_pointer'])

        if 'options' in tcp_data:
            for option in tcp_data['options']:
                if option == 'end':
                    self.__pack('>B', 0)
                    break
                elif option == 'nop':
                    self.__pack('>B', 1)
                    continue
                elif option == 'sack_permitted':
                    self.__pack('>B', 4)
                    self.__pack('>B', 2)
                    continue
                elif isinstance(option, list):
                    self.__output_write(bytes(option))
                    continue

                option_key = next(iter(option))
                option_value = option[option_key]
                if option_key == 'max_segment_size':
                    self.__pack('>B', 2)
                    self.__pack('>B', 4)
                    self.__pack('>H', option_value)
                elif option_key == 'window_scale':
                    self.__pack('>B', 3)
                    self.__pack('>B', 3)
                    self.__pack('>B', option_value)
                elif option_key == 'timestamps':
                    self.__pack('>B', 8)
                    self.__pack('>B', 10)
                    self.__pack('>L', option_value[0])
                    self.__pack('>L', option_value[1])

        if 'unknown_payload' in info:
            self.__pack_unknown_payload(info)


    def __pack_protocol_udp(self, info):
        udp_data = info['udp_data']
        self.__pack('>H', udp_data['source_port'])
        self.__pack('>H', udp_data['destination_port'])
        self.__pack('>H', udp_data['length'])
        self.__pack('>H', udp_data['checksum'])

        if 'unknown_payload' in info:
            self.__pack_unknown_payload(info)


    def __pack_options(self, options, packers):
        for k, v in options.items():
            start_offset = self.__output_file.tell()
            self.__pack(self.fmt_uint32, 0)

            payload_offset = self.__output_file.tell()
            if k == 'opt_comment':
                code = 1
                self.__pack_utf8(v)
            elif k in packers:
                packer = packers[k]
                code = packer[0]
                packer[1](v)
            else:
                self.__output_file.seek(-4, RELATIVE)
                print('Unknown option', k, file=sys.stderr)
                continue
            size = self.__output_file.tell() - payload_offset

            self.__align(size, 4)

            end_offset = self.__output_file.tell()
            self.__output_file.seek(start_offset, ABSOLUTE)
            self.__pack(self.fmt_uint16, code)
            self.__pack(self.fmt_uint16, size)
            self.__output_file.seek(end_offset, ABSOLUTE)

        self.__pack(self.fmt_uint32, 0)


    def __pack_aligned(self, callback, align):
        start_offset = self.__output_file.tell()
        callback()
        self.__align(self.__output_file.tell() - start_offset, align)


    def __align(self, size, align):
        size = align_value(size, align) - size
        if size > 0:
            self.__output_file.write(bytes([0] * size))


    def __pack(self, fmt, value):
        self.__output_file.write(struct.pack(fmt, value))


    def __pack_utf8(self, value):
        self.__output_file.write(value.encode('utf-8'))


    def __pack_tsresol(self, value):
        temp = 0x80 if value['base'] == 2 else 0
        temp = temp | value['power']
        self.__pack(self.fmt_uint8, temp)


    def __pack_timestamp(self, tsresol, value):
        ticks = int((value - datetime.datetime(1970, 1, 1)).total_seconds() / tsresol)
        self.__pack(self.fmt_uint32, (ticks >> 32) & 0xFFFFFFFF)
        self.__pack(self.fmt_uint32, ticks & 0xFFFFFFFF)


    def __pack_unknown_payload(self, info):
        self.__pack_aligned(lambda: self.__output_file.write(bytes(info['unknown_payload'])), 4)


    def __configure_endianess(self, endianess):
        prefix = '>' if endianess == 'big' else '<'
        self.fmt_uint8 = prefix + 'B'
        self.fmt_uint16 = prefix + 'H'
        self.fmt_uint32 = prefix + 'L'
        self.fmt_uint64 = prefix + 'Q'


parser = argparse.ArgumentParser()
parser.add_argument('input_file', help='input file')
parser.add_argument('output_file', nargs='?', default='-', help='output file')
parser.add_argument('--endianess', default=sys.byteorder, choices=['big', 'little'], help='simulate endianess of machine')
args = parser.parse_args()

with Packer(args.input_file, args.output_file, args.endianess) as packer:
    packer.pack()
