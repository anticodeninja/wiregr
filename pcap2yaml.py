#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import datetime
import yaml
import struct
import sys
from collections import OrderedDict

from common import *

class Parser:

    def __init__(self, input_file, output_file):
        self.__configure_endianess(MAGIC)

        if input_file != '-':
            self.__input_file = open(input_file, 'rb')
        else:
            self.__input_file = sys.stdin

        if output_file != '-':
            self.__output_file = open(output_file, 'w')
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

    def parse(self):
        while True:
            temp = self.__input_file.read(4)
            if len(temp) == 0:
                break

            start_offset = self.__input_file.tell()
            end_offset = start_offset + self.__unpack(self.fmt_uint32) - 8

            info = OrderedDict()
            info['block_type'] = HexInt(struct.unpack(self.fmt_uint32, temp)[0])
            if info['block_type'] == 0x0A0D0D0A:
                self.__parse_section_header(info, end_offset)
            elif info['block_type'] == 0x00000001:
                self.__parse_interface_description_block(info, end_offset)
            elif info['block_type'] == 0x00000005:
                self.__parse_interface_statistic_block(info, end_offset)
            elif info['block_type'] == 0x00000006:
                self.__parse_enhanced_packet_block(info, end_offset)
            else:
                self.__parse_unknown_payload(info, end_offset)
                print('Unknown block_type', hex(info['block_type']), file=sys.stderr)

            end_offset = self.__input_file.tell()
            self.__input_file.seek(start_offset, ABSOLUTE)
            block_total_length_pre = self.__unpack(self.fmt_uint32)
            self.__input_file.seek(end_offset, ABSOLUTE)
            block_total_length_post = self.__unpack(self.fmt_uint32)
            assert block_total_length_pre == block_total_length_post

            print(yaml.dump(info, Dumper=CustomDumper), file=self.__output_file)

    def __parse_section_header(self, info, end_offset):
        # re-calculate end_offset after detection endianess
        self.__configure_endianess(self.__unpack(self.fmt_uint32))
        self.__input_file.seek(-8, RELATIVE)
        end_offset = self.__input_file.tell() + self.__unpack(self.fmt_uint32) - 12

        info['magic'] = HexInt(self.__unpack(self.fmt_uint32))
        info['major_version'] = self.__unpack(self.fmt_uint16)
        info['minor_version'] = self.__unpack(self.fmt_uint16)
        info['section_length'] = HexInt(self.__unpack(self.fmt_uint64))
        info['options'] = self.__parse_options({
            2: ('shb_hardware', self.__unpack_utf8),
            3: ('shb_os', self.__unpack_utf8),
            4: ('shb_userappl', self.__unpack_utf8)
        })


    def __parse_interface_description_block(self, info, end_offset):
        info['link_type'] = self.__unpack(self.fmt_uint16)
        self.__unpack(self.fmt_uint16) # RESERVED
        info['snapshot_length'] = self.__unpack(self.fmt_uint32)
        info['options'] = self.__parse_options({
            2: ('if_name', self.__unpack_utf8),
            3: ('if_description', self.__unpack_utf8),
            9: ('if_tsresol', self.__unpack_tsresol),
            11: ('if_filter', self.__unpack_utf8),
            12: ('if_os', self.__unpack_utf8),
        })

        interface_param = InterfaceParam()
        interface_param.link_type = info['link_type']
        if 'if_tsresol' in info['options']:
            interface_param.tsresol = info['options']['if_tsresol']['base'] ** (-info['options']['if_tsresol']['power'])
        self.__interfaces.append(interface_param)


    def __parse_enhanced_packet_block(self, info, end_offset):
        info['interface_id'] = self.__unpack(self.fmt_uint32)
        interface_param = self.__interfaces[info['interface_id']]
        info['datetime'] = self.__unpack_timestamp(interface_param.tsresol)
        info['captured_length'] = self.__unpack(self.fmt_uint32)
        info['packet_length'] = self.__unpack(self.fmt_uint32)

        end_payload_offset = self.__input_file.tell() + info['captured_length']
        if interface_param.link_type == LINKTYPE_ETHERNET:
            self.__parse_aligned(
                lambda: self.__parse_ethernet_data(info, end_payload_offset),
                4)
        else:
            info['unknown_payload'] = self.__parse_aligned(
                lambda: self.__input_file.read(info['captured_length']),
                4)
            print('Unknown link_type', interface_param.link_type, file=sys.stderr)

        if self.__input_file.tell() < end_offset:
            info['options'] = self.__parse_options({
                2: ('ebp_flags', lambda x: HexInt(self.__unpack(self.fmt_uint32))),
                3: ('ebp_hash', lambda x: self.__input_file.read(x)),
                4: ('epb_dropcount', lambda x: HexInt(self.__unpack(self.fmt_uint64))),
            })


    def __parse_interface_statistic_block(self, info, end_offset):
        info['interface_id'] = self.__unpack(self.fmt_uint32)
        info['datetime'] = self.__unpack_timestamp(10 ** -6)

        info['options'] = self.__parse_options({
            2: ('isb_starttime', lambda x: self.__unpack_timestamp(10 ** -6)),
            3: ('isb_endtime', lambda x: self.__unpack_timestamp(10 ** -6)),
            4: ('isb_ifrecv', lambda x: self.__unpack(self.fmt_uint64)),
            5: ('isb_ifdrop', lambda x: self.__unpack(self.fmt_uint64)),
        })


    def __parse_ethernet_data(self, info, end_offset):
        ethernet_data = OrderedDict()
        info['ethernet_data'] = ethernet_data

        ethernet_data['destination'] = self.__input_file.read(6)
        ethernet_data['source'] = self.__input_file.read(6)
        ethernet_data['type'] = self.__unpack('>H')

        if ethernet_data['type'] == TYPE_IPV4:
            self.__parse_type_ipv4(info, end_offset)
        else:
            self.__parse_unknown_payload(info, end_offset)


    def __parse_type_ipv4(self, info, end_offset):
        ipv4_data = OrderedDict()
        info['ipv4_data'] = ipv4_data

        temp = self.__unpack('B')
        ipv4_data['version'] = temp >> 4
        ipv4_data['header_length'] = temp & 0x0F
        ipv4_data['dsf'] = HexInt(self.__unpack('>B'))
        ipv4_data['total_length'] = self.__unpack('>H')
        ipv4_data['identification'] = HexInt(self.__unpack('>H'))
        temp = self.__unpack('>H')
        ipv4_data['flags'] = HexInt(temp >> 13)
        ipv4_data['flagment_offset'] = temp & 0x1FFF
        ipv4_data['ttl'] = self.__unpack('>B')
        ipv4_data['protocol'] = self.__unpack('>B')
        ipv4_data['header_checksum'] = HexInt(self.__unpack('>H'))
        ipv4_data['source'] = [x for x in self.__input_file.read(4)]
        ipv4_data['destination'] = [x for x in self.__input_file.read(4)]

        if ipv4_data['protocol'] == PROTOCOL_TCP:
            self.__parse_protocol_tcp(info, end_offset)
        elif ipv4_data['protocol'] == PROTOCOL_UDP:
            self.__parse_protocol_udp(info, end_offset)
        else:
            self.__parse_unknown_payload(info, end_offset)


    def __parse_protocol_tcp(self, info, end_offset):
        tcp_data = OrderedDict()
        info['tcp_data'] = tcp_data

        tcp_data['source_port'] = self.__unpack('>H')
        tcp_data['destination_port'] = self.__unpack('>H')
        tcp_data['seq_num'] = self.__unpack('>L')
        tcp_data['ack_num'] = self.__unpack('>L')
        temp = self.__unpack('>H')
        tcp_data['header_length'] = temp >> 12
        tcp_data['flags'] = temp & 0x1FF
        tcp_data['window_size'] = self.__unpack('>H')
        tcp_data['checksum'] = HexInt(self.__unpack('>H'))
        tcp_data['urgent_pointer'] = self.__unpack('>H')

        if tcp_data['header_length'] > 5:
            tcp_options = OrderedList()
            tcp_data['options'] = tcp_options
            options_end = start_offset + 4 * tcp_data['header_length']
            while self.__input_file.tell() < options_end:
                option_code = self.__unpack('>B')
                if option_code == 0:
                    tcp_options.append('end')
                    break
                elif option_code == 1:
                    tcp_options.append('nop')
                    continue

                option_size = self.__unpack('>B')
                if option_code == 2:
                    tcp_options.append({ 'max_segment_size': self.__unpack('>H') })
                    assert option_size == 4
                elif option_code == 3:
                    tcp_options.append({ 'window_scale': self.__unpack('>B') })
                    assert option_size == 3
                elif option_code == 4:
                    tcp_options.append('sack_permitted')
                    assert option_size == 2
                elif option_code == 8:
                    tcp_options.append({ 'timestamps': [self.__unpack('>L'), self.__unpack('>L')] })
                    assert option_size == 10
                else:
                    self.__input_file.seek(-2, RELATIVE)
                    tcp_options.append(self.__input_file.read(option_size))

        self.__parse_unknown_payload(info, end_offset)


    def __parse_protocol_udp(self, info, end_offset):
        udp_data = OrderedDict()
        info['udp_data'] = udp_data
        start_offset = self.__input_file.tell()

        udp_data['source_port'] = self.__unpack('>H')
        udp_data['destination_port'] = self.__unpack('>H')
        udp_data['length'] = self.__unpack('>H')
        udp_data['checksum'] = HexInt(self.__unpack('>H'))

        self.__parse_unknown_payload(info, end_offset)


    def __parse_unknown_payload(self, info, end_offset):
        length = end_offset - self.__input_file.tell()
        if length > 0:
            info['unknown_payload'] = self.__input_file.read(length)


    def __parse_options(self, parsers):
        options = OrderedDict()

        while True:
            option_code = self.__unpack(self.fmt_uint16)
            option_length = self.__unpack(self.fmt_uint16)

            if option_code == OPT_END:
                break
            elif option_code == OPT_COMMENT:
                options['opt_comment'] = self.__parse_aligned(
                    lambda: self.__unpack_utf8(option_length), 4)
            elif option_code in parsers:
                parser = parsers[option_code]
                options[parser[0]] = self.__parse_aligned(
                    lambda: parser[1](option_length), 4)
            else:
                self.__input_file.seek(align_value(option_length, 4), RELATIVE)
                print('Unknown option_code', option_code, file=sys.stderr)

        return options


    def __parse_aligned(self, callback, align):
        start_offset = self.__input_file.tell()
        temp = callback()
        end_offset = start_offset + align_value(self.__input_file.tell() - start_offset, align)
        self.__input_file.seek(end_offset, ABSOLUTE)
        return temp


    def __unpack(self, fmt):
        block = self.__input_file.read(struct.calcsize(fmt))
        return struct.unpack(fmt, block)[0]


    def __unpack_utf8(self, length):
        return self.__input_file.read(length).decode('utf-8')


    def __unpack_tsresol(self, length):
        temp = self.__unpack(self.fmt_uint8)
        info = OrderedDict()
        info['base'] = 2 if temp & 0x80 else 10
        info['power'] = temp & 0x7F
        return info


    def __unpack_timestamp(self, tsresol):
        ticks = self.__unpack(self.fmt_uint32) << 32 | self.__unpack(self.fmt_uint32)
        return datetime.datetime(1970, 1, 1) + datetime.timedelta(0, ticks * tsresol)


    def __configure_endianess(self, magic):
        prefix = '>' if magic == MAGIC else '<'
        self.fmt_uint8 = prefix + 'B'
        self.fmt_uint16 = prefix + 'H'
        self.fmt_uint32 = prefix + 'L'
        self.fmt_uint64 = prefix + 'Q'


parser = argparse.ArgumentParser()
parser.add_argument('input_file', help='input file')
parser.add_argument('output_file', nargs='?', default='-', help='output file')
args = parser.parse_args()

with Parser(args.input_file, args.output_file) as parser:
    parser.parse()
