#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import yaml
import struct
import sys
from collections import OrderedDict

ABSOLUTE = 0
RELATIVE = 1
FROM_END = 2

OPT_END = 0
OPT_COMMENT = 1

class HexInt(int): pass

class CustomDumper(yaml.Dumper):

    def __init__(self, *args, **kargs):
        kargs['default_flow_style'] = False
        super().__init__(*args, **kargs)
        self.yaml_representers = self.yaml_representers.copy()
        self.yaml_representers[OrderedDict] = lambda dumper, data: dumper.represent_dict(data.items())
        self.yaml_representers[HexInt] = lambda dumper, data: yaml.ScalarNode('tag:yaml.org,2002:int', hex(data))
        self.yaml_representers[bytes] = lambda dumper, data: dumper.represent_sequence(
            'tag:yaml.org,2002:seq', (HexInt(x) for x in data), flow_style=True)

class Parser:

    def __init__(self, filename):
        self.__configure_endianess(0x1A2B3C4D)
        self.__input_file = open(filename, 'rb')
        self.__input_file.seek(0, FROM_END)
        self.__length = self.__input_file.tell()
        self.__input_file.seek(0, ABSOLUTE)
        self.__tsresol = []

    def parse(self):
        while self.__input_file.tell() < self.__length:
            info = OrderedDict()
            info['block_type'] = HexInt(self.__unpack(self.fmt_uint32))
            if info['block_type'] == 0x0A0D0D0A:
                self.__parse_section_header(info)
            elif info['block_type'] == 0x00000001:
                self.__parse_interface_description_block(info)
            elif info['block_type'] == 0x00000005:
                self.__parse_interface_statistic_block(info)
            elif info['block_type'] == 0x00000006:
                self.__parse_enhanced_packet_block(info)
            else:
                self.__parse_unknown_block(info)
                print('Unknown block_type', hex(info['block_type']), file=sys.stderr)

            print(yaml.dump(info, Dumper=CustomDumper))

    def __parse_section_header(self, info):
        self.__input_file.seek(4, RELATIVE)
        self.__configure_endianess(self.__unpack(self.fmt_uint32))
        self.__input_file.seek(-8, RELATIVE)

        block_total_length_pre = self.__unpack(self.fmt_uint32)
        end_payload_offset = self.__input_file.tell() + block_total_length_pre - 12

        info['magic'] = HexInt(self.__unpack(self.fmt_uint32))
        info['major_version'] = self.__unpack(self.fmt_uint16)
        info['minor_version'] = self.__unpack(self.fmt_uint16)
        info['section_length'] = HexInt(self.__unpack(self.fmt_uint64))
        info['options'] = self.__parse_options({
            2: ('shb_hardware', self.__unpack_utf8),
            3: ('shb_os', self.__unpack_utf8),
            4: ('shb_userappl', self.__unpack_utf8)
        })

        block_total_length_post = self.__unpack(self.fmt_uint32)
        assert block_total_length_pre == block_total_length_post


    def __parse_interface_description_block(self, info):
        block_total_length_pre = self.__unpack(self.fmt_uint32)

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

        if 'if_tsresol' in info['options']:
            self.__tsresol.append(
                info['options']['if_tsresol']['base'] ** (-info['options']['if_tsresol']['power']))
        else:
            self.__tsresol.append(10 ** -6)

        block_total_length_post = self.__unpack(self.fmt_uint32)
        assert block_total_length_pre == block_total_length_post


    def __parse_enhanced_packet_block(self, info):
        block_total_length_pre = self.__unpack(self.fmt_uint32)
        block_payload_end = self.__input_file.tell() + block_total_length_pre - 12

        info['interface_id'] = self.__unpack(self.fmt_uint32)
        info['datetime'] = self.__unpack_timestamp(self.__tsresol[info['interface_id']])
        info['captured_length'] = self.__unpack(self.fmt_uint32)
        info['packet_length'] = self.__unpack(self.fmt_uint32)
        info['packed_data'] = self.__parse_aligned(
            lambda x: self.__input_file.read(x), info['captured_length'], 4)

        if block_payload_end < self.__input_file.tell():
            info['options'] = self.__parse_options({
                2: ('ebp_flags', lambda x: HexInt(self.__unpack(self.fmt_uint32))),
                3: ('ebp_hash', lambda x: self.__input_file.read(x)),
                4: ('epb_dropcount', lambda x: HexInt(self.__unpack(self.fmt_uint64))),
            })

        block_total_length_post = self.__unpack(self.fmt_uint32)
        assert block_total_length_pre == block_total_length_post


    def __parse_interface_statistic_block(self, info):
        block_total_length_pre = self.__unpack(self.fmt_uint32)
        block_payload_end = self.__input_file.tell() + block_total_length_pre - 12

        info['interface_id'] = self.__unpack(self.fmt_uint32)
        info['datetime'] = self.__unpack_timestamp(10 ** -6)

        info['options'] = self.__parse_options({
            2: ('isb_starttime', lambda x: self.__unpack_timestamp(10 ** -6)),
            3: ('isb_endtime', lambda x: self.__unpack_timestamp(10 ** -6)),
            4: ('isb_ifrecv', lambda x: self.__unpack(self.fmt_uint64)),
            5: ('isb_ifdrop', lambda x: self.__unpack(self.fmt_uint64)),
        })

        block_total_length_post = self.__unpack(self.fmt_uint32)
        assert block_total_length_pre == block_total_length_post


    def __parse_unknown_block(self, info):
        block_total_length_pre = self.__unpack(self.fmt_uint32)

        block_size = block_total_length_pre - 12
        info['unknown_payload'] = self.__input_file.read(block_size)

        block_total_length_post = self.__unpack(self.fmt_uint32)
        assert block_total_length_pre == block_total_length_post


    def __parse_options(self, parsers):
        options = OrderedDict()

        while True:
            option_code = self.__unpack(self.fmt_uint16)
            option_length = self.__unpack(self.fmt_uint16)
            option_format = None
            option_taken = 0

            if option_code == OPT_END:
                break
            elif option_code == OPT_COMMENT:
                options['opt_comment'] = self.__parse_aligned(
                    lambda x: self.__unpack_utf8(x), option_length, 4)
            elif option_code in parsers:
                parser = parsers[option_code]
                options[parser[0]] = self.__parse_aligned(
                    lambda x: parser[1](x), option_length, 4)
            else:
                self.__input_file.seek(self.__align(option_length, 4), RELATIVE)
                print('Unknown option_code', option_code, file=sys.stderr)

        return options

    def __parse_aligned(self, callback, length, align):
        option_end = self.__input_file.tell() + self.__align(length, align)
        temp = callback(length)
        self.__input_file.seek(option_end, ABSOLUTE)
        return temp

    def __align(self, size, align):
        if size % align == 0:
            return size
        return size // align * align + align

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
        prefix = '>' if magic == 0x1A2B3C4D else '<'
        self.fmt_uint8 = prefix + 'B'
        self.fmt_uint16 = prefix + 'H'
        self.fmt_uint32 = prefix + 'L'
        self.fmt_uint64 = prefix + 'Q'



Parser('http.pcapng').parse()
