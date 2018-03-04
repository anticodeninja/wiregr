#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import yaml
import struct
import sys
from collections import OrderedDict

from wiregr.common import *
from wiregr.packets import *

class PcapReader(BaseWorker):

    def __init__(self, input_file, output_file):
        super().__init__(input_file, True, output_file, False)
        self._configure_endianess(MAGIC)
        self.__interfaces = []

    def process(self):
        while True:
            temp = self._input_file.read(4)
            if len(temp) == 0:
                break

            start_offset = self._input_file.tell()
            block_length_pre = self.__unpack(self.fmt_uint32)
            end_offset = start_offset + block_length_pre - 8

            info = OrderedDict()
            info['block_type'] = HexInt(struct.unpack(self.fmt_uint32, temp)[0])
            if info['block_type'] == 0x0A0D0D0A:
                block_length_pre = self.__parse_section_header(info, start_offset, block_length_pre)
            elif info['block_type'] == 0x00000001:
                self.__parse_interface_description_block(info, end_offset)
            elif info['block_type'] == 0x00000005:
                self.__parse_interface_statistic_block(info, end_offset)
            elif info['block_type'] == 0x00000006:
                self.__parse_enhanced_packet_block(info, end_offset)
            else:
                self.__parse_unknown_payload(info, end_offset)
                print('Unknown block_type', hex(info['block_type']), file=sys.stderr)

            block_length_post = self.__unpack(self.fmt_uint32)
            assert block_length_pre == block_length_post

            self._writer.write(info)

    def __parse_section_header(self, info, start_offset, block_length_pre):
        old_fmt_uint32 = self.fmt_uint32

        info['magic'] = HexInt(self.__unpack(self.fmt_uint32))
        self._configure_endianess(info['magic'])
        block_length_pre = struct.unpack(self.fmt_uint32, struct.pack(old_fmt_uint32, block_length_pre))[0]
        end_offset = start_offset + block_length_pre - 8

        info['major_version'] = self.__unpack(self.fmt_uint16)
        info['minor_version'] = self.__unpack(self.fmt_uint16)
        info['section_length'] = HexInt(self.__unpack(self.fmt_uint64))

        if self._input_file.tell() < end_offset:
            info['options'] = self.__parse_options({
                2: ('shb_hardware', self.__unpack_utf8),
                3: ('shb_os', self.__unpack_utf8),
                4: ('shb_userappl', self.__unpack_utf8)
            })

        return block_length_pre


    def __parse_interface_description_block(self, info, end_offset):
        info['link_type'] = self.__unpack(self.fmt_uint16)
        self.__unpack(self.fmt_uint16) # RESERVED
        info['snapshot_length'] = self.__unpack(self.fmt_uint32)

        if self._input_file.tell() < end_offset:
            info['options'] = self.__parse_options({
                2: ('if_name', self.__unpack_utf8),
                3: ('if_description', self.__unpack_utf8),
                9: ('if_tsresol', self.__unpack_tsresol),
                11: ('if_filter', self.__unpack_utf8),
                12: ('if_os', self.__unpack_utf8),
            })

        interface_param = InterfaceParam()
        interface_param.link_type = info['link_type']
        if 'options' in info and 'if_tsresol' in info['options']:
            interface_param.tsresol = info['options']['if_tsresol']['base'] ** (-info['options']['if_tsresol']['power'])
        self.__interfaces.append(interface_param)


    def __parse_enhanced_packet_block(self, info, end_offset):
        info['interface_id'] = self.__unpack(self.fmt_uint32)
        interface_param = self.__interfaces[info['interface_id']]
        info['datetime'] = self.__unpack_timestamp(interface_param.tsresol)
        info['captured_length'] = self.__unpack(self.fmt_uint32)
        info['packet_length'] = self.__unpack(self.fmt_uint32)

        end_payload_offset = self._input_file.tell() + info['captured_length']
        if interface_param.link_type == LINKTYPE_ETHERNET:
            self.__parse_aligned(
                lambda: self.__parse_ethernet_data(info, end_payload_offset),
                4)
        else:
            info['unknown_payload'] = self.__parse_aligned(
                lambda: self._input_file.read(info['captured_length']),
                4)
            print('Unknown link_type', interface_param.link_type, file=sys.stderr)

        if self._input_file.tell() < end_offset:
            info['options'] = self.__parse_options({
                2: ('ebp_flags', lambda x: HexInt(self.__unpack(self.fmt_uint32))),
                3: ('ebp_hash', lambda x: self._input_file.read(x)),
                4: ('epb_dropcount', lambda x: HexInt(self.__unpack(self.fmt_uint64))),
            })


    def __parse_interface_statistic_block(self, info, end_offset):
        info['interface_id'] = self.__unpack(self.fmt_uint32)
        info['datetime'] = self.__unpack_timestamp(10 ** -6)

        if self._input_file.tell() < end_offset:
            info['options'] = self.__parse_options({
                2: ('isb_starttime', lambda x: self.__unpack_timestamp(10 ** -6)),
                3: ('isb_endtime', lambda x: self.__unpack_timestamp(10 ** -6)),
                4: ('isb_ifrecv', lambda x: self.__unpack(self.fmt_uint64)),
                5: ('isb_ifdrop', lambda x: self.__unpack(self.fmt_uint64)),
            })


    def __parse_ethernet_data(self, info, end_offset):
        info['ethernet_data'] = ethernet_header_read(self._reader)

        if info['ethernet_data']['type'] == TYPE_IPV4:
            self.__parse_type_ipv4(info, end_offset)
        else:
            self.__parse_unknown_payload(info, end_offset)


    def __parse_type_ipv4(self, info, end_offset):
        info['ipv4_data'] = ipv4_header_read(self._reader)

        if info['ipv4_data']['protocol'] == PROTOCOL_TCP:
            self.__parse_protocol_tcp(info, end_offset)
        elif info['ipv4_data']['protocol'] == PROTOCOL_UDP:
            self.__parse_protocol_udp(info, end_offset)
        else:
            self.__parse_unknown_payload(info, end_offset)


    def __parse_protocol_tcp(self, info, end_offset):
        info['tcp_data'] = tcp_header_read(self._reader)
        self.__parse_unknown_payload(info, end_offset)


    def __parse_protocol_udp(self, info, end_offset):
        info['udp_data'] = udp_header_read(self._reader)
        self.__parse_unknown_payload(info, end_offset)


    def __parse_unknown_payload(self, info, end_offset):
        length = end_offset - self._input_file.tell()
        if length > 0:
            info['unknown_payload'] = self._input_file.read(length)


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
                self._input_file.seek(align_value(option_length, 4), RELATIVE)
                print('Unknown option_code', option_code, file=sys.stderr)

        return options


    def __parse_aligned(self, callback, align):
        start_offset = self._input_file.tell()
        temp = callback()
        end_offset = start_offset + align_value(self._input_file.tell() - start_offset, align)
        self._input_file.seek(end_offset, ABSOLUTE)
        return temp


    def __unpack(self, fmt):
        block = self._input_file.read(struct.calcsize(fmt))
        return struct.unpack(fmt, block)[0]


    def __unpack_utf8(self, length):
        return self._input_file.read(length).decode('utf-8')


    def __unpack_tsresol(self, length):
        temp = self.__unpack(self.fmt_uint8)
        info = OrderedDict()
        info['base'] = 2 if temp & 0x80 else 10
        info['power'] = temp & 0x7F
        return info


    def __unpack_timestamp(self, tsresol):
        ticks = self.__unpack(self.fmt_uint32) << 32 | self.__unpack(self.fmt_uint32)
        return datetime.datetime(1970, 1, 1) + datetime.timedelta(0, ticks * tsresol)

