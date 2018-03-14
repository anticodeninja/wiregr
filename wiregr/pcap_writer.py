#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the
# Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
# with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

import datetime
import yaml
import struct
import sys
from collections import OrderedDict

from wiregr.common import *
from wiregr.packets import *

class PcapWriter(BaseWorker):

    def __init__(self, input_file, output_file):
        super().__init__(input_file, False, output_file, '.pcapng', True)
        self._configure_endianess(MAGIC)
        self.__interfaces = []


    def process(self):
        for info in self._reader.read():
            if info['block_type'] == 0x0A0D0D0A:
                self._configure_endianess(info['magic'])

            self.__pack(self.fmt_uint32, info['block_type'])
            start_offset = self._output_file.tell()
            self.__pack(self.fmt_uint32, 0)

            payload_offset = self._output_file.tell()
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
            block_total_length = self._output_file.tell() - payload_offset + 12

            end_offset = self._output_file.tell()
            self._output_file.seek(start_offset, ABSOLUTE)
            self.__pack(self.fmt_uint32, block_total_length)
            self._output_file.seek(end_offset, ABSOLUTE)
            self.__pack(self.fmt_uint32, block_total_length)


    def __pack_section_header(self, info):
        self.__pack(self.fmt_uint32, MAGIC)
        self.__pack(self.fmt_uint16, info['major_version'])
        self.__pack(self.fmt_uint16, info['minor_version'])
        self.__pack(self.fmt_uint64, info['section_length'])

        if 'options' in info:
            self.__pack_options(info['options'], {
                'shb_hardware': (2, self.__pack_utf8),
                'shb_os': (3, self.__pack_utf8),
                'shb_userappl': (4, self.__pack_utf8)
            })


    def __pack_interface_description_block(self, info):
        interface_param = InterfaceParam()
        interface_param.link_type = info['link_type']
        if 'options' in info and 'if_tsresol' in info['options']:
            interface_param.tsresol = info['options']['if_tsresol']['base'] ** (-info['options']['if_tsresol']['power'])
        self.__interfaces.append(interface_param)

        self.__pack(self.fmt_uint16, info['link_type'])
        self.__pack(self.fmt_uint16, 0) # RESERVED
        self.__pack(self.fmt_uint32, info['snapshot_length'])

        if 'options' in info:
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
                'ebp_hash': (3, lambda x: self._output_file.write(bytes(x))),
                'epb_dropcount': (4, lambda x: self.__pack(self.fmt_uint64, x)),
            })


    def __pack_interface_statistic_block(self, info):
        self.__pack(self.fmt_uint32, info['interface_id'])
        self.__pack_timestamp(10 ** -6, info['datetime'])

        if 'options' in info:
            self.__pack_options(info['options'], {
                'isb_starttime': (2, lambda x: self.__pack_timestamp(10 ** -6, x)),
                'isb_endtime': (3, lambda x: self.__pack_timestamp(10 ** -6, x)),
                'isb_ifrecv': (4, lambda x: self.__pack(self.fmt_uint64, x)),
                'isb_ifdrop': (5, lambda x: self.__pack(self.fmt_uint64, x)),
            })


    def __pack_ethernet_data(self, info):
        ethernet_header_pack(self._writer, info['ethernet_data'])

        if 'ipv4_data' in info:
            self.__pack_type_ipv4(info)
        else:
            self.__pack_unknown_payload(info)


    def __pack_type_ipv4(self, info):
        ipv4_header_pack(self._writer, info['ipv4_data'])

        if 'tcp_data' in info:
            self.__pack_protocol_tcp(info)
        elif 'udp_data' in info:
            self.__pack_protocol_udp(info)
        else:
            self.__pack_unknown_payload(info)


    def __pack_protocol_tcp(self, info):
        tcp_header_pack(self._writer, info['tcp_data'])

        if 'unknown_payload' in info:
            self.__pack_unknown_payload(info)


    def __pack_protocol_udp(self, info):
        udp_header_pack(self._writer, info['udp_data'])

        if 'unknown_payload' in info:
            self.__pack_unknown_payload(info)


    def __pack_options(self, options, packers):
        for k, v in options.items():
            start_offset = self._output_file.tell()
            self.__pack(self.fmt_uint32, 0)

            payload_offset = self._output_file.tell()
            if k == 'opt_comment':
                code = 1
                self.__pack_utf8(v)
            elif k in packers:
                packer = packers[k]
                code = packer[0]
                packer[1](v)
            else:
                self._output_file.seek(-4, RELATIVE)
                print('Unknown option', k, file=sys.stderr)
                continue
            size = self._output_file.tell() - payload_offset

            self.__align(size, 4)

            end_offset = self._output_file.tell()
            self._output_file.seek(start_offset, ABSOLUTE)
            self.__pack(self.fmt_uint16, code)
            self.__pack(self.fmt_uint16, size)
            self._output_file.seek(end_offset, ABSOLUTE)

        self.__pack(self.fmt_uint32, 0)


    def __pack_aligned(self, callback, align):
        start_offset = self._output_file.tell()
        callback()
        self.__align(self._output_file.tell() - start_offset, align)


    def __align(self, size, align):
        size = align_value(size, align) - size
        if size > 0:
            self._output_file.write(bytes([0] * size))


    def __pack(self, fmt, value):
        self._output_file.write(struct.pack(fmt, value))


    def __pack_utf8(self, value):
        self._output_file.write(value.encode('utf-8'))


    def __pack_tsresol(self, value):
        temp = 0x80 if value['base'] == 2 else 0
        temp = temp | value['power']
        self.__pack(self.fmt_uint8, temp)


    def __pack_timestamp(self, tsresol, value):
        ticks = int((value - datetime.datetime(1970, 1, 1)).total_seconds() / tsresol)
        self.__pack(self.fmt_uint32, (ticks >> 32) & 0xFFFFFFFF)
        self.__pack(self.fmt_uint32, ticks & 0xFFFFFFFF)


    def __pack_unknown_payload(self, info):
        self.__pack_aligned(lambda: self._writer.pack_payload(info['unknown_payload']), 4)

