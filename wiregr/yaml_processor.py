#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the
# Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
# with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

import datetime
import yaml
import struct
import sys
import io
from collections import OrderedDict

from .common import *
from .packets import *


class YamlProcessor(BaseWorker):

    def __init__(self, input_file, output_file, processors):
        super().__init__(input_file, False, output_file, False)
        self.__processors = processors

    def process(self):
        for info in self._reader.read():
            for processor in self.__processors:
                processor.process(info)
            self._writer.write(info)


class CleanMac:

    def process(self, info):
        if info['block_type'] != 0x6:
            return

        if 'ethernet_data' in info:
            ethernet_data = info['ethernet_data']
            ethernet_data['destination'] = [0, 0, 0, 0, 0, 0]
            ethernet_data['source'] = [0, 0, 0, 0, 0, 0]


class MoveTimeline:

    def __init__(self, start_time):
        self.__start_time = start_time
        self.__timespan = None

    def process(self, info):
        if info['block_type'] != 0x5 and info['block_type'] != 0x6:
            return

        if self.__timespan is None:
            self.__timespan = info['datetime'] - self.__start_time

        info['datetime'] = info['datetime'] - self.__timespan


class FixLengths:

    def process(self, info):

        if info['block_type'] != 0x6:
            return

        total_length = 0

        if 'unknown_payload' in info:
            phw = StructWriter(io.BytesIO())
            phw.pack_payload(info['unknown_payload'])
            total_length += phw.stream.tell()

        if 'udp_data' in info:
            udp_data = info['udp_data']

            phw = StructWriter(io.BytesIO())
            udp_header_pack(phw, udp_data)

            udp_data['length'] = phw.stream.tell() + total_length
            total_length += phw.stream.tell()

        if 'tcp_data' in info:
            tcp_data = info['tcp_data']

            phw = StructWriter(io.BytesIO())
            tcp_header_pack(phw, tcp_data)

            tcp_data['header_length'] = phw.stream.tell() // 4
            total_length += phw.stream.tell()

        if 'ipv4_data' in info:
            ipv4_data = info['ipv4_data']

            phw = StructWriter(io.BytesIO())
            ipv4_header_pack(phw, ipv4_data)

            ipv4_data['total_length'] = phw.stream.tell() + total_length
            total_length += phw.stream.tell()

        if 'ethernet_data' in info:
            ethernet_data = info['ethernet_data']

            phw = StructWriter(io.BytesIO())
            ethernet_header_pack(phw, ethernet_data)

            total_length += phw.stream.tell()

        if info['captured_length'] == info['packet_length']:
            info['packet_length'] = total_length
        info['captured_length'] = total_length


class FixChecksums:

    def process(self, info):

        if info['block_type'] != 0x6:
            return

        if 'ipv4_data' in info:
            ipv4_data = info['ipv4_data']
            ipv4_data['header_checksum'] = 0

            phw = StructWriter(io.BytesIO())
            ipv4_header_pack(phw, ipv4_data)
            ipv4_data['header_checksum'] = HexInt(calc_carry_add_checksum(phw.stream))

        if 'udp_data' in info:
            udp_data = info['udp_data']
            udp_data['checksum'] = 0

            phw = StructWriter(io.BytesIO())
            if 'ipv4_data' in info:
                phw.pack_bytes(ipv4_data['source'])
                phw.pack_bytes(ipv4_data['destination'])
                phw.pack_fmt('>H', ipv4_data['protocol'])
                phw.pack_fmt('>H', ipv4_data['total_length'] - 4 * ipv4_data['header_length'])

            udp_header_pack(phw, udp_data)
            phw.pack_payload(info['unknown_payload'])

            udp_data['checksum'] = HexInt(calc_carry_add_checksum(phw.stream))

        if 'tcp_data' in info:
            tcp_data = info['tcp_data']
            tcp_data['checksum'] = 0

            phw = StructWriter(io.BytesIO())
            if 'ipv4_data' in info:
                phw.pack_bytes(ipv4_data['source'])
                phw.pack_bytes(ipv4_data['destination'])
                phw.pack_fmt('>H', ipv4_data['protocol'])
                phw.pack_fmt('>H', ipv4_data['total_length'] - 4 * ipv4_data['header_length'])

            tcp_header_pack(phw, tcp_data)
            if 'unknown_payload' in info:
                phw.pack_payload(info['unknown_payload'])

            tcp_data['checksum'] = HexInt(calc_carry_add_checksum(phw.stream))

class FixTcpStreams:

    def __init__(self):
        self.__streams = {}

    def process(self, info):

        if info['block_type'] != 0x6 or 'ipv4_data' not in info or 'tcp_data' not in info:
            return

        ipv4_data = info['ipv4_data']
        tcp_data = info['tcp_data']
        tcp_segment_length = ipv4_data['total_length']\
                             - 4 * ipv4_data['header_length']\
                             - 4 * tcp_data['header_length']

        stream, direction = self.__get_stream(ipv4_data, tcp_data)
        tcp_data['seq_num'] = stream[direction]
        tcp_data['ack_num'] = stream[not direction]
        stream[direction] += tcp_segment_length

    def __get_stream(self, ipv4_data, tcp_data):
        one = '.'.join(str(x) for x in ipv4_data['source']) + ':' + str(tcp_data['source_port'])
        two = '.'.join(str(x) for x in ipv4_data['destination']) + ':' + str(tcp_data['destination_port'])
        direction = one < two
        key = one + '_' + two if direction else two + '_' + one

        if key in self.__streams:
            stream = self.__streams[key]
        else:
            stream = {
                direction: tcp_data['seq_num'],
                not direction: tcp_data['ack_num']
            }
            self.__streams[key] = stream

        if tcp_data['flags'] & 0x002:
            if tcp_data['flags'] & 0x010:
                stream[direction] = tcp_data['seq_num']
            else:
                stream[not direction] = 0

            self.__streams[key] = { k: v for k, v in stream.items() }
            self.__streams[key][direction] = tcp_data['seq_num'] + 1

        return stream, direction

