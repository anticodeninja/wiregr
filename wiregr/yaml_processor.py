#!/usr/bin/env python
# -*- coding: utf-8 -*-

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


class FixChecksums:

    def process(self, info):

        if 'ipv4_data' in info:
            ipv4_data = info['ipv4_data']
            old_checksum = ipv4_data['header_checksum']
            ipv4_data['header_checksum'] = 0

            phw = StructWriter(io.BytesIO())
            ipv4_header_pack(phw, ipv4_data)
            ipv4_data['header_checksum'] = HexInt(calc_carry_add_checksum(phw.stream))

        if 'udp_data' in info:
            udp_data = info['udp_data']
            old_checksum = udp_data['checksum']
            udp_data['checksum'] = 0

            phw = StructWriter(io.BytesIO())
            if 'ipv4_data' in info:
                phw.pack_bytes(ipv4_data['source'])
                phw.pack_bytes(ipv4_data['destination'])
                phw.pack_fmt('>H', ipv4_data['protocol'])
                phw.pack_fmt('>H', ipv4_data['total_length'] - 4 * ipv4_data['header_length'])

            udp_header_pack(phw, udp_data)
            phw.pack_bytes(info['unknown_payload'])

            udp_data['checksum'] = HexInt(calc_carry_add_checksum(phw.stream))

        if 'tcp_data' in info:
            tcp_data = info['tcp_data']
            old_checksum = tcp_data['checksum']
            tcp_data['checksum'] = 0

            phw = StructWriter(io.BytesIO())
            if 'ipv4_data' in info:
                phw.pack_bytes(ipv4_data['source'])
                phw.pack_bytes(ipv4_data['destination'])
                phw.pack_fmt('>H', ipv4_data['protocol'])
                phw.pack_fmt('>H', ipv4_data['total_length'] - 4 * ipv4_data['header_length'])

            tcp_header_pack(phw, tcp_data)
            if 'unknown_payload' in info:
                phw.pack_bytes(info['unknown_payload'])

            tcp_data['checksum'] = HexInt(calc_carry_add_checksum(phw.stream))

