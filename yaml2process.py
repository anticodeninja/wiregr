#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import datetime
import yaml
import struct
import sys
import io
from collections import OrderedDict

from common import *
from packets import *

class MegaProcessor:

    def __init__(self, input_file, output_file, processors):
        self.__processors = processors

        if input_file != '-':
            self.__input_file = open(input_file, 'r')
        else:
            self.__input_file = sys.stdin

        if output_file != '-':
            self.__output_file = open(output_file, 'w')
        else:
            self.__output_file = sys.stdout

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.__input_file != sys.stdin:
            self.__input_file.close()
        if self.__output_file != sys.stdout:
            self.__output_file.close()

    def process(self):
        lines = []
        for line in self.__input_file:
            line = line.strip('\n\r')
            if len(line) > 0:
                lines.append(line)
                continue

            info = yaml.load('\n'.join(lines), Loader=CustomLoader)
            lines = []

            for processor in self.__processors:
                processor.process(info)

            print(yaml.dump(info, Dumper=CustomDumper), file=self.__output_file)


class FixChecksums:

    def process(info):

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


parser = argparse.ArgumentParser()
parser.add_argument('input_file', nargs='?', default='-', help='input file')
parser.add_argument('output_file', nargs='?', default='-', help='output file')
parser.add_argument('--fix-checksums', action='store_true', help='fix header checksums')
args = parser.parse_args()

processors = []
if args.fix_checksums:
    processors.append(FixChecksums)

with MegaProcessor(args.input_file, args.output_file, processors) as mega_processor:
    mega_processor.process()
