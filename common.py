#!/usr/bin/env python
# -*- coding: utf-8 -*-

import yaml
import struct
import sys
from collections import OrderedDict

ABSOLUTE = 0
RELATIVE = 1
FROM_END = 2

MAGIC = 0x1A2B3C4D

OPT_END = 0
OPT_COMMENT = 1

class HexInt(int): pass
class UnflowList(list): pass

class CustomDumper(yaml.Dumper):

    @staticmethod
    def save_hex_int(dumper, data):
        return yaml.ScalarNode('tag:yaml.org,2002:int', hex(data))

    @staticmethod
    def save_flow_list(dumper, data):
        return dumper.represent_sequence('tag:yaml.org,2002:seq', data, flow_style=True)

    @staticmethod
    def save_flow_bytes(dumper, data):
        return dumper.represent_sequence('tag:yaml.org,2002:seq', (HexInt(x) for x in data), flow_style=True)

    @staticmethod
    def save_unflow_list(dumper, data):
        return dumper.represent_list(data)

    @staticmethod
    def save_ordered_dict(dumper, data):
        return dumper.represent_dict(data.items())

    def __init__(self, *args, **kargs):
        kargs['default_flow_style'] = False
        super().__init__(*args, **kargs)

        self.yaml_representers = self.yaml_representers.copy()
        self.yaml_representers[HexInt] = CustomDumper.save_hex_int
        self.yaml_representers[list] = CustomDumper.save_flow_list
        self.yaml_representers[bytes] = CustomDumper.save_flow_bytes
        self.yaml_representers[UnflowList] = CustomDumper.save_unflow_list
        self.yaml_representers[OrderedDict] = CustomDumper.save_ordered_dict


class CustomLoader(yaml.Loader):

    @staticmethod
    def detect_unflow_list(loader, node):
        if node.flow_style == None:
            return UnflowList(*loader.construct_yaml_seq(node))
        return loader.construct_yaml_seq(node)

    @staticmethod
    def detect_ordered_dict(loader, node):
        return OrderedDict(loader.construct_pairs(node))

    @staticmethod
    def detect_hex_int(loader, node):
        if node.value.startswith('0x'):
            return HexInt(loader.construct_yaml_int(node))
        return loader.construct_yaml_int(node)

    def __init__(self, *args, **kargs):
        super().__init__(*args, **kargs)

        self.yaml_constructors = self.yaml_constructors.copy()
        self.yaml_constructors['tag:yaml.org,2002:int'] = CustomLoader.detect_hex_int
        self.yaml_constructors['tag:yaml.org,2002:seq'] = CustomLoader.detect_unflow_list
        self.yaml_constructors['tag:yaml.org,2002:map'] = CustomLoader.detect_ordered_dict


class InterfaceParam:

    tsresol = 10 ** -6
    link_type = 1

class BaseWorker:

    def __init__(self, input_file, is_binary_input, output_file, is_binary_output):
        if input_file != '-':
            self._input_file = open(input_file, 'r' + ('b' if is_binary_input else ''))
        else:
            self._input_file = sys.stdin

        if output_file != '-':
            self._output_file = open(output_file, 'w' + ('b' if is_binary_output else ''))
        else:
            self._output_file = sys.stdout

        if is_binary_input:
            self._reader = StructReader(self._input_file)
        else:
            self._reader = YamlReader(self._input_file)

        if is_binary_output:
            self._writer = StructWriter(self._output_file)
        else:
            self._writer = YamlWriter(self._output_file)


    def __enter__(self):
        return self


    def __exit__(self, type, value, traceback):
        if self._input_file != sys.stdin:
            self._input_file.close()
        if self._output_file != sys.stdout:
            self._output_file.close()

    def _configure_endianess(self, magic):
        prefix = '>' if magic == MAGIC else '<'
        self.fmt_uint8 = prefix + 'B'
        self.fmt_uint16 = prefix + 'H'
        self.fmt_uint32 = prefix + 'L'
        self.fmt_uint64 = prefix + 'Q'


class YamlReader:

    def __init__(self, stream):
        self.stream = stream

    def read(self):
        lines = []
        for line in self.stream:
            line = line.strip('\n\r')
            if len(line) > 0:
                lines.append(line)
                continue

            info = yaml.load('\n'.join(lines), Loader=CustomLoader)
            yield info
            lines = []


class YamlWriter:

    def __init__(self, stream):
        self.stream = stream

    def write(self, info):
        print(yaml.dump(info, Dumper=CustomDumper), file=self.stream)


class StructReader:

    def __init__(self, stream):
        self.stream = stream

    def read_fmt(self, fmt):
        block = self.stream.read(struct.calcsize(fmt))
        return struct.unpack(fmt, block)[0]

    def read_bytes(self, size):
        return self.stream.read(size)


class StructWriter:

    def __init__(self, stream):
        self.stream = stream

    def pack_fmt(self, fmt, value):
        self.stream.write(struct.pack(fmt, value))

    def pack_bytes(self, value):
        if not isinstance(value, bytes):
            value = bytes(value)
        self.stream.write(value)


def align_value(value, multiplier):
    if value % multiplier == 0:
        return value
    return value // multiplier * multiplier + multiplier


def calc_carry_add_checksum(stream):
    result = 0
    stream.seek(0, ABSOLUTE)

    while True:
        block = stream.read(2)

        if len(block) == 2:
            result = result + (block[0] << 8) + block[1]
        elif len(block) == 1:
            result = result + (block[0] << 8)
        else:
            break

        result = (result & 0xffff) + (result >> 16)

    return ~result & 0xFFFF

