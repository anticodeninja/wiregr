#!/usr/bin/env python
# -*- coding: utf-8 -*-

import yaml
import struct
from collections import OrderedDict

ABSOLUTE = 0
RELATIVE = 1
FROM_END = 2

MAGIC = 0x1A2B3C4D

OPT_END = 0
OPT_COMMENT = 1

LINKTYPE_ETHERNET = 1

TYPE_IPV4 = 0x0800

PROTOCOL_TCP = 6
PROTOCOL_UDP = 17

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

