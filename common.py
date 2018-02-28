#!/usr/bin/env python
# -*- coding: utf-8 -*-

import yaml
from collections import OrderedDict

ABSOLUTE = 0
RELATIVE = 1
FROM_END = 2

OPT_END = 0
OPT_COMMENT = 1

LINKTYPE_ETHERNET = 1

TYPE_IPV4 = 0x0800

PROTOCOL_TCP = 6
PROTOCOL_UDP = 17

class HexInt(int): pass
class OrderedList(list): pass

class CustomDumper(yaml.Dumper):

    def __init__(self, *args, **kargs):
        kargs['default_flow_style'] = False
        super().__init__(*args, **kargs)
        self.yaml_representers = self.yaml_representers.copy()
        self.yaml_representers[HexInt] = lambda dumper, data: yaml.ScalarNode('tag:yaml.org,2002:int', hex(data))
        self.yaml_representers[list] = lambda dumper, data: dumper.represent_sequence(
            'tag:yaml.org,2002:seq', data, flow_style=True)
        self.yaml_representers[bytes] = lambda dumper, data: dumper.represent_sequence(
            'tag:yaml.org,2002:seq', (HexInt(x) for x in data), flow_style=True)
        self.yaml_representers[OrderedList] = lambda dumper, data: dumper.represent_list(data)
        self.yaml_representers[OrderedDict] = lambda dumper, data: dumper.represent_dict(data.items())


class InterfaceParam:

    tsresol = 10 ** -6
    link_type = 1
