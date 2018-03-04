#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the
# Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
# with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse

def main():
    parser = argparse.ArgumentParser(description="Synchronize org-mode files with cloud.")

    subparsers = parser.add_subparsers(dest='command', title='commands')

    pcap2yaml = subparsers.add_parser('pcap2yaml', help='convert pcap to yaml.')
    pcap2yaml.add_argument('input_file', nargs='?', default='-', help='input file')
    pcap2yaml.add_argument('output_file', nargs='?', default='-', help='output file')

    yaml2pcap = subparsers.add_parser('yaml2pcap', help='convert yaml to pcap.')
    yaml2pcap.add_argument('input_file', nargs='?', default='-', help='input file')
    yaml2pcap.add_argument('output_file', nargs='?', default='-', help='output file')

    yaml_process = subparsers.add_parser('process', help='process yaml file.')
    yaml_process.add_argument('input_file', nargs='?', default='-', help='input file')
    yaml_process.add_argument('output_file', nargs='?', default='-', help='output file')
    yaml_process.add_argument('--fix-lengths', action='store_true', help='fix header lengths')
    yaml_process.add_argument('--fix-checksums', action='store_true', help='fix header checksums')

    args = parser.parse_args()

    if args.command == 'pcap2yaml':
        import wiregr.pcap_reader as module
        with module.PcapReader(args.input_file, args.output_file) as reader:
            reader.process()
    elif args.command == 'yaml2pcap':
        import wiregr.pcap_writer as module
        with module.PcapWriter(args.input_file, args.output_file) as writer:
            writer.process()
    elif args.command == 'process':
        import wiregr.yaml_processor as module
        processors = []
        if args.fix_lengths:
            processors.append(module.FixLengths())
        if args.fix_checksums:
            processors.append(module.FixChecksums())
        with module.YamlProcessor(args.input_file, args.output_file, processors) as processor:
            processor.process()


if __name__ == "__main__":
    main()
