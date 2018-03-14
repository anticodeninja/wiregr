#!/usr/bin/env python
# -*- coding: utf-8 -*-

import filecmp
import shutil
import tempfile
import os
import sys

import unittest
import unittest.mock as mock

import wiregr

class TestBasicScenarios(unittest.TestCase):

    def setUp(self):
        self.data_dir = os.path.join(os.path.dirname(__file__), 'data')
        self.test_dir = tempfile.mkdtemp()


    def tearDown(self):
        shutil.rmtree(self.test_dir)


    def configure_files(self, input_name, output_name, shorten=False):
        self.input_file = os.path.join(self.data_dir, input_name)
        self.copied_file = os.path.join(self.test_dir, input_name)
        self.output_file = os.path.join(self.test_dir, output_name)
        self.ref_file = os.path.join(self.data_dir, output_name)

        if shorten:
            shutil.copyfile(self.input_file, self.copied_file)


    def run_and_check(self, argv):
        with mock.patch.object(sys, 'argv', argv):
            wiregr.main()
        self.assertTrue(filecmp.cmp(self.output_file, self.ref_file),
                        'output and ref file are not equal')


    def test_pcap2yaml_rtp(self):
        self.configure_files('rtp_sample.pcapng', 'rtp_sample.yaml')
        self.run_and_check(['wiregr', 'pcap2yaml', self.input_file, self.output_file])


    def test_pcap2yaml_rtp_shorten_args(self):
        self.configure_files('rtp_sample.pcapng', 'rtp_sample.yaml', True)
        self.run_and_check(['wiregr', 'pcap2yaml', self.copied_file])


    def test_yaml2pcap_rtp(self):
        self.configure_files('rtp_sample.yaml', 'rtp_sample.pcapng')
        self.run_and_check(['wiregr', 'yaml2pcap', self.input_file, self.output_file])


    def test_yaml2pcap_rtp_shorten_args(self):
        self.configure_files('rtp_sample.yaml', 'rtp_sample.pcapng', True)
        self.run_and_check(['wiregr', 'yaml2pcap', self.copied_file])


    def test_yaml_process_dummy_rtp(self):
        self.configure_files('rtp_sample.yaml', 'rtp_sample.yaml')
        self.run_and_check(['wiregr', 'process', self.input_file, self.output_file])


    def test_yaml_process_dummy_rtp_shorten_args(self):
        self.configure_files('rtp_sample.yaml', 'rtp_sample.yaml', True)
        self.run_and_check(['wiregr', 'process', self.copied_file])


    def test_yaml_process_fix_checksums_rtp(self):
        self.configure_files('rtp_sample.yaml', 'rtp_sample.yaml')
        self.run_and_check(['wiregr', 'process', self.input_file, self.output_file, '--fix-checksums'])


    def test_yaml_process_recalc_len_rtp(self):
        self.configure_files('rtp_sample.yaml', 'rtp_sample.yaml')
        self.run_and_check(['wiregr', 'process', self.input_file, self.output_file, '--fix-lengths'])


    def test_pcap2yaml_rtsp(self):
        self.configure_files('rtsp_sample.pcapng', 'rtsp_sample.yaml')
        self.run_and_check(['wiregr', 'pcap2yaml', self.input_file, self.output_file])


    def test_yaml2pcap_mixed_payload_mysql(self):
        self.configure_files('mysql_sample.yaml', 'mysql_sample.pcapng')
        self.run_and_check(['wiregr', 'yaml2pcap', self.input_file, self.output_file])


    def test_yaml2pcap_rtsp(self):
        self.configure_files('rtsp_sample.yaml', 'rtsp_sample.pcapng')
        self.run_and_check(['wiregr', 'yaml2pcap', self.input_file, self.output_file])


    def test_yaml_process_dummy_rtsp(self):
        self.configure_files('rtsp_sample.yaml', 'rtsp_sample.yaml')
        self.run_and_check(['wiregr', 'process', self.input_file, self.output_file])


    def test_yaml_process_fix_checksums_rtsp(self):
        self.configure_files('rtsp_sample.yaml', 'rtsp_sample.yaml')
        self.run_and_check(['wiregr', 'process', self.input_file, self.output_file, '--fix-checksums'])


    def test_yaml_process_fix_len_rtsp(self):
        self.configure_files('rtsp_sample.yaml', 'rtsp_sample.yaml')
        self.run_and_check(['wiregr', 'process', self.input_file, self.output_file, '--fix-lengths'])


    def test_yaml_process_fix_stream_mysql_start(self):
        self.configure_files('mysql_sample_start.yaml', 'mysql_sample_start.yaml')
        self.run_and_check(['wiregr', 'process', self.input_file, self.output_file, '--fix-tcp-streams'])


    def test_yaml_process_fix_stream_mysql_cont(self):
        self.configure_files('mysql_sample_cont.yaml', 'mysql_sample_cont.yaml')
        self.run_and_check(['wiregr', 'process', self.input_file, self.output_file, '--fix-tcp-streams'])


    def test_yaml_process_mixed_payload_mysql(self):
        self.configure_files('mysql_sample.yaml', 'mysql_sample.yaml')
        self.run_and_check(['wiregr', 'process', self.input_file, self.output_file, '--fix-lengths', '--fix-checksums'])


    def test_yaml_process_clean_mac_rtsp(self):
        self.configure_files('rtsp_sample.yaml', 'rtsp_sample_zeromac.yaml')
        self.run_and_check(['wiregr', 'process', self.input_file, self.output_file, '--clean-mac'])


    def test_yaml_process_move_timeline_mysql(self):
        self.configure_files('mysql_sample_start.yaml', 'mysql_sample_start_2018.yaml')
        self.run_and_check(['wiregr', 'process', self.input_file, self.output_file, '--move-timeline', '2018-01-01'])


if __name__ == '__main__':
    unittest.main()
