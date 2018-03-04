=============================================
Wiregr - Wireshark Dissector Regression Utils
=============================================

The main goal of this utility is to allow keeping wireshark dumps as text files.
It might sound crazy, but it is quite helpful for regression tests for wireshark dissectors and network related applications.

You can use Wiregr to solve the following tasks (but it is not limited to):

* Convert pcapng files to text files with the yaml markup.
* Edit text traffic and of course with your lovely text editor (it is not masked advertisement of emacs or vim).
* Convert text traffic back to pcapng files.
* Anonymize you dump: mask or replace such field as MAC addresses etc.
* Hide traces of traffic manipulations: fix all headers as no one touch your dumps.
* Troll your coworkers and admins with very strange and "untouched" dumps.
* Have any other fun.

And it support all kind of traffic and its modifications... but for some you should write some code.
And I will be glad if you return it to upstream.


Installation
============

I'm not sure that somewhere these utils will be in PYPI, so it is the easiest and reliable way to install this::

  git clone git@github.com:anticodeninja/wiregr.git
  pip install -e wiregr


Usage
=====

Convert pcapng file to text file::

  wiregr pcap2yaml rtp_sample.pcapng rtp_sample.yaml

Fix headers checksums::

  wiregr process rtp_sample.yaml rtp_sample_fixed.yaml

The whole list of processing variants can be listed by::

  wiregr process -h

Convert text file back to pcapng file::

  wiregr yaml2pcap rtp_sample_fixed.yaml rtp_sample_fixed.pcapng

