#!/usr/bin/env pypy
import pdb
import argparse
import scapy.all as sc

OPS = [
  'summary',
]

def get_args():
  parser = argparse.ArgumentParser(description="Perform basic operations on packet data")
  parser.add_argument("-p", "--packet", required=True, metavar="PACKETDUMP", help="Packet dump")
  parser.add_argument("-s", "--summary", action="store_true", help="Summarize contents")
  args = parser.parse_args()
  return args

def get_op(args):
  for op in OPS:
    op_is_set = getattr(args, op, False)

    if op_is_set:
      return op

def load_pcap(filename):
  packets = sc.sniff(offline=filename)
  return packets

def summarize(packets):
  packets.summary()

if __name__ == '__main__':
  args = get_args()
  op = get_op(args)
  packets = load_pcap(args.packet)

  if op == "summary":
    summarize(packets)
