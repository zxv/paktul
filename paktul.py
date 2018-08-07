#!/usr/bin/env pypy
import pdb
import argparse
import scapy.all as sc

OPS = [
  'summary',
  'listsessions',
]

def get_args():
  parser = argparse.ArgumentParser(description="Perform basic operations on packet data")
  parser.add_argument("-p", "--packet", required=True, metavar="PACKETDUMP", help="Packet dump")
  parser.add_argument("-s", "--summary", action="store_true", help="Summarize contents")
  parser.add_argument("-l", "--listsessions", action="store_true", help="Get session data")
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

def list_sessions(packets):
  sessions = packets.sessions()
  if sessions:
    keys = sessions.keys()
    if keys:
      for key in keys:
        print key

if __name__ == '__main__':
  args = get_args()
  op = get_op(args)
  packets = load_pcap(args.packet)

  if op == "summary":
    summarize(packets)

  if op == "listsessions":
    sessions = list_sessions(packets)
