import sys, os, argparse
from datetime import datetime

def cli_args():
    
    desc = 'Get last packet timestamp.'
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('infile', action='store', help='Input file. Must be a PCAP')
    
    return parser.parse_args()

def determine_endianness(global_header): # Expect this to be a byte array
    magic_num_test = b'x\a1\xb2\xc3\xd4'
    magic_num = global_header[0:4]
    if magic_num == magic_num_test:
        return 'big'
    else:
        return 'little'

#@profile
def last_timestamp(infile): # Expecting most of this to be command line input, so strings
    
    # Open input file
    in_ptr = open(infile, 'rb+')
    
    # Global Header
    global_header = in_ptr.read(24)
    endianness = determine_endianness(global_header)
    print(f'This file was generated on a {endianness}-endian computer')

    packet_header = in_ptr.read(16)
        
    timestamp = packet_header[0:4]
    packet_length = int.from_bytes(packet_header[8:12], byteorder=endianness)
    print(f"first timestamp is {datetime.fromtimestamp(int.from_bytes(timestamp, byteorder=endianness))}")

    #in_ptr.seek(packet_length,1)
    
    # Packets
    while True:
        # Packet Header
        packet_header = in_ptr.read(chunk_size := 16 + packet_length)
        if len(packet_header) != (chunk_size):
            break # Python returns '' for EOF, which evaluates FALSE
        
        timestamp = packet_header[-16:-12]
        packet_length = int.from_bytes(packet_header[-8:-4], byteorder=endianness)

            
    # Be nice to your pointers. Put them away when you're done with them
    print(f"Last packet's timestamp is {datetime.fromtimestamp(int.from_bytes(timestamp, byteorder=endianness))}")
    in_ptr.close()
    
    return

if __name__ == "__main__":
	a = cli_args()

	last_timestamp(a.infile)