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

@profile
def last_timestamp(infile): # Expecting most of this to be command line input, so strings
    
    # Open input file
    in_ptr = open(infile, 'rb+')
    pcap = in_ptr.read()
    pcap_ptr = 0
    
    # Global Header
    global_header = pcap[pcap_ptr : (pcap_ptr := pcap_ptr + 24)] # I am the walrus, goo goo g'joob
    endianness = determine_endianness(global_header)
    print(f'This file was generated on a {endianness}-endian computer')
        
    timestamp = pcap[pcap_ptr : pcap_ptr + 4]
    packet_length = int.from_bytes(pcap[pcap_ptr + 8 : pcap_ptr + 12], byteorder=endianness)
    print(f"first timestamp is {datetime.fromtimestamp(int.from_bytes(timestamp, byteorder=endianness))}")

    pcap_ptr += (16 + packet_length)
    pcap_len = in_ptr.tell()
    
    # Packets
    while True:
        # Packet Header
        try:
            timestamp = pcap[pcap_ptr : pcap_ptr + 4]
            packet_length = int.from_bytes(pcap[pcap_ptr + 8 : pcap_ptr + 12], byteorder=endianness)
            #print(f"current timestamp is {datetime.fromtimestamp(int.from_bytes(timestamp, byteorder=endianness))}")
            #print(f" pcap_len is {pcap_len}")
            #print(f" pcap_ptr is {pcap_ptr}")
            
        except:
            # If we try to read outside of the array, it raises an exception. We can use that to determine EOF
            break
                
        # Move the file pointer to the beginning of the
        # next packet header
        pcap_ptr += (16 + packet_length)
        if pcap_ptr >= pcap_len:
                break
            
    # Be nice to your pointers. Put them away when you're done with them
    print(f"Last packet's timestamp is {datetime.fromtimestamp(int.from_bytes(timestamp, byteorder=endianness))}")
    in_ptr.close()
    
    return

if __name__ == "__main__":
	a = cli_args()

	last_timestamp(a.infile)