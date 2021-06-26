import sys, os, argparse, io
from datetime import datetime

def cli_args():
    
    desc = 'Get last packet timestamp.'
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('infile', action='store', help='Input file. Must be a PCAP')
    parser.add_argument('-b','--buffersize', nargs = '?', const=524288000, action='store', help='Use a different buffer size, in bytes. Default is 500MB')
    
    return parser.parse_args()

def determine_endianness(global_header): # Expect this to be a byte array
    magic_num_test = b'x\a1\xb2\xc3\xd4'
    magic_num = global_header[0:4]
    if magic_num == magic_num_test:
        return 'big'
    else:
        return 'little'


def last_timestamp(infile, buffersize = 524288000): # Expecting most of this to be command line input, so strings
    
    # Open input and output files
    b = bytearray(buffersize)
    in_file = io.open(infile, 'rb')

    segment_size = in_file.readinto(b)
    file_ptr = 0
    
    # Global Header
    global_header = b[file_ptr : file_ptr + 24]
    endianness = determine_endianness(global_header)
    file_ptr += 24
    print(f'This file was generated on a {endianness}-endian computer')

    # First packet
    packet_header = b[file_ptr:file_ptr+16]
    timestamp = packet_header[0:4]
    packet_length = int.from_bytes(packet_header[8:12], byteorder=endianness)


    file_ptr += 16
    offset = packet_length + 16

    
    # Packets
    while True:

        try:
            packet_length = int.from_bytes(b[file_ptr+offset-8:file_ptr+offset-4], byteorder=endianness)
            timestamp = b[file_ptr+offset-16:file_ptr+offset-12]
            file_ptr += offset
            offset = packet_length + 16
        except:
            blob = b[file_ptr:]
            rem = file_ptr + offset - segment_size

            segment_size = in_file.readinto(b)
            if not segment_size:
                break

            blob = blob + b[:rem]
            packet_length = int.from_bytes(blob[-8:-4], byteorder=endianness)
            timestamp = blob[-16:-12]
            print(int.from_bytes(timestamp, byteorder=endianness))

            file_ptr = rem
            offset = packet_length + 16
            continue
    # Be nice to your pointers. Put them away when you're done with them
    print(f"Last packet's timestamp is {datetime.fromtimestamp(int.from_bytes(timestamp, byteorder=endianness))}")
    in_file.close()
    
    return

if __name__ == "__main__":
	a = cli_args()

	last_timestamp(a.infile, int(a.buffersize))