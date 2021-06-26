#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int print_hex(char prompt[], unsigned char hex_array[], int array_count)
{
    printf("%s", prompt);
    for(int i=0; i < array_count; i++)
    {
        printf("%02x ",hex_array[i]);
    }
    printf("\n");
    return 0;
}

int hex_to_int(unsigned char hex_array[], int endianness) /* Assuming 4 byte array */
{
    int result;

    if(endianness == 1)
    {
        result = ((hex_array[3] & 0x0000ffff) << 24) | 
                     ((hex_array[2] & 0x0000ffff) << 16) | 
                     ((hex_array[1] & 0x0000ffff) << 8) | 
                     (hex_array[0] & 0x0000ffff);
    }
    else
    {
        result = ((hex_array[0] & 0x0000ffff) << 24) | 
                     ((hex_array[1] & 0x0000ffff) << 16) | 
                     ((hex_array[2] & 0x0000ffff) << 8) | 
                     (hex_array[3] & 0x0000ffff);
    }

    return result;

}

int determine_endianness(unsigned char global_header[])
{
    unsigned char magic_num_test[4] = {0xa1, 0xb2, 0xc3, 0xd4};
    unsigned char magic_num[4] = {global_header[0], 
                                  global_header[1], 
                                  global_header[2], 
                                  global_header[3]};

    int result = memcmp(magic_num, magic_num_test, 4);

    if(result == 0)
    {
        return 0; /* 0 for big endian */
    }
    else
    {
        return 1; /* 1 for little endian */
    }
}

int main(int argc, char **argv)
{
    FILE *fp;
    unsigned char global_header[24];
    unsigned char packet_header[16];
    unsigned char timestamp_hex[4];
    unsigned char packet_len_hex[4];

    /* 1. Open input file */

    fp = fopen(argv[1], "rb");
    fread(&global_header, sizeof(char), 24, fp);
    int endianness = determine_endianness(global_header);

    /* 2a. Get first packet header */

    fread(&packet_header, sizeof(char), 16, fp);
    for(int i=0; i<4; i++)
    {
        timestamp_hex[i] = packet_header[i];
    }
    for (int i=8; i<12; ++i)
    {
        packet_len_hex[i-8] = packet_header[i];
    }
    int packet_len = hex_to_int(packet_len_hex, endianness);
    fseek(fp, packet_len, SEEK_CUR);

    /* 2b. All the other packets */

    while(1) /* Infinite loops are fun ... foreverrrrrr */ 
    {
        fread(&packet_header, sizeof(char), 16, fp);
        int eof_bool = feof(fp);
        if(eof_bool != 0)
        {
            break;
        }
        for(int i=0; i<4; i++)
        {
            timestamp_hex[i] = packet_header[i];
        }
        for (int i=8; i<12; ++i)
        {
            packet_len_hex[i-8] = packet_header[i];
        }
        packet_len = hex_to_int(packet_len_hex, endianness);
        fseek(fp, packet_len, SEEK_CUR);
    }
    
    int last_timestamp = hex_to_int(timestamp_hex, endianness);
    time_t timestamp_formatted = (time_t)last_timestamp;
    struct tm *timestamp_struct = localtime(&timestamp_formatted);
    char formatted_time[80];
    strftime(formatted_time, 80, "%x %X",timestamp_struct);
    printf("Last timestamp is %s\n", formatted_time);

    fclose(fp);

return 1; 
}