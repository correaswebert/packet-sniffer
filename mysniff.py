"""
A tcpdump like tool that takes command-line arguments:
Destination IP Address, Destination Port Number,  Protocol Name (optional)
Where protocol name should handle following protocols:
http, telnet, ftp, tcp, udp
"""

import os
import socket
import struct
import sys
import threading
from collections import defaultdict

# network protocol and number mapping
NETWORK_PROTOCOL_MAPPING = defaultdict(lambda: None)
NETWORK_PROTOCOL_MAPPING[8] = "IP"

# transport protocol and number mapping
TRANSPORT_PROTOCOL_MAPPING = defaultdict(lambda: None)
TRANSPORT_PROTOCOL_MAPPING[6] = "TCP"
TRANSPORT_PROTOCOL_MAPPING[17] = "UDP"

# command line arguments
DST_IP_ADDR = None
DST_PORT = None
PROTOCOL = None


# constants
ETH_HEAD_LEN = 14
IP_HEAD_LEN = 20
UDP_HEAD_LEN = 8

TCP_PROTOCOL_NUM = 6
UDP_PROTOCOL_NUM = 17


def isvalidIp(ip_addr):
    """Check if valid IPv4 address"""
    try:
        subnets = list(map(int, ip_addr.split('.')))
        return len(subnets) == 4 and all(map(lambda x: 0 <= x <= 255, subnets))
    except ValueError:
        return False


def bytesToMac(addr_bytes):
    """Convert byte sequence into MAC address

    Byte sequence can comprise of both single character string elements, as
    well as byte-encoded string elements, which is extracted as an int. So we
    need to convert the character to its ordinal Unicode datapoint.

    b'\\xac\\x84\\xc6\\xc3\\xb14' (put \\ to escape in VS Code's hover hint)

    Here, except for the last byte, '4', the other 5 bytes are byte-encoded.
    After converting '4' -> '\\x34' = ord('4')
    Convert each integer to its hex encoding and strip off the '0x' prefix.
    """

    mac_addr = ""
    for c in addr_bytes:
        if isinstance(c, str):
            c = ord(c)
        mac_addr += hex(c)[2:].zfill(2) + ":"
    return mac_addr[:-1]


def printBytewise(func):
    def inner(hex_data):
        hex_data, ascii_data = func(hex_data)
        bytes_in_row = 0
        line = ""

        for i in range(0, len(hex_data), 16):
            if bytes_in_row == 4:
                bytes_in_row = 0

            # hexadecimal section
            line += ' '.join(hex_data[i:i+8]) + "  "
            line += ' '.join(hex_data[i+8:i+16]) + "    "

            # padding if needed (hexadecimal section has len 52)
            line = line.ljust(52)

            # ascii section
            line += ascii_data[i:i+8] + " " + ascii_data[i+8:i+16]

            print(line)
            line = ""
            bytes_in_row += 1
        print()

    return inner


@printBytewise
def convertDataToPrintable(data):
    """Convert all the non readable characters in byte-string to '.' """

    readable = ""
    hex_data = []

    for c in data:
        # printable characters (DEL is not printable)
        if 32 < c < 127:
            readable += chr(c)
        else:
            readable += '.'
        hex_data.append(hex(c)[2:].zfill(2))

    return hex_data, readable


def extractEthernetPayload(eth_packet):
    """Extract the Ethernet payload and headers"""

    readable_eth_header = ""
    eth_header, eth_payload = eth_packet[:
                                         ETH_HEAD_LEN], eth_packet[ETH_HEAD_LEN:]

    eth = struct.unpack('!6s6sH', eth_header)
    net_protocol_num = socket.ntohs(eth[2])
    net_protocol_name = NETWORK_PROTOCOL_MAPPING[socket.ntohs(eth[2])]

    readable_eth_header += f"Destination MAC:     {bytesToMac(eth_packet[0:6])}\n"
    readable_eth_header += f"Source MAC:          {bytesToMac(eth_packet[6:12])}\n"
    readable_eth_header += f"Network Protocol:    {net_protocol_name} ({str(net_protocol_num)})\n"

    return net_protocol_num, readable_eth_header, eth_payload


def extractIpPayload(ip_packet):
    """Extract the IP payload and headers"""

    readable_ip_header = ""
    ip_header, ip_payload = ip_packet[:IP_HEAD_LEN], ip_packet[IP_HEAD_LEN:]

    # now unpack them :)
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    iph_length = ihl * 4

    trans_protocol_num = iph[6]
    trans_protocol_name = TRANSPORT_PROTOCOL_MAPPING[iph[6]]
    src_addr = socket.inet_ntoa(iph[8])
    dst_addr = socket.inet_ntoa(iph[9])

    readable_ip_header += f"Version:             IPv{version}\n"
    readable_ip_header += f"IP Header Length:    {iph_length} bytes\n"
    readable_ip_header += f"Time to Live:        {iph[5]} seconds\n"
    readable_ip_header += f"Transport Protocol:  {trans_protocol_name} ({trans_protocol_num})\n"
    readable_ip_header += f"Source Address:      {src_addr}\n"
    readable_ip_header += f"Destination Address: {dst_addr}\n"

    return trans_protocol_num, readable_ip_header, ip_payload, dst_addr, trans_protocol_name


def extractUdpPayload(udp_packet):
    """Extract the UDP payload and headers"""

    readable_udp_header = ""
    UDP_HEAD_LEN = 8
    udp_header = udp_packet[:8]

    # now unpack them :)
    udph = struct.unpack('!HHHH', udp_header)
    src_port = udph[0]
    dst_port = udph[1]

    readable_udp_header += f"Source Port:         {src_port}\n"
    readable_udp_header += f"Dest Port:           {dst_port}\n"
    readable_udp_header += f"Length:              {udph[2]}\n"
    readable_udp_header += f"Checksum:            {udph[3]}\n"

    # get data from the packet
    udp_payload = udp_packet[UDP_HEAD_LEN:]

    return readable_udp_header, udp_payload, src_port, dst_port


def extractTcpPayload(tcp_packet):
    """Extract the TCP payload and headers"""

    readable_tcp_header = ""
    tcp_header = tcp_packet[:20]

    tcph = struct.unpack('!HHLLBBHHH', tcp_header)

    src_port = tcph[0]
    dst_port = tcph[1]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    h_size = tcph_length * 4

    readable_tcp_header += f"Source Port:         {src_port}\n"
    readable_tcp_header += f"Dest Port:           {dst_port}\n"
    readable_tcp_header += f"Sequence Number:     {tcph[2]}\n"
    readable_tcp_header += f"Acknowledgement:     {tcph[3]}\n"
    readable_tcp_header += f"TCP header length:   {h_size} bytes\n"

    # get data from the packet
    tcp_payload = tcp_packet[h_size:]

    return readable_tcp_header, tcp_payload, src_port, dst_port


def keepNetworkPacket(trans_proto):
    """Keep only TCP or UDP packets"""

    if trans_proto not in ("TCP", "UDP"):
        return False
    return True


def keepTransportPacket(proto, s_port, d_port):
    """Only keep packets adhering to following table:

    HTTP:   (80)
    FTP:    (20, 21)
    Telnet: (23)
    """

    if PROTOCOL:
        if PROTOCOL == "HTTP" and proto == "TCP" and \
                80 in (s_port, d_port):
            return True

        elif PROTOCOL == "FTP" and proto == "TCP" and \
                (21 in (s_port, d_port) or 20 in (s_port, d_port)):
            return True

        elif PROTOCOL == "TELNET" and proto == "TCP" and \
                23 in (s_port, d_port):
            return True

        # filterout packet
        return False

    # no protocol specified
    return True


def parsePacket(packet):
    """Parse and filter (if required) the packets"""

    # --------------------------- ETHERNET FILTERING ---------------------------

    network_protocol, eth_header, eth_payload = \
        extractEthernetPayload(packet)

    # Parse only IP packets, IP Protocol number = 8
    if network_protocol != 8:
        return

    # ------------------------------ IP FILTERING ------------------------------

    transport_protocol, ip_header, ip_payload, dst_ip_addr, trans_proto = \
        extractIpPayload(eth_payload)

    # print(trans_proto)

    if DST_IP_ADDR and dst_ip_addr != DST_IP_ADDR:
        return
    # print(f"Hit: {dst_ip_addr}")

    # if protocol filter is specified
    if not keepNetworkPacket(trans_proto):
        return

    # ---------------------------- TCP/UDP FILTERING ---------------------------

    src_port = ""
    dst_port = ""
    trans_payload = ""
    trans_header = ""

    if transport_protocol == TCP_PROTOCOL_NUM:
        trans_header, trans_payload, src_port, dst_port = \
            extractTcpPayload(ip_payload)

    elif transport_protocol == UDP_PROTOCOL_NUM:
        trans_header, trans_payload, src_port, dst_port = \
            extractUdpPayload(ip_payload)

    if DST_PORT and dst_port != DST_PORT:
        return

    # ------------------------ HTTP/FTP/TELNET FILTERING -----------------------

    # if protocol filter is specified
    if not keepTransportPacket(trans_proto, src_port, dst_port):
        return

    # ------------------------------- PRINT DATA -------------------------------

    # Get lock to synchronize threads
    threadLock.acquire()

    print(eth_header)
    print(ip_header)
    print(trans_header)

    print(f"Application data:  {len(trans_payload)} bytes")
    if trans_payload and trans_payload.isascii():
        print(trans_payload.decode())

    print(f"Frame data: {len(packet)} bytes")
    convertDataToPrintable(packet)

    print("=" * 70, end="\n\n")

    # Free lock to release next thread
    threadLock.release()

    # end the thread
    return


if __name__ == "__main__":
    # # argument count
    argc = len(sys.argv)

    try:
        if argc == 1 and input("No filter applied, continue? (y/n) ").lower() != "y":
            raise Exception("Aborted!")

        for arg in sys.argv[1:]:
            if isvalidIp(arg):
                if DST_IP_ADDR is None:
                    DST_IP_ADDR = arg
                else:
                    raise Exception("Invalid arguments!")

            elif arg.isdigit() and 0 <= int(arg) <= 65536:
                if DST_PORT is None:
                    DST_PORT = int(arg)
                else:
                    raise Exception("Invalid arguments!")

            elif arg == "http" or arg == "ftp" or arg == "telnet" or arg == "udp" or arg == "tcp":
                PROTOCOL = arg.upper()

        if not any((DST_IP_ADDR, DST_PORT, PROTOCOL)):
            raise Exception("Insufficient valid arguments!")

        # create a AF_PACKET type raw socket (thats basically packet level)
        # define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
        raw_sock = socket.socket(socket.AF_PACKET,
                                 socket.SOCK_RAW,
                                 socket.ntohs(0x0003))

    except PermissionError:
        print("You need to run the script as super user!")
        sys.exit(1)
    except socket.error as msg:
        print("Socket could not be created")
        print(f"Error Code: {msg[0]}")
        print(f"Message: {msg[1]}")
        sys.exit(1)
    except Exception as e:
        print("There was some error!")
        print(e)
        sys.exit(1)

    else:
        print(f"{DST_IP_ADDR=}, {DST_PORT=}, {PROTOCOL=}")
        threadLock = threading.Lock()

    try:
        while True:
            packet = raw_sock.recv(65565)
            threading.Thread(target=parsePacket, args=(packet,)).start()

    except KeyboardInterrupt:
        print("Stopping sniffer.")
        raw_sock.close()

        # current process is stopped, any spawned threads are also killed
        os._exit(0)
