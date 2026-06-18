import socket
import struct
import textwrap


TAB = "\t"
DATA_TAB = TAB * 2


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("=" * 60)
    print("  Network Packet Analyzer - Educational Use Only")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        print(f"\nEthernet Frame:")
        print(f"{TAB}Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}")

        if eth_proto == 8:
            (version, header_length, ttl, proto,
             src_ip, dest_ip, data) = ipv4_packet(data)

            print(f"{TAB}IPv4 Packet:")
            print(f"{DATA_TAB}Version: {version}, Header Length: {header_length}, TTL: {ttl}")
            print(f"{DATA_TAB}Protocol: {proto}, Source: {src_ip}, Destination: {dest_ip}")

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(f"{DATA_TAB}ICMP Packet:")
                print(f"{DATA_TAB}Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
                print(f"{DATA_TAB}Data:")
                print(format_data(DATA_TAB, data))

            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flags, data = tcp_segment(data)
                print(f"{DATA_TAB}TCP Segment:")
                print(f"{DATA_TAB}Source Port: {src_port}, Destination Port: {dest_port}")
                print(f"{DATA_TAB}Sequence: {sequence}, Acknowledgement: {acknowledgement}")
                print(f"{DATA_TAB}Flags: {flags}")
                print(f"{DATA_TAB}Data:")
                print(format_data(DATA_TAB, data))

            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(f"{DATA_TAB}UDP Segment:")
                print(f"{DATA_TAB}Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}")
                print(f"{DATA_TAB}Data:")
                print(format_data(DATA_TAB, data))

            else:
                print(f"{DATA_TAB}Other IPv4 Data:")
                print(format_data(DATA_TAB, data))

        else:
            print(f"{TAB}Other Ethernet Data:")
            print(format_data(TAB, data))


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return (
        get_mac_addr(dest_mac),
        get_mac_addr(src_mac),
        socket.htons(proto),
        data[14:]
    )


def get_mac_addr(bytes_addr):
    return ":".join(map("{:02x}".format, bytes_addr)).upper()


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, dest = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return (
        version,
        header_length,
        ttl,
        proto,
        ipv4(src),
        ipv4(dest),
        data[header_length:]
    )


def ipv4(addr):
    return ".".join(map(str, addr))


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    (src_port, dest_port, sequence,
     acknowledgement, offset_reserved_flags) = struct.unpack("! H H L L H", data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        "URG": (offset_reserved_flags & 32) >> 5,
        "ACK": (offset_reserved_flags & 16) >> 4,
        "PSH": (offset_reserved_flags & 8) >> 3,
        "RST": (offset_reserved_flags & 4) >> 2,
        "SYN": (offset_reserved_flags & 2) >> 1,
        "FIN": offset_reserved_flags & 1,
    }
    return src_port, dest_port, sequence, acknowledgement, flags, data[offset:]


def udp_segment(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]


def format_data(prefix, data):
    if not data:
        return f"{prefix}  (no data)"
    try:
        text = data.decode("utf-8", errors="replace")
        lines = textwrap.wrap(text, 80)
        return "\n".join(f"{prefix}  {line}" for line in lines)
    except Exception:
        return f"{prefix}  {data[:64].hex()}"


if __name__ == "__main__":
    main()
