import socket


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # Uncomment this block to pass the first stage
    #
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    #
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            
            # HEADER
            # 16 bits
            p_id = buf[:2] # b"\x04\xd2" # Packet Identifier (ID) 16 bits
            # 16 bits per 8 bits
            # first 8 bits for p_qr, p_opcode, p_aa, p_tc, p_rd
            p_qr = bytes([0x80 + buf[2]]) # Query/Response Indicator (QR) 1 bit
            p_opcode = b"" # Operation Code (OPCODE) 4 bits
            p_aa = b"" # Authoritative Answer (AA) 1 bit
            p_tc = b"" # Truncation (TC) 1 bit
            p_rd = b"" # Recursion Desired (RD) 1 bit
            # second 8 bits for p_ra, p_z, p_rcode
            p_ra = b"\x00" if buf[2] == b'\x00' else b"\x04" # Recursion Available (RA) 1 bit
            p_z = b"" # Reserved (Z) 3 bits
            p_rcode = b"" # Response Code (RCODE) 4 bits
            # 16 bits
            p_qdcount = b"\x00\x01" # Question Count (QDCOUNT) 16 bits
            # 16 bits
            p_ancount = b"\x00\x01" # Answer Record Count (ANCOUNT) 16 bits
            # 16 bits
            p_nscount = b"\x00\x00" # Authority Record Count (NSCOUNT) 16 bits
            # 16 bits
            p_arcount = b"\x00\x00" # Additional Record Count (ARCOUNT) 16 bits
            
            # 96 bits = 12 bytes for header 
            
            header = p_id + p_qr + p_ra + p_qdcount + p_ancount + p_nscount + p_arcount
            
            # QUESTIONS
            q_domain = b"\x0ccodecrafters\x02io\x00" # Name label sequence \xzz for size and then content
            q_type = b"\x00\x01" # Type 2 bytes = 16 bits big-endian 1 for "A" record type
            q_class = b"\x00\x01" # Type 2 bytes = 16 bits big-endian 1 for "IN" record class
            
            questions = q_domain + q_type + q_class
            
            # ANSWERS
            a_name = b"\x0ccodecrafters\x02io\00" # Name Label Sequence
            a_type = b"\x00\x01" # Type 2-byte Integer
            a_class = b"\x00\x01" # Class 2-byte Integer
            a_ttl = b"\x00\x00\x00\x3c" # TTL (Time-To-Live) 4-byte Integer
            a_length = b"\x00\x04" # Length (RDLENGTH) 2-byte Integer
            a_data = b"\x08\x08\x08\x08" # Data (RDATA) Variable
            
            rr = a_name + a_type + a_class + a_ttl + a_length + a_data
            
            anwser = rr
            
            response = header + questions + rr
            
            print(f"buf: {buf}")
            print(f"source: {source}")
            print(f"response: {response}")
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()