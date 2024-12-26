import socket
import struct

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            # Unpack the DNS query header
            id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
                "!HHHHHH", buf[:12]
            )

            # Extract the opcode and rcode from the flags field
            opcode = (flags >> 11) & 0x0F  # Extract opcode (bits 11-14)
            rcode = flags & 0x0F  # Extract Rcode (bits 0-3)

            print(f"Received Opcode: {opcode}, Rcode: {rcode}")

            # Check if it's an IQUERY (Opcode 1)
            if opcode == 1:  # IQUERY
                print(f"Received IQUERY (opcode 1), changing Rcode to 4 (NOTIMP) and changing to QUERY response.")
                rcode = 4  # Set Rcode to 4 for IQUERY (Not Implemented)
                opcode = 0  # Change Opcode to QUERY for the response

            # Construct DNS response
            name = b"\x0ccodecrafters\x02io\x00"
            qtype = struct.pack("!H", 1)  # Type A (IPv4 address)
            qclass = struct.pack("!H", 1)  # Class IN (Internet)
            question = name + qtype + qclass
            
            # Modify flags for the response (QR = 1, set the appropriate opcode and rcode)
            flags &= 0x7FFF  # Clear QR bit
            flags |= 0x8000  # Set QR bit to 1 for response
            flags &= 0xFF0F  # Clear the current Rcode (lower 4 bits)
            flags |= (rcode & 0x0F)  # Set the new Rcode
            flags |= (opcode << 11)  # Set the new Opcode (shifted by 11 bits)

            # Create the DNS response header with the updated flags, opcode, and rcode
            response = struct.pack(
                "!6H", id, flags, qdcount, 1, nscount, arcount
            )
            
            # Add the question section (same as in the query)
            response += question
            # Add the answer section (codecrafters.io -> 8.8.8.8)
            response += name
            response += struct.pack("!2H", 1, 0x0001)  # TYPE and CLASS
            response += struct.pack("!I", 60)  # TTL
            response += struct.pack("!H", 4)  # RDLENGTH (4 bytes for IPv4)
            response += socket.inet_aton("8.8.8.8")  # RDATA (IP address 8.8.8.8)

            # Send the DNS response
            udp_socket.sendto(response, source)

        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
