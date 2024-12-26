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

            # Extract the current opcode (from the flags field)
            opcode = (flags >> 11) & 0x0F  # Extract opcode from flags (top 4 bits)
            rcode = flags & 0x0F  # Extract Rcode from the lower 4 bits of flags

            # Handle different opcodes
            if opcode == 0:  # Standard Query (QUERY)
                print(f"Received QUERY (opcode 0), responding normally.")
                rcode = 0  # Set Rcode to NOERROR
            elif opcode == 1:  # Inverse Query (IQUERY)
                print(f"Received IQUERY (opcode 1), changing to QUERY response")
                opcode = 0  # Change to QUERY response
                rcode = 0  # Set Rcode to NOERROR
            elif opcode == 2:  # Status Query (STATUS)
                print(f"Received STATUS Query (opcode 2), responding with STATUS response.")
                opcode = 2  # Ensure the response opcode is 2
                rcode = 0  # Set Rcode to NOERROR for STATUS queries
            else:
                print(f"Unknown Opcode {opcode}, responding with QUERY.")
                opcode = 0  # Default to QUERY for unknown opcodes
                rcode = 0  # Set Rcode to NOERROR for unknown queries

            # Add the question section (codecrafters.io, IN, A)
            name = b"\x0ccodecrafters\x02io\x00"
            qtype = struct.pack("!H", 1)  # Type A (IPv4 address)
            qclass = struct.pack("!H", 1)  # Class IN (Internet)
            question = name + qtype + qclass
            
            # Modify the flags to indicate a response (QR = 1) and set the appropriate opcode
            flags &= 0x7FFF  # Clear the QR bit
            flags |= 0x8000  # Set the QR bit to 1 for response
            flags |= (opcode << 11)  # Set the correct opcode in the flags

            # Set the Rcode (Response Code) based on the incoming query's flags
            flags &= 0xFF0F  # Clear the Rcode bits (lower 4 bits)
            flags |= (rcode & 0x0F)  # Set the Rcode (lower 4 bits)

            # Create the DNS response header with the appropriate flags and opcode
            response = struct.pack(
                "!6H", id, flags, qdcount, 1, nscount, arcount
            )
            
            # Add the question section to the response (same as in the query)
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
