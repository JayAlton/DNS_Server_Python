import socket

import struct
from dataclasses import dataclass
from typing import ClassVar


@dataclass
class DNSMessage:
    id: int
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

    ID_LEN: ClassVar[int] = 16
    QR_LEN: ClassVar[int] = 1
    OP_CODE_LEN: ClassVar[int] = 4    
    AA_LEN: ClassVar[int] = 1
    TC_LEN: ClassVar[int] = 1
    RD_LEN: ClassVar[int] = 1
    RA_LEN: ClassVar[int] = 1
    Z_LEN: ClassVar[int] = 3
    RCODE_LEN: ClassVar[int] = 4
    QDCOUNT_LEN: ClassVar[int] = 16
    ANCOUNT_LEN: ClassVar[int] = 16
    NSCOUNT_LEN: ClassVar[int] = 16
    ARCOUNT_LEN: ClassVar[int] = 16

    def serialize(self) -> str:
        # assumes bit endian
        combined1 = 0
        cur_shift = 0
        for val, delta_shift in zip(
            (self.rd, self.tc, self.aa, self.op_code, self.qr),
            (
                DNSMessage.RD_LEN,
                DNSMessage.TC_LEN,
                DNSMessage.AA_LEN,
                DNSMessage.OP_CODE_LEN,
                0,
            ),
        ):
            combined1 |= val << cur_shift
            cur_shift += delta_shift
        
        # assume big endian
        combined2 = 0
        cur_shift = 0
        for val, delta_shift in zip (
            (self.rcode, self.z, self.ra),
            (DNSMessage.RCODE_LEN, DNS_Message.Z_LEN, DNS_Message.RA_LEN),
        ):
            combined2 |= val << cur_shift
            cur_shift += delta_shift
            
        return struct.pack(
            ">HHHHHH",
            self.id,
            combined1,
            combined2,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

def encode_url(url):
    response = b""
    domains = url.split(".")
    for domain in domains:
        response += struct.pack(">B", len(domain))
        response += b"".join((struct.pack(">B", ord(char)) for char in domain))

    response += struct.pack(">B", 0)
    return response

def main():
    RDLENGTH = 4
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # Uncomment this block to pass the first stage
    
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    type_dict_python_int = {"A": 1}
    type_dict = {k: struct.pack(">H", v) for k, v in type_dict_python_int.items()}
    
    class_dict_python_int = {"IN": 1}
    class_dict = {k: struct.pack(">H", v) for k, v in class_dict_python_int.items()}
    
    first = true

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            response = b""
            if first:
                response_data = DNSMessage(
                    id=1234,
                    qr=1,
                    opcode=0,
                    aa=0,
                    tc=0,
                    rd=0,
                    ra=0,
                    z=0,
                    rcode=0,
                    qdcount=qdcount,
                    ancount=1,
                    nscount=0,
                    arcount=0,
                )
            response = response_data.serialize()
            question = encode_url("codecrafters.io") + type_dict["A"] + class_dict["IN"]
            response += question

            answer = (
                encode_url("codecrafters.io")
                + type_dict["A"]
                + class_dict["IN"]
                + struct.pack(">I", 60)
                + struct.pack(">H", RDLENGTH)
                + struct.pack(">BBBB", 8, 8, 8, 8)
            )
            response += answer

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
