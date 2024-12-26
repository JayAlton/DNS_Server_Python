import socket
from ipaddress import IPv4Address
from .dns_message import ARecord, Message, Question, RecordType, RecordClass


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # Uncomment this block to pass the first stage
    #
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    print("Listening on port 2053...")

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
    
            id = int.from_bytes(buf[:2], "big")
            replyMessage = Message.build_reply(
                id = id,
                questions=[
                    Question(
                        name="codecrafters.io",
                        type=RecordType.A,
                        klass=RecordClass.IN,
                    )
                ],
                resource_records=[
                    ARecord("codecrafters.io", 60, IPv4Address("192.168.1.1"))
                ],
            )

            
            print(reply_message.to_bytes())
            print(len(reply_message.to_bytes()))
    
            udp_socket.sendto(reply_message.to_bytes(), source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break



if __name__ == "__main__":
    main()