import struct
from ipaddress import IPv4Address

# Define DNS Record Types and Classes
class RecordType:
    A = 1    # A record (IPv4 Address)

class RecordClass:
    IN = 1   # Internet class (IN)

# DNS Message Format
class Question:
    def __init__(self, name, type, klass):
        self.name = name
        self.type = type
        self.klass = klass

    def to_bytes(self):
        # Convert the name to DNS wire format (length-prefixed labels)
        labels = self.name.split('.')
        byte_name = b''.join([bytes([len(label)]) + label.encode() for label in labels])
        byte_name += b'\0'  # Null byte to end the name
        # Pack the Question as per DNS specification
        return byte_name + struct.pack('>HH', self.type, self.klass)

class ARecord:
    def __init__(self, name, ttl, address):
        self.name = name
        self.ttl = ttl
        self.address = address

    def to_bytes(self):
        # Convert the name to DNS wire format (length-prefixed labels)
        labels = self.name.split('.')
        byte_name = b''.join([bytes([len(label)]) + label.encode() for label in labels])
        byte_name += b'\0'  # Null byte to end the name
        # Convert IPv4 address to packed binary format
        address_bytes = self.address.packed
        # Pack the A record as per DNS specification
        return byte_name + struct.pack('>HHIH', RecordType.A, RecordClass.IN, self.ttl, len(address_bytes)) + address_bytes

class Message:
    def __init__(self, id, flags, questions, answers):
        self.id = id
        self.flags = flags
        self.questions = questions
        self.answers = answers

    @staticmethod
    def build_reply(id, id_query, questions, resource_records):
        flags = 0x8180  # Standard DNS flags for a reply (QR = 1, AA = 1, etc.)
        # Create a new message
        message = Message(id, flags, questions, resource_records)
        return message

    def to_bytes(self):
        # Header
        header = struct.pack('>HHHHHH', self.id, self.flags, len(self.questions), len(self.answers), 0, 0)
        
        # Questions section
        question_bytes = b''.join([q.to_bytes() for q in self.questions])
        
        # Answers section
        answer_bytes = b''.join([rr.to_bytes() for rr in self.answers])
        
        return header + question_bytes + answer_bytes

