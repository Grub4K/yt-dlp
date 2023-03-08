from base64 import b64decode
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO

from Cryptodome.Hash import SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15

# Ref: https://datatracker.ietf.org/doc/html/rfc4880
# Ref: https://datatracker.ietf.org/doc/html/rfc4880#section-4.3


@dataclass
class PublicKey:
    key: ...
    description: str


@dataclass
class Signature:
    hash_algorithm: ...
    description: str
    trailer: bytes
    integrity: bytes
    data: bytes
    key_id: str


def parse_message(data):
    data = BytesIO(unarmor(data))
    while True:
        byte = data.read(1)
        if not byte:
            break

        # Ref: https://datatracker.ietf.org/doc/html/rfc4880#section-4.2
        header = ord(byte)
        assert header & 0b1000_0000, 'Initial bit must always be set'

        length_type = header & 0b0000_0011
        assert length_type != 0b11, 'Streams are not supported'

        if header & 0b0100_0000:
            if length_type == 1:
                length = ord(data.read(1))
            elif length_type == 2:
                octet_a, octet_b = data.read(2)
                length = ((octet_a - 192) << 8) + octet_b + 192
            else:
                assert data.read(1) == b'\xFF'
                length = ord(data.read(1))
        else:
            length = int.from_bytes(data.read(1 << length_type), 'big')

        packet_type = (header >> 2) & 0xF
        yield packet_type, data.read(length)


def unarmor(message):
    message = message.strip()
    if message[:3] != b'---':
        return message

    lines = message.splitlines()
    lines_iter = iter(lines[1:-2])
    # TODO: Implement simple armor checksum
    # checksum = lines[-2]

    # Skip armored header
    for line in lines_iter:
        if not line.strip():
            break

    return b64decode(b''.join(lines_iter))


def _read_mpi(stream):
    # Ref: https://datatracker.ietf.org/doc/html/rfc4880#section-3.2
    return stream.read((int.from_bytes(stream.read(2), 'big') + 7) // 8)


def parse_public_key_packet(data):
    # Ref: https://datatracker.ietf.org/doc/html/rfc4880#section-5.5.2
    stream = BytesIO(data)
    assert ord(stream.read(1)) == 4, 'Only v4 keys supported'

    created_timestamp = int.from_bytes(stream.read(4), 'big')
    created_at = datetime.fromtimestamp(created_timestamp, tz=timezone.utc)

    assert ord(stream.read(1)) == 1, 'Only RSA key algorithm is supported'

    n = _read_mpi(stream)
    e = _read_mpi(stream)
    key = RSA.construct((int.from_bytes(n, 'big'), int.from_bytes(e, 'big')))
    return PublicKey(key, f'RSA @ {created_at.strftime("%Y-%m-%d %H:%M:%S")}')


def parse_signature_packet(data):
    # Ref: https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3
    stream = BytesIO(data)
    header = stream.read(6)
    version, sig_type, pkey_alg, hash_alg, *hashed_length = header
    assert version == 4, 'Only v4 signatures supported'
    # Ref: https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.1
    assert sig_type == 0, 'Only binary signatures supported'
    # Ref: https://datatracker.ietf.org/doc/html/rfc4880#section-9.1
    assert pkey_alg == 1, 'Only RSA signatures supported'
    # Ref: https://datatracker.ietf.org/doc/html/rfc4880#section-9.4
    assert hash_alg == 10, 'Only SHA512 signatures supported'
    hashed_data = stream.read(int.from_bytes(hashed_length, 'big'))
    unhashed_data = stream.read(int.from_bytes(stream.read(2), 'big'))
    key_id = ' '.join(f'{byte:02X}' for byte in unhashed_data[2:])

    integrity = stream.read(2)

    # Algorithm specific MPI count for RSA
    signature = _read_mpi(stream) + _read_mpi(stream)

    trailer = header + hashed_data
    return Signature(
        SHA512, f'SHA512 (type=0x{sig_type:02X})',
        trailer + b'\x04\xFF' + len(trailer).to_bytes(4, 'big'),
        integrity, signature, key_id)


def rsa_key_from_message(stream):
    parsed_stream = iter(parse_message(stream))

    key = None
    for packet_type, data in parsed_stream:
        if packet_type == 6:
            key = parse_public_key_packet(data)
            break
    assert key, 'One public key block is required'

    for packet_type, data in parsed_stream:
        if packet_type == 13:
            key.description = f'{key.description} by {data.decode()}'

    return key


def signature_from_message(stream):
    [(packet_type, data)] = parse_message(stream)
    assert packet_type == 2, 'Invalid packet count for signature'
    return parse_signature_packet(data)


def verify(data, signature, key):
    # Ref: https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.4
    message_hash = signature.hash_algorithm.new()
    message_hash.update(data)
    message_hash.update(signature.trailer)
    if message_hash.digest()[:2] != signature.integrity:
        # Failed signature integrity check
        return False

    try:
        pkcs1_15.new(key.key).verify(message_hash, signature.data)
        return True
    except ValueError:
        return False
