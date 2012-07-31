def parse_name(payload, offset):
    name = []

    for i in range(100):
        n = payload[offset]
        offset += 1

        if n == 0:
            break
        elif (n & 0xc0) == 0xc0:
            ptr = unpack('>H', payload[offset - 1:offset + 1])[0] & 0x3fff
            offset += 1
            name.append(parse_name(payload, ptr)[0])
            break
        else:
            name.append(payload[offset:offset + n].decode('utf-8'))
            offset += n

    return '.'.join(name), offset

def pack_name(name):
    names = name.split('.')
    payload = b''

    for name in names:
        payload += (chr(len(name)) + name).encode('utf-8')

    return payload + chr(0).encode('utf-8')

