from typing import Union, Mapping, Iterable, get_type_hints
import hashlib
import binascii
import json


def sha256d(s: Union[str, bytes]) -> str:
    """A double SHA-256 hash."""
    if not isinstance(s, bytes):
        s = s.encode()

    return hashlib.sha256(hashlib.sha256(s).digest()).hexdigest()


def serialize(obj) -> str:
    """NamedTuple-flavord serliazation to JSON."""
    def contents_to_primitive(o):
        if hasattr(o, '_asdict'):
            o = {**o._asdict(), '_type': type(o).__name__}
        elif isinstance(o, (list, tuple)):
            return [contents_to_primitive(i) for i in o]
        elif isinstance(o, bytes):
            return binascii.hexlify(o).decode()
        elif not isinstance(o, (dict, bytes, str, int, type(None))):
            raise ValueError(f"Can't serialize {o}")

        if isinstance(o, Mapping):
            for key, value in o.items():
                o[key] = contents_to_primitive(value)

        return o

    return json.dumps(
        contents_to_primitive(obj), sort_keys=True, separators=(',', ':')
    )


def chunks(l, n) -> Iterable[Iterable]:
    return (l[i:i+n] for i in range(0, len(l), n))


def deserialize(serialized: str) -> object:
    """NamedTuple-flavored serialization from JSON."""
    gs = globals()

    def contents_to_objs(o):
        if isinstance(o, list):
            return [contents_to_objs(i) for i in o]
        elif not isinstance(o, Mapping):
            return o

        _type = gs[o.pop('_type', None)]
        bytes_keys = {
            k for k, v in get_type_hints(_type).items() if v == bytes
        }

        for k, v in o.items():
            o[k] = contents_to_objs(v)

            if k in bytes_keys:
                o[k] = binascii.unhexlify(o[k]) if o[k] else o[k]

        return _type(**o)

    return contents_to_objs(json.loads(serialized))
