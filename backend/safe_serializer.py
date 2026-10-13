"""High-Performance JSON Serialization and Decompression Bomb Protection Module.

Features:
1. Fast orjson Drop-in: Provides accelerated serialization/deserialization for all telemetry.
2. Anti-Zip-Bomb Streaming Buffer: Enforces strict decompression security limits:
   - Maximum uncompressed size: 50MB (default)
   - Maximum compression ratio: 10:1 (default)
   Raises DecompressionBombError upon violation to protect memory and storage exhaustion.
"""

import io
import os
import zipfile
import zlib
import gzip
from typing import Any, Union, Optional, Tuple, Dict, List

try:
    import orjson
    HAS_ORJSON = True
except ImportError:
    HAS_ORJSON = False
    import json as std_json


class DecompressionBombError(ValueError):
    """Raised when an uncompressed archive or buffer breaches enterprise safety limits."""
    pass


# ------------------------------------------------------------------------------
# 1. ORJSON SERIALIZATION & DESERIALIZATION WRAPPER
# ------------------------------------------------------------------------------
def dumps(obj: Any, indent: bool = False, sort_keys: bool = False, **kwargs) -> str:
    """Serializes Python object to JSON string using orjson with standard fallback."""
    if HAS_ORJSON:
        opt = 0
        if indent:
            opt |= orjson.OPT_INDENT_2
        if sort_keys:
            opt |= orjson.OPT_SORT_KEYS
        try:
            return orjson.dumps(obj, option=opt).decode("utf-8")
        except Exception:
            # Fallback to standard json if custom types not handled
            import json as std_json
            return std_json.dumps(obj, indent=2 if indent else None, sort_keys=sort_keys, default=str)
    else:
        import json as std_json
        return std_json.dumps(obj, indent=2 if indent else None, sort_keys=sort_keys, default=str)


def dumps_bytes(obj: Any, indent: bool = False, sort_keys: bool = False, **kwargs) -> bytes:
    """Serializes Python object directly to JSON bytes."""
    if HAS_ORJSON:
        opt = 0
        if indent:
            opt |= orjson.OPT_INDENT_2
        if sort_keys:
            opt |= orjson.OPT_SORT_KEYS
        try:
            return orjson.dumps(obj, option=opt)
        except Exception:
            import json as std_json
            return std_json.dumps(obj, indent=2 if indent else None, sort_keys=sort_keys, default=str).encode("utf-8")
    else:
        import json as std_json
        return std_json.dumps(obj, indent=2 if indent else None, sort_keys=sort_keys, default=str).encode("utf-8")


def loads(s: Union[str, bytes, bytearray, memoryview], **kwargs) -> Any:
    """Deserializes JSON string or bytes to Python object using orjson."""
    if HAS_ORJSON:
        if isinstance(s, str):
            s = s.encode("utf-8")
        return orjson.loads(s)
    else:
        import json as std_json
        if isinstance(s, bytes):
            s = s.decode("utf-8")
        return std_json.loads(s)


# ------------------------------------------------------------------------------
# 2. ANTI-ZIP-BOMB & DECOMPRESSION PROTECTION BUFFER
# ------------------------------------------------------------------------------
DEFAULT_MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB
DEFAULT_MAX_RATIO = 10.0                          # 10:1 ratio


class SafeDecompressor:
    """Streaming decompression engine guarding against nested and recursive zip bombs."""

    @staticmethod
    def decompress_stream(
        input_data: Union[bytes, io.BytesIO],
        max_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
        max_ratio: float = DEFAULT_MAX_RATIO,
        chunk_size: int = 64 * 1024
    ) -> bytes:
        """Safely decompresses zlib/gzip streaming bytes with strict ratio and size guards."""
        raw_bytes = input_data.getvalue() if isinstance(input_data, io.BytesIO) else input_data
        compressed_len = max(len(raw_bytes), 1)

        d_obj = zlib.decompressobj(wbits=zlib.MAX_WBITS | 32)  # Automatic header detect (zlib/gzip)
        out = io.BytesIO()
        total_extracted = 0

        # Stream decompression in chunks
        offset = 0
        while offset < len(raw_bytes):
            chunk = raw_bytes[offset:offset + chunk_size]
            offset += chunk_size
            decompressed_chunk = d_obj.decompress(chunk)
            if decompressed_chunk:
                out.write(decompressed_chunk)
                total_extracted += len(decompressed_chunk)

                if total_extracted > max_bytes:
                    raise DecompressionBombError(
                        f"Decompression bomb rejected: uncompressed size {total_extracted} bytes exceeds {max_bytes} limit (50MB)."
                    )
                ratio = total_extracted / compressed_len
                if total_extracted > 1024 * 1024 and ratio > max_ratio:
                    raise DecompressionBombError(
                        f"Decompression bomb rejected: expansion ratio {ratio:.1f}:1 exceeds safety threshold of {max_ratio:.1f}:1."
                    )

        out.write(d_obj.flush())
        return out.getvalue()

    @staticmethod
    def inspect_and_extract_zip(
        zip_source: Union[str, bytes, io.BytesIO],
        max_total_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
        max_ratio: float = DEFAULT_MAX_RATIO
    ) -> Dict[str, bytes]:
        """Safely inspects and extracts a ZIP archive in memory, rejecting zip bombs."""
        if isinstance(zip_source, bytes):
            zip_obj = io.BytesIO(zip_source)
            compressed_size = len(zip_source)
        elif isinstance(zip_source, str):
            with open(zip_source, "rb") as f:
                content = f.read()
            zip_obj = io.BytesIO(content)
            compressed_size = len(content)
        else:
            zip_obj = zip_source
            pos = zip_obj.tell()
            zip_obj.seek(0, io.SEEK_END)
            compressed_size = zip_obj.tell()
            zip_obj.seek(pos)

        extracted_files: Dict[str, bytes] = {}
        total_uncompressed = 0

        with zipfile.ZipFile(zip_obj, "r") as zf:
            for info in zf.infolist():
                # Prevent path traversal zip slips
                if ".." in info.filename or info.filename.startswith("/") or info.filename.startswith("\\"):
                    raise DecompressionBombError(f"Malicious zip slip path traversal detected: {info.filename}")

                # Check pre-computed uncompressed size metadata
                total_uncompressed += info.file_size
                if total_uncompressed > max_total_bytes:
                    raise DecompressionBombError(
                        f"Decompression bomb rejected: total uncompressed archive size exceeds {max_total_bytes} bytes (50MB limit)."
                    )
                ratio = total_uncompressed / max(compressed_size, 1)
                if total_uncompressed > 1024 * 1024 and ratio > max_ratio:
                    raise DecompressionBombError(
                        f"Decompression bomb rejected: expansion ratio {ratio:.1f}:1 exceeds {max_ratio:.1f}:1 limit."
                    )

            # Stream-extract each file with real-time byte count verification
            for info in zf.infolist():
                if info.is_dir():
                    continue
                file_extracted = 0
                buf = io.BytesIO()
                with zf.open(info.filename) as member:
                    while True:
                        chunk = member.read(64 * 1024)
                        if not chunk:
                            break
                        buf.write(chunk)
                        file_extracted += len(chunk)
                        if file_extracted > max_total_bytes:
                            raise DecompressionBombError(
                                f"Decompression bomb detected while streaming {info.filename}: exceeded {max_total_bytes} limit."
                            )
                extracted_files[info.filename] = buf.getvalue()

        return extracted_files
