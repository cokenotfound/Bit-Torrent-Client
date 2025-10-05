# class BencodeDecoder:
#     """
#     A class to decode BitTorrent's Bencoded data format (used in .torrent files and tracker responses).
#     Supports: strings, integers, lists, and dictionaries.
#     """
#     def __init__(self, data):
#         # We use a bytearray for data to allow efficient slicing and reading
#         if isinstance(data, str):
#             self.data = bytearray(data, 'latin-1')
#         elif isinstance(data, bytes):
#             self.data = bytearray(data)
#         else:
#             raise TypeError("Input data must be bytes or string.")
#         self.offset = 0

#     def decode(self):
#         """
#         Starts the decoding process and returns the decoded Python object.
#         """
#         if self.offset >= len(self.data):
#             return None
        
#         # Check the starting character to determine the data type
#         return self._decode_next()

#     def _decode_next(self):
#         """
#         Decodes the next item based on the current offset.
#         """
#         start_char = chr(self.data[self.offset])

#         if start_char == 'i': # Integer
#             return self._decode_int()
#         elif start_char == 'l': # List
#             return self._decode_list()
#         elif start_char == 'd': # Dictionary
#             return self._decode_dict()
#         elif start_char.isdigit(): # String (preceded by length)
#             return self._decode_string()
#         else:
#             raise ValueError(f"Invalid bencoded character at {self.offset}: {start_char}")

#     def _decode_int(self):
#         """
#         Format: i<integer>e
#         """
#         self.offset += 1  # Skip 'i'
#         end_index = self.data.find(b'e', self.offset)
#         if end_index == -1:
#             raise ValueError("Invalid integer format: missing 'e'")

#         int_bytes = self.data[self.offset:end_index]
#         self.offset = end_index + 1  # Move past 'e'
#         return int(int_bytes.decode('ascii'))

#     def _decode_string(self):
#         """
#         Format: <length>:<string_bytes>
#         """
#         colon_index = self.data.find(b':', self.offset)
#         if colon_index == -1:
#             raise ValueError("Invalid string format: missing ':'")

#         length_bytes = self.data[self.offset:colon_index]
#         length = int(length_bytes.decode('ascii'))
#         self.offset = colon_index + 1 # Move past ':'

#         string_data = self.data[self.offset:self.offset + length]
#         self.offset += length

#         # Strings in Bencoding can be arbitrary byte sequences,
#         # so we return them as bytes (required for info hash calculation later)
#         return bytes(string_data)

#     def _decode_list(self):
#         """
#         Format: l<item1><item2>...e
#         """
#         self.offset += 1  # Skip 'l'
#         result = []
#         while chr(self.data[self.offset]) != 'e':
#             result.append(self._decode_next())
#         self.offset += 1 # Skip 'e'
#         return result

#     def _decode_dict(self):
#         """
#         Format: d<key1><value1><key2><value2>...e
#         """
#         self.offset += 1 # Skip 'd'
#         result = {}
#         while chr(self.data[self.offset]) != 'e':
#             # Keys MUST be strings (bytes in Python 3)
#             key = self._decode_string()
#             value = self._decode_next()
#             result[key] = value
#         self.offset += 1 # Skip 'e'
#         return result




        
import sys
import struct

class BencodeDecoder:
    """
    A class to decode BitTorrent's proprietary Bencode format.
    Handles integers (i), lists (l), dictionaries (d), and byte strings.
    """
    def __init__(self, data):
        # Ensure data is bytes for binary handling
        if isinstance(data, str):
            data = data.encode('utf-8', errors='ignore')
        self.data = data
        self.offset = 0

    def _decode_next(self):
        """Determines the type of the next object and calls the appropriate decoder."""
        if self.offset >= len(self.data):
            raise IndexError("Unexpected end of Bencoded data.")

        char = chr(self.data[self.offset])

        if char == 'i':
            return self._decode_int()
        elif char == 'l':
            return self._decode_list()
        elif char == 'd':
            return self._decode_dict()
        elif char.isdigit():
            return self._decode_string()
        else:
            raise ValueError(f"Unknown Bencode type identifier: {char} at offset {self.offset}")

    def _decode_int(self):
        """Decodes an integer (format: i<integer>e)."""
        # Skip 'i'
        self.offset += 1
        try:
            end_index = self.data.index(b'e', self.offset)
            int_bytes = self.data[self.offset:end_index]
            value = int(int_bytes.decode('ascii'))
            self.offset = end_index + 1
            return value
        except ValueError:
            raise ValueError("Invalid integer format: closing 'e' not found.")
        except IndexError:
            raise IndexError("Integer started but data ended prematurely.")

    def _decode_string(self):
        """Decodes a byte string (format: <length>:<string_bytes>)."""
        try:
            colon_index = self.data.index(b':', self.offset)
            length_bytes = self.data[self.offset:colon_index]
            length = int(length_bytes.decode('ascii'))

            # Move offset past the colon
            self.offset = colon_index + 1

            # Read the string bytes
            end_index = self.offset + length
            if end_index > len(self.data):
                raise IndexError("String length exceeds remaining data.")

            string_bytes = self.data[self.offset:end_index]
            self.offset = end_index
            return string_bytes
        except ValueError:
            raise ValueError("Invalid string format: colon not found.")

    def _decode_list(self):
        """Decodes a list (format: l<item1><item2>...e)."""
        # Skip 'l'
        self.offset += 1
        result = []
        while self.data[self.offset:self.offset + 1] != b'e':
            result.append(self._decode_next())
        # Skip 'e'
        self.offset += 1
        return result

    def _decode_dict(self):
        """Decodes a dictionary (format: d<key1><value1>...e). Keys must be strings."""
        # Skip 'd'
        self.offset += 1
        result = {}
        while self.data[self.offset:self.offset + 1] != b'e':
            key = self._decode_string()  # Keys must be byte strings
            value = self._decode_next()
            result[key] = value
        # Skip 'e'
        self.offset += 1
        return result

    def decode(self):
        """Starts the decoding process and returns the fully decoded object."""
        return self._decode_next()

# Helper function to recursively re-bencode the 'info' dictionary
def _re_bencode(data):
    """Recursively bencode a Python object back into bytes."""
    if isinstance(data, int):
        return f"i{data}e".encode('ascii')
    elif isinstance(data, bytes):
        return f"{len(data)}:".encode('ascii') + data
    elif isinstance(data, list):
        encoded = b"l"
        for item in data:
            encoded += _re_bencode(item)
        return encoded + b"e"
    elif isinstance(data, dict):
        encoded = b"d"
        # Keys must be sorted before bencoding, as per specification
        for key in sorted(data.keys()):
            encoded += _re_bencode(key)
            encoded += _re_bencode(data[key])
        return encoded + b"e"
    else:
        raise TypeError(f"Unsupported type for bencoding: {type(data)}")

def get_bencoded_info(torrent_dict):
    """
    Extracts the raw bencoded bytes of the 'info' dictionary for SHA1 hashing.
    This bypasses re-parsing and is the most reliable way to get the exact bytes
    that define the info hash.
    """
    try:
        # Find the start and end indices of the 'info' dictionary in the raw data
        # 'info' must be bencoded first: 4:info (length:key)
        info_key = b'4:info'
        info_start = torrent_dict.data.find(info_key) + len(info_key)
        
        # We need to find the matching 'e' for the 'd' that follows '4:info'.
        # Since this is complex, we will rely on re-bencoding the parsed structure
        # for maximum safety, even though it's less direct.
        info_dict = torrent_dict.decode()
        if b'info' in info_dict:
            # Re-bencode the structure to get the exact bytes required for hashing
            return _re_bencode(info_dict[b'info'])
        else:
            raise ValueError("Torrent file does not contain 'info' dictionary.")
    except Exception as e:
        # Fallback to the recursive re-bencode of the parsed info dictionary
        if b'info' in torrent_dict.decode():
             return _re_bencode(torrent_dict.decode()[b'info'])
        raise e
