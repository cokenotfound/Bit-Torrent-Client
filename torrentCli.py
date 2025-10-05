import sys
import hashlib
import random
import string
import urllib.parse
import urllib.request
import socket
import struct
import threading
import time
import os # Added for file handling

# --- 1. Bencoding Decoder Implementation (Imported) ---
# Ensure 'bencode_decoder.py' is in the same directory!
from bencode_decoder import BencodeDecoder 

# --- GLOBAL CONSTANTS ---

# Message IDs defined by the BitTorrent Peer Wire Protocol
MESSAGE_IDS = {
    0: 'choke',
    1: 'unchoke',
    2: 'interested',
    3: 'not interested',
    5: 'bitfield',
    6: 'request',
    7: 'piece',
    10: 'keep-alive'
}

# --- THREADING/CONCURRENCY GLOBAL STATE ---
successful_connections = []
handshake_lock = threading.Lock()
MAX_SUCCESSFUL_CONNECTIONS = 3
MAX_HANDSHAKE_ATTEMPTS = 30 # Increased attempts for better success rate

# --- DOWNLOAD PROGRESS STATE ---
pieces_completed = 0
total_pieces = 0
progress_lock = threading.Lock()
client_running = threading.Event() # For safe thread termination

# --- 2. Client Utility Functions (Torrent Parsing & Tracker Communication) ---

def generate_peer_id():
    """Generates a 20-byte Peer ID for client identification."""
    random_bytes = ''.join(random.choices(string.ascii_letters + string.digits, k=18))
    return ('-PY0001-' + random_bytes).encode('latin-1')[:20]

def calculate_info_hash(info_dict):
    """Calculates the SHA1 hash of the bencoded 'info' dictionary."""
    def bencode_single(obj):
        """Internal function to bencode a single object for hashing."""
        if isinstance(obj, int):
            return f"i{obj}e".encode('ascii')
        elif isinstance(obj, bytes):
            return f"{len(obj)}:".encode('ascii') + obj
        elif isinstance(obj, list):
            content = b''.join(bencode_single(item) for item in obj)
            return b'l' + content + b'e'
        elif isinstance(obj, dict):
            content = b''
            # Keys MUST be bencoded strings (bytes) and sorted lexicographically
            for key in sorted(obj.keys()):
                content += bencode_single(key)
                content += bencode_single(obj[key])
            return b'd' + content + b'e'
        else:
            raise TypeError(f"Unsupported type for bencoding: {type(obj)}")

    info_bencoded = bencode_single(info_dict)
    return hashlib.sha1(info_bencoded).digest()

def parse_torrent_file(filepath):
    """Reads, decodes, and extracts essential data and all trackers from the .torrent file."""
    try:
        with open(filepath, 'rb') as f:
            torrent_raw_data = f.read()
    except FileNotFoundError:
        print(f"Error: Torrent file not found at {filepath}")
        return None

    try:
        decoder = BencodeDecoder(torrent_raw_data)
        torrent_data = decoder.decode()
    except Exception as e:
        print(f"Error decoding Bencode data: {e}")
        return None

    info = torrent_data.get(b'info')
    if not info:
        print("Error: Torrent file is missing 'info' dictionary.")
        return None

    info_hash = calculate_info_hash(info)
    
    # Extract all trackers from 'announce' and 'announce-list'
    trackers = []
    if torrent_data.get(b'announce'):
        trackers.append(torrent_data[b'announce'])
    announce_list = torrent_data.get(b'announce-list', [])
    for tier in announce_list:
        if isinstance(tier, list):
            for tracker_url in tier:
                if isinstance(tracker_url, bytes) and tracker_url not in trackers:
                    trackers.append(tracker_url)
    
    # Simplified length calculation (assumes single file)
    total_size = info.get(b'length', 0)
    
    return {
        'trackers': trackers,
        'info_hash': info_hash,
        'info': info,
        'length': total_size,
        'piece_length': info.get(b'piece length', 0),
        'pieces_raw': info.get(b'pieces', b'') # Raw concatenated SHA1 hashes
    }

def create_tracker_url(torrent_data, peer_id, tracker_url_str, port=6881, uploaded=0, downloaded=0, left=None):
    """Constructs the URL for the HTTP GET request."""
    if left is None:
        left = torrent_data['length']

    # Use list of tuples for correct single encoding of binary data
    params = [
        ('info_hash', torrent_data['info_hash']),
        ('peer_id', peer_id),
        ('port', port),
        ('uploaded', uploaded),
        ('downloaded', downloaded),
        ('left', left),
        ('compact', 1),
        ('event', 'started') 
    ]
    query_string = urllib.parse.urlencode(params)
    return f"{tracker_url_str}?{query_string}"

def decode_peers(peers_bytes):
    """Parses the compact peer list (6 bytes per peer: 4 for IP, 2 for Port)."""
    peers = []
    if len(peers_bytes) % 6 != 0:
        print("Warning: Compact peer list length is not a multiple of 6.")
        return peers

    for i in range(0, len(peers_bytes), 6):
        peer_data = peers_bytes[i:i+6]
        ip_int = struct.unpack('>I', peer_data[:4])[0]
        ip_address = socket.inet_ntoa(struct.pack('>I', ip_int))
        port = struct.unpack('>H', peer_data[4:6])[0]
        peers.append({'ip': ip_address, 'port': port})
    return peers

def _get_peers_from_http_tracker(tracker_url):
    """Handles communication with HTTP trackers."""
    print(f"Attempting to contact HTTP tracker: {tracker_url[:80]}...")
    try:
        with urllib.request.urlopen(tracker_url, timeout=10) as response:
            tracker_response_data = response.read()
    except Exception as e:
        print(f"Error contacting HTTP tracker: {e}")
        return None

    try:
        response_dict = BencodeDecoder(tracker_response_data).decode()
        if b'failure reason' in response_dict:
            print(f"Tracker returned failure: {response_dict[b'failure reason'].decode()}")
            return None

        peers_bytes = response_dict.get(b'peers')
        if not peers_bytes or not isinstance(peers_bytes, bytes):
            print("Tracker response is missing the compact 'peers' list.")
            return None

        peers = decode_peers(peers_bytes)
        print(f"\n--- HTTP Tracker Response Received ---")
        print(f"Found {len(peers)} peers.")
        print("--------------------------------------")
        return peers
    except Exception as e:
        print(f"Error decoding HTTP tracker response: {e}")
        return None

def _send_receive_udp(sock, request, address, expected_length, retries=1):
    """Helper for single UDP send/receive with minimum response check."""
    for attempt in range(retries):
        try:
            sock.sendto(request, address)
            response, _ = sock.recvfrom(2048)
            
            # Check for error message from tracker (Action 3)
            if len(response) >= 8:
                action, _ = struct.unpack('!LL', response[:8])
                if action == 3:
                    error_message = response[8:].decode('latin-1', errors='ignore')
                    raise Exception(f"UDP Tracker Error: {error_message}")
            
            if len(response) >= expected_length:
                return response
            else:
                raise socket.timeout(f"Received incomplete packet ({len(response)} bytes).")
            
        except socket.timeout:
            # Only raises timeout exception if all retries (currently 1) fail
            raise socket.timeout(f"Timeout after {retries} attempt(s).")
        except Exception:
            raise 
    
    raise socket.timeout(f"Failed to receive valid response from UDP tracker after {retries} attempt(s).")

def _get_peers_from_udp_tracker(tracker_url_str, torrent_info, peer_id, client_port=6881, timeout=10):
    """Handles the two-step binary communication (Connect, then Announce) for UDP trackers (BEP 15)."""
    RETRY_ATTEMPTS = 1
    
    try:
        parsed_url = urllib.parse.urlparse(tracker_url_str)
        tracker_ip = socket.gethostbyname(parsed_url.hostname)
        tracker_addr = (tracker_ip, parsed_url.port)
        
    except Exception as e:
        print(f"Error parsing UDP tracker URL or resolving host: {e}")
        return None

    print(f"Attempting to contact UDP tracker: {tracker_addr[0]}:{tracker_addr[1]} (Timeout: {timeout}s, Retries: {RETRY_ATTEMPTS})...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    transaction_id = random.randint(0, 0xFFFFFFFF)
    
    try:
        # --- STEP 1: CONNECT REQUEST (Action 0) ---
        connection_request = struct.pack('!QLL', 0x41727101980, 0, transaction_id)
        print(f"  Attempt 1/{RETRY_ATTEMPTS}...")
        connection_response = _send_receive_udp(sock, connection_request, tracker_addr, 16, retries=RETRY_ATTEMPTS)
        
        action, response_tid, connection_id = struct.unpack('!LLQ', connection_response)
        if action != 0 or response_tid != transaction_id:
            print("UDP Connect failed: Invalid action or transaction ID in response.")
            return None

        # --- STEP 2: ANNOUNCE REQUEST (Action 1) ---
        action = 1
        transaction_id = random.randint(0, 0xFFFFFFFF)
        event = 2  # 'started' event
        NUM_WANT_UNLIMITED = 0xFFFFFFFF # Use unsigned representation of -1
        
        announce_request = struct.pack('!QLL20s20sQQQLLLLH',
            connection_id, action, transaction_id,
            torrent_info['info_hash'], peer_id,
            0, torrent_info['length'], 0,
            event, 0, random.randint(0, 0xFFFFFFFF),
            NUM_WANT_UNLIMITED, client_port
        )
        
        print(f"  Attempt 1/{RETRY_ATTEMPTS}...")
        announce_response = _send_receive_udp(sock, announce_request, tracker_addr, 20, retries=RETRY_ATTEMPTS)

        action, response_tid, interval, leechers, seeders = struct.unpack('!LLLLL', announce_response[:20])
        
        if action != 1 or response_tid != transaction_id:
            print("UDP Announce failed: Invalid action or transaction ID in response.")
            return None
            
        peers_bytes = announce_response[20:]
        peers = decode_peers(peers_bytes)

        print(f"\n--- UDP Tracker Response Received ---")
        print(f"Leechers: {leechers}, Seeders: {seeders}")
        print(f"Found {len(peers)} peers.")
        print("--------------------------------------")

        return peers

    except socket.timeout:
        print(f"Error contacting UDP tracker: Timeout after {RETRY_ATTEMPTS} attempt(s).")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during UDP request: {e}")
        return None
    finally:
        sock.close()

def get_peers(torrent_info, peer_id, client_port=6881):
    """Attempts to get peers by iterating through all available trackers."""
    trackers = torrent_info.get('trackers', [])
    if not trackers:
        print("Error: No trackers found in torrent file.")
        return None

    print(f"Found {len(trackers)} trackers. Starting iteration...")
    
    for tracker_url_bytes in trackers:
        try:
            tracker_url_str = tracker_url_bytes.decode('utf-8')
        except UnicodeDecodeError:
            continue

        if tracker_url_str.startswith('http'):
            http_url = create_tracker_url(torrent_info, peer_id, tracker_url_str, client_port)
            peers = _get_peers_from_http_tracker(http_url)
            if peers: return peers
        
        elif tracker_url_str.startswith('udp'):
            peers = _get_peers_from_udp_tracker(tracker_url_str, torrent_info, peer_id, client_port)
            if peers: return peers

    print("\n--- Tracker Summary ---")
    print("Failed to get peers from all listed trackers.")
    return None

# --- PROGRESS DISPLAY LOGIC ---

def display_progress():
    """Displays a CLI progress bar."""
    bar_length = 50
    while not client_running.is_set():
        with progress_lock:
            if total_pieces == 0:
                time.sleep(0.5)
                continue

            fraction = pieces_completed / total_pieces
            filled_length = int(round(bar_length * fraction))
            bar = '█' * filled_length + '-' * (bar_length - filled_length)
            percent = round(fraction * 100, 2)
            
            # Suppress all other output (using \r) and only show the bar
            sys.stdout.write(f'\r[PROGRESS] |{bar}| {percent:.2f}% ({pieces_completed}/{total_pieces}) ')
            sys.stdout.flush()
        
        if pieces_completed == total_pieces:
            break
        
        time.sleep(0.5)
    
    # Print a final line feed to move past the progress bar
    sys.stdout.write('\n')
    sys.stdout.flush()


# --- 3. Peer Handshake Implementation (Concurrent) ---

def perform_handshake(peer, torrent_info, peer_id, timeout=7): # Increased timeout to 7s
    """Attempts to establish a connection and perform the 68-byte handshake."""
    HANDSHAKE_PSTR = b'BitTorrent protocol'
    RESERVED_BYTES = b'\x00' * 8

    handshake_message = struct.pack('!B', len(HANDSHAKE_PSTR)) + \
                        HANDSHAKE_PSTR + \
                        RESERVED_BYTES + \
                        torrent_info['info_hash'] + \
                        peer_id
    
    ip = peer['ip']
    port = peer['port']
    sock = None
    
    try:
        # Increased timeout to 7 seconds for a better chance of response
        sock = socket.create_connection((ip, port), timeout=timeout) 
        sock.sendall(handshake_message)
        response = sock.recv(68)
        
        if len(response) != 68:
            raise Exception(f"Received {len(response)} bytes, expected 68.")

        # Validate Info Hash
        response_info_hash = response[28:48]
        if response_info_hash != torrent_info['info_hash']:
            raise Exception("Info hash mismatch.")
        
        # Handshake successful - LOGGING REMOVED HERE
        return {'socket': sock, 'peer_id': response[48:68], 'ip': ip, 'port': port}
        
    except socket.timeout:
        # Error logging removed
        return None
    except Exception as e:
        # Error logging removed
        if sock: sock.close()
        return None
    finally:
        pass


# --- 4. Peer Wire Protocol Implementation (Download Preparation) ---

class PeerConnection:
    """MAnages the state and message exchange with a single peer."""
    def __init__(self, sock, peer_id, torrent_info, output_filename):
        self.sock = sock
        self.peer_id = peer_id
        self.torrent_info = torrent_info
        self.output_filename = output_filename # Stored here
        
        pieces_raw_len = len(torrent_info['pieces_raw'])
        self.num_pieces = pieces_raw_len // 20
        # FIX: Changed 'piece length' (with space) to 'piece_length' (with underscore)
        self.piece_length = torrent_info['piece_length'] 
        # Calculate expected bitfield size in bytes: ceil(num_pieces / 8)
        self.expected_bitfield_len = (self.num_pieces + 7) // 8

        self.am_choking = True      # We start choked (cannot upload to peer)
        self.am_interested = False  # We start not interested
        self.peer_choking = True    # Peer starts choking us (cannot download from peer)
        self.peer_bitfield = [False] * self.num_pieces # What pieces the peer has
        
        # A list to track pieces we are currently trying to download
        self.pieces_we_have = [False] * self.num_pieces 
        self.downloading = True # State flag for the loop

        # Piece Download State
        self.BLOCK_SIZE = 2**14  # 16 KB standard block size (16384 bytes)
        self.current_piece_index = -1 
        self.current_piece_offset = 0 # Offset for the NEXT block to request
        self.piece_buffer = {} # {offset: data} to store blocks for the current piece
        self.piece_data_size = 0 # Total bytes assembled for the current piece

    def _get_piece_hash(self, index):
        """Extracts the 20-byte SHA1 hash for a given piece index."""
        start = index * 20
        end = start + 20
        return self.torrent_info['pieces_raw'][start:end]

    def send_message(self, message_id, payload=b''):
        """Formats and sends a Peer Wire Protocol message: <length><id><payload>"""
        message_length = 1 + len(payload) 
        message = struct.pack('!I', message_length) + \
                  struct.pack('!B', message_id) + \
                  payload
        
        # Logging removed
        
        try:
            self.sock.sendall(message)
            # Logging removed
        except Exception:
            # Logging removed
            self.close()

    def send_interested(self):
        """Sends the 'interested' message (ID 2)."""
        self.am_interested = True
        self.send_message(2) 
        
    def send_request(self, index, begin, length):
        """Sends a 'request' message (ID 6). Payload: <index><begin><length> (all 4-byte integers)"""
        if self.peer_choking:
            # Logging removed
            return

        payload = struct.pack('!III', index, begin, length)
        self.send_message(6, payload)
        # Logging removed
        self.current_piece_offset += length # Update offset for the next request

    def _get_next_block_request(self):
        """Requests the next block of the current piece."""
        piece_index = self.current_piece_index
        piece_len = self.piece_length
        offset = self.current_piece_offset
        
        if offset < piece_len:
            # Calculate remaining bytes in the piece
            remaining = piece_len - offset
            # Request the smaller of BLOCK_SIZE or the remaining length
            request_length = min(self.BLOCK_SIZE, remaining)
            
            self.send_request(piece_index, offset, request_length)
        else:
            # Logging removed
            pass

    def check_and_request(self):
        """
        Called after UNCHOKE or BITFIELD. If we are unchoked, finds the first
        needed piece that the peer has, and starts the download process.
        """
        if not self.peer_choking and self.am_interested and self.current_piece_index == -1:
            # Find the first piece the peer has and we don't
            piece_index = -1
            for i in range(self.num_pieces):
                if self.peer_bitfield[i] and not self.pieces_we_have[i]:
                    piece_index = i
                    break

            if piece_index != -1:
                # Initialize piece download state
                self.current_piece_index = piece_index
                self.current_piece_offset = 0
                self.piece_buffer = {}
                self.piece_data_size = 0

                # Logging removed
                
                # Request the first block
                self._get_next_block_request()
            else:
                # Logging removed
                self.send_message(3) # Not interested
                self.downloading = False # Stop loop since we can't download from here.

    def _validate_and_write_piece(self):
        """Assembles the piece, validates its hash, and writes it to disk."""
        # FIX: Move global declaration to the start of the function scope
        global pieces_completed 
        
        piece_index = self.current_piece_index
        
        # 1. Assemble the piece from the buffer
        assembled_data = b''.join(self.piece_buffer[offset] for offset in sorted(self.piece_buffer.keys()))
        
        # 2. Validate hash
        expected_hash = self._get_piece_hash(piece_index)
        actual_hash = hashlib.sha1(assembled_data).digest()
        
        if actual_hash == expected_hash:
            # Logging removed
            
            # 3. Write to disk 
            try:
                # Try to open existing file first
                with open(self.output_filename, 'r+b') as f:
                    offset = piece_index * self.piece_length
                    f.seek(offset)
                    f.write(assembled_data)

                self.pieces_we_have[piece_index] = True
                # Logging removed
                
                # 4. Update global progress
                with progress_lock:
                    pieces_completed += 1
                if pieces_completed == total_pieces:
                    print("\n\n[COMPLETED] DOWNLOAD FINISHED!")
                    client_running.set() # Signal main loop to terminate
                    
            except FileNotFoundError:
                # If the file doesn't exist, create it with 'wb' and then write the piece.
                try:
                    with open(self.output_filename, 'wb') as f:
                        f.seek(piece_index * self.piece_length)
                        f.write(assembled_data)
                    self.pieces_we_have[piece_index] = True
                    # Logging removed

                    # Update global progress (Only once for file creation)
                    with progress_lock:
                        pieces_completed += 1
                    if pieces_completed == total_pieces:
                        print("\n\n[COMPLETED] DOWNLOAD FINISHED!")
                        client_running.set() # Signal main loop to terminate
                        
                except Exception:
                    # Logging removed
                    pass
            except Exception:
                 # Logging removed
                 pass


        else:
            # Logging removed
            pass

        # Reset state for the next piece
        self.current_piece_index = -1
        self.current_piece_offset = 0
        self.piece_buffer = {}
        self.piece_data_size = 0
        
    def handle_bitfield(self, bitfield_bytes):
        """Parses the bitfield payload and updates which pieces the peer has."""
        if len(bitfield_bytes) != self.expected_bitfield_len:
            # Logging removed
            self.close()
            return

        for i, byte in enumerate(bitfield_bytes):
            for j in range(8):
                piece_index = i * 8 + j
                
                if piece_index >= self.num_pieces:
                    # Stop processing if we exceed the total number of pieces
                    break
                
                # Check if the bit is set (MSB first)
                if byte & (1 << (7 - j)):
                    self.peer_bitfield[piece_index] = True
        
        # Logging removed
        
        # Attempt to request a piece now that we know what the peer has
        self.check_and_request()
        
    def handle_piece(self, payload):
        """Handles the incoming 'piece' message (ID 7): <index><begin><data>"""
        if len(payload) < 8:
            # Logging removed
            self.close()
            return

        # Unpack index and begin (4-byte integers)
        index, begin = struct.unpack('!II', payload[:8])
        data = payload[8:]
        
        # Logging removed
        
        # 1. Store the block in the buffer
        self.piece_buffer[begin] = data
        self.piece_data_size += len(data)
        
        # 2. Check for piece completion (The piece length must match the sum of block sizes)
        if self.piece_data_size >= self.piece_length and self.current_piece_index == index:
            self._validate_and_write_piece()
            self.check_and_request() # Try to find the next piece
        else:
            # 3. Request the next block
            self._get_next_block_request()
        
    def handle_message(self, message):
        """Processes an incoming message based on its ID."""
        msg_id = message['id']
        
        if msg_id == 'choke':
            self.peer_choking = True
            # Logging removed
        
        elif msg_id == 'unchoke':
            self.peer_choking = False
            # Logging removed
            self.check_and_request() 
        
        elif msg_id == 'interested':
            pass 

        elif msg_id == 'bitfield':
            self.handle_bitfield(message['payload'])
            
        elif msg_id == 'piece':
            self.handle_piece(message['payload'])

        elif msg_id == 'keep-alive':
            pass # Do nothing, just maintain connection

    def read_message(self):
        """
        Reads a single, complete message from the socket, handling fragmentation.
        Returns the parsed message dictionary or None if the connection closes.
        """
        try:
            # 1. Read the 4-byte length prefix. Use blocking read here.
            len_prefix_bytes = self.sock.recv(4)
            
            if not len_prefix_bytes:
                # Connection closed gracefully by peer
                return None 

            message_length = struct.unpack('>I', len_prefix_bytes)[0]

            # Keep-Alive message check (length 0)
            if message_length == 0:
                return {'id': MESSAGE_IDS[10], 'payload': b''}

            # 2. Read the 1-byte message ID
            # Set a timeout for reading the rest of the message data
            self.sock.settimeout(10) 
            message_id_bytes = self.sock.recv(1)
            
            if not message_id_bytes:
                raise IOError("Connection closed before reading message ID.")

            message_id = struct.unpack('>B', message_id_bytes)[0]

            # 3. Read the remaining payload (length - 1 byte for the ID)
            payload_len = message_length - 1
            payload = b''
            
            # Ensure we read the full payload, even if it comes in chunks
            while len(payload) < payload_len:
                chunk = self.sock.recv(payload_len - len(payload))
                if not chunk:
                    raise IOError("Connection closed while reading message payload.")
                payload += chunk

            return {'id': MESSAGE_IDS.get(message_id), 'payload': payload}

        except socket.timeout:
            return None 
        except Exception:
            # Logging removed
            self.close()
            return None
    
    def start_download_loop(self):
        """The main loop for communicating with the peer after handshake."""
        # Logging removed
        
        # 1. Immediately tell the peer we are interested in its pieces
        self.send_interested()
        
        # 2. Enter continuous messaging loop
        self.sock.settimeout(10) # Timeout for reading messages
        
        try:
            while self.downloading:
                message = self.read_message()
                
                if message is None:
                    # Connection closed gracefully by peer
                    break
                
                if message:
                    self.handle_message(message)
                    
        except Exception:
            # Logging removed
            pass
        finally:
            self.close()


    def close(self):
        """Closes the socket connection."""
        self.downloading = False # Ensure loop terminates
        self.sock.close()
        # Logging removed


def handshake_worker(peer, torrent_info, client_peer_id, output_filename):
    """Worker function to run the handshake in a separate thread."""
    global successful_connections
    global handshake_lock
    
    with handshake_lock:
        if len(successful_connections) >= MAX_SUCCESSFUL_CONNECTIONS:
            return 
            
    handshake_result = perform_handshake(peer, torrent_info, client_peer_id)

    if handshake_result:
        # LOGGING REMOVED - Success message is no longer printed here.
        
        with handshake_lock:
            if len(successful_connections) < MAX_SUCCESSFUL_CONNECTIONS:
                successful_connections.append(handshake_result)
                
                # Immediately start the download prep phase
                peer_conn = PeerConnection(
                    sock=handshake_result['socket'], 
                    peer_id=handshake_result['peer_id'], 
                    torrent_info=torrent_info,
                    output_filename=output_filename # Pass the dynamic filename
                )
                peer_conn.start_download_loop()

# --- 5. Main Execution ---

def main():
    if len(sys.argv) != 2:
        print("Usage: python bittorrent_client.py <path_to_torrent_file.torrent>")
        sys.exit(1)

    torrent_filepath = sys.argv[1]
    
    # 1. Parse the torrent file
    torrent_info = parse_torrent_file(torrent_filepath)
    if not torrent_info:
        sys.exit(1)
        
    # --- DYNAMIC OUTPUT PATH GENERATION ---
    torrent_name_with_ext = os.path.basename(torrent_filepath)
    base_name = os.path.splitext(torrent_name_with_ext)[0]
    output_directory = base_name
    output_filename = os.path.join(output_directory, "download.bin")
    
    # Create the output directory
    try:
        os.makedirs(output_directory, exist_ok=True)
    except Exception as e:
        print(f"[ERROR] Failed to create output directory {output_directory}: {e}")
        sys.exit(1)

    print(f"\n[INFO] Download directory created: {output_directory}/")
    print(f"[INFO] Download target: {output_filename} (Size: {torrent_info['length']} bytes)")
    
    # 2. Setup Progress Tracker
    global total_pieces
    total_pieces = len(torrent_info['pieces_raw']) // 20
    print(f"[INFO] Total pieces to download: {total_pieces}")
    
    # 3. Generate our unique ID
    client_peer_id = generate_peer_id()
    print(f"Client Peer ID: {client_peer_id.decode('latin-1')}")

    # 4. Start the progress display worker
    progress_thread = threading.Thread(target=display_progress)
    progress_thread.start()
    
    # 5. Request peer list from the appropriate tracker protocol
    peers = get_peers(torrent_info, client_peer_id)
    
    if peers:
        print("\n--- Starting Concurrent Handshakes ---")
        
        # Reset global state
        global successful_connections
        successful_connections = []
        threads = []
        
        # 6. Start concurrent threads for handshake
        for peer in peers[:MAX_HANDSHAKE_ATTEMPTS]:
            with handshake_lock:
                if len(successful_connections) >= MAX_SUCCESSFUL_CONNECTIONS:
                    break
            
            # Pass the dynamic filename to the worker thread
            t = threading.Thread(target=handshake_worker, args=(peer, torrent_info, client_peer_id, output_filename)) 
            threads.append(t)
            t.start()
            
        # Wait for all handshake threads to finish attempting connections
        for t in threads:
            t.join() 
        
        # The handshake summary is crucial for debugging, so we keep it.
        print("\n--- Final Summary ---")
        print(f"Handshake Attempts: {len(threads)}. Successful: {len(successful_connections)}") 
        print("---------------------")

    # 7. Signal the progress bar thread to stop (if it hasn't already)
    client_running.set()
    progress_thread.join()
    
if __name__ == '__main__':
    main()
