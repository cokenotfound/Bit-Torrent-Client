import libtorrent as lt
import time
import sys
import os

def run_libtorrent_client(torrent_file_path):
    """Initializes libtorrent, adds the torrent, and monitors download progress."""
    
    if not os.path.exists(torrent_file_path):
        print(f"Error: Torrent file not found at {torrent_file_path}")
        return

    # 1. Initialize the session and listen for connections
    ses = lt.session()
    print("Libtorrent Session Initialized.")

    # 2. Get torrent info and set up file storage
    info = lt.torrent_info(torrent_file_path)
    
    # Create output directory based on torrent name
    base_name = os.path.splitext(os.path.basename(torrent_file_path))[0]
    output_dir = base_name
    os.makedirs(output_dir, exist_ok=True)
    
    # Set download parameters
    params = {
        'ti': info,
        'save_path': output_dir,
        'storage_mode': lt.storage_mode_t.storage_mode_sparse,
        'paused': False,
        'auto_managed': True,
        'duplicate_is_error': True
    }

    # 3. Add the torrent to the session
    h = ses.add_torrent(params)
    
    print(f"[INFO] Starting download for: {h.name()}")
    print(f"[INFO] Saving to: {output_dir}")
    print(f"[INFO] Total pieces: {info.num_pieces()}")
    
    # Loop until the torrent is finished or an error occurs
    while not h.is_seed():
        s = h.status()
        
        # Display Progress Bar (Similar to our custom progress bar logic, but uses libtorrent data)
        progress_bar = '#' * int(s.progress * 50)
        remaining_bar = '-' * (50 - len(progress_bar))
        
        print(f'\r[PROGRESS] |{progress_bar}{remaining_bar}| {s.progress * 100:.2f}% '
              f'Rate: {s.download_rate / 1000:.1f} kB/s '
              f'Peers: {s.num_peers} ', end='')
              
        sys.stdout.flush()

        # Check for errors
        if s.error:
            print(f"\n[ERROR] Download failed: {s.error}")
            return
        
        # Wait before updating
        time.sleep(1)

    # Final cleanup message
    print(f"\n[COMPLETED] Download finished successfully!")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python libtorrent_client.py <path_to_torrent_file.torrent>")
        sys.exit(1)
    
    # The client now expects the path to the torrent file as the only argument
    run_libtorrent_client(sys.argv[1])
