# Bit-Torrent-Client
A multi-threaded Python BitTorrent client built from scratch. Features Bencoding, concurrent peer discovery, full PWP messaging, and Rarest-First swarm optimization for verified, efficient downloading. 

## Idea
This project implemented a Python BitTorrent P2P client.

### Approach One 
Leveraged the high-performance libtorrent library to gain a vague understanding of the Protocol Fundamentals; while establishing a robust, production-ready system for file retrieval and cryptographic integrity checking. 

### Approach Two 
Constructed the client entirely from scratch, demonstrating low-level mastery of the protocol. This involved developing a bespoke Bencoding parser, managing concurrent multi-threading, and manually coding the core logic to achieve comprehensive understanding.

Reference - https://markuseliasson.se/article/bittorrent-in-python/

## Core Principles
### What? 
The core objective is Trustless Integrity and High Availability. The system must ensure that data received from anonymous, unreliable sources is both uncorrupted and remains available throughout the download.
When? (Mechanism)
### When?
Integrity is enforced upon piece completion via cryptographic hashing. Availability is optimized during peer communication via concurrency and selection algorithms.
How? (Implementation)
### How?
    Trust Enforcement: Every file piece is checked against its expected SHA-1 hash from the torrent file before being written to disk.

    Concurrency: Utilized Python's threading to manage up to 30 simultaneous socket connections to maximize peer search efficiency against volatile networks.

    Incentives (Game Theory): The architecture is designed to support the Tit-for-Tat incentive model, which encourages peers to upload to the client in return for download priority.

## Implementation


## Novelty
### What makes it different from a standard UTorrent Client?

## Future Work
### Swarm Optimisation
Swarm Optimization: This involves implementing the Rarest-First piece selection algorithm. This upgrade focuses the client's intelligence on prioritizing the least available data in the swarm, which enhances overall download resilience and contributes to the health of the network.

### Seeding Capability
This integrates the crucial Tit-for-Tat incentive system. It requires the client to process incoming REQUEST messages from other peers and upload verified file blocks, transforming the downloader into a full, contributing member of the network after the download is complete.
