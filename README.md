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
### When?
### How?


## Implementation


## Novelty
### What makes it different from your standard UTorrent Client?

## Future Work
### Swarm Optimisation
Swarm Optimization: This involves implementing the Rarest-First piece selection algorithm. This upgrade focuses the client's intelligence on prioritizing the least available data in the swarm, which enhances overall download resilience and contributes to the health of the network.

### Seeding Capability
This integrates the crucial Tit-for-Tat incentive system. It requires the client to process incoming REQUEST messages from other peers and upload verified file blocks, transforming the downloader into a full, contributing member of the network after the download is complete.
