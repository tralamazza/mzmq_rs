#!/usr/bin/env python3
"""Minimal pyzmq SUB socket that listens on a TCP port and prints received messages.

Usage:
    python sub_listener.py <port> <topic_prefix>

The script subscribes to the given topic prefix (empty string subscribes to all),
then prints each received message as:
    TOPIC:PAYLOAD

where TOPIC and PAYLOAD are hex-encoded.
"""

import sys
import zmq
import binascii

def main():
    if len(sys.argv) != 3:
        print("Usage: python sub_listener.py <port> <topic_prefix>", file=sys.stderr)
        sys.exit(1)

    port = int(sys.argv[1])
    topic_prefix = sys.argv[2].encode('utf-8')

    ctx = zmq.Context()
    sock = ctx.socket(zmq.SUB)
    sock.setsockopt(zmq.RCVTIMEO, 5000)  # 5 second timeout
    sock.bind(f"tcp://*:{port}")
    sock.setsockopt(zmq.SUBSCRIBE, topic_prefix)

    print(f"READY port={port} topic_prefix={topic_prefix!r}", flush=True)

    try:
        while True:
            try:
                # ZMQ PUB sends multipart: [topic, payload]
                topic = sock.recv()
                payload = sock.recv()
                hex_topic = binascii.hexlify(topic).decode('ascii')
                hex_payload = binascii.hexlify(payload).decode('ascii')
                print(f"{hex_topic}:{hex_payload}", flush=True)
            except zmq.Again:
                # Timeout, keep listening
                continue
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        ctx.term()

if __name__ == "__main__":
    main()