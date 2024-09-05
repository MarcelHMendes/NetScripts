from scapy.all import *
import os

def split_file(file_path, chunksize):
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(chunksize)
            if not chunk:
                break
            yield chunk

file_path = "teste.txt"
chunksize = 64
for chunk in split_file(file_path, chunksize):
    packet = IP(dst="127.0.0.1") / ICMP() / chunk
    send(packet)
