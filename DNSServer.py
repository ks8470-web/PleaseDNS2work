import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import dns.rrset
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# ---------- Encryption helpers (as required by assignment) ----------
def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    return encrypted_data

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

# Assignment-specified parameters
salt = b'Tandon'  # must be bytes
password = 'ks8470@nyu.edu'  # your NYU email used on Gradescope
input_string = 'AlwaysWatching'

encrypted_value = encrypt_with_aes(input_string, password, salt)
# The fernet encrypted bytes are already base64-encoded bytes; decode to ascii for TXT storage
encrypted_token_str = encrypted_value.decode('ascii')

# Optional utility
def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# ---------- DNS records dictionary (assignment-provided) ----------
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',     # mname
            'admin.example.com.',   # rname
            2023081401,             # serial
            3600,                   # refresh
            1800,                   # retry
            604800,                 # expire
            86400,                  # minimum
        ),
    },
    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
    },
    'google.com.': {
        dns.rdatatype.A: '192.168.1.103',
    },
    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104',
    },
    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105',
    },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        # TXT must be a tuple/list of strings per our storage convention
        dns.rdatatype.TXT: (encrypted_token_str,),
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
}

# ---------- Server bind parameters ----------
BIND_ADDRESS = '127.0.0.1'
# Use 5300 for testing without root. Change to 53 if you run as root and want the standard DNS port.
BIND_PORT = 5300

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((BIND_ADDRESS, BIND_PORT))
    print(f"DNS server bound to {BIND_ADDRESS}:{BIND_PORT}")

    while True:
        try:
            data, addr = server_socket.recvfrom(4096)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            # take first question
            if not request.question:
                # no question, ignore
                continue

            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # Debug print
            print(f"Query from {addr}: name={qname}, type={dns.rdatatype.to_text(qtype)}")

            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    # answer_data is list of (pref, server)
                    for pref, server in answer_data:
                        # MX expects (rdclass, rdtype, preference, exchange)
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.SOA:
                    # answer_data is tuple: (mname, rname, serial, refresh, retry, expire, minimum)
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata_list.append(SOA(dns.rdataclass.IN, dns.rdatatype.SOA, mname, rname, serial, refresh, retry, expire, minimum))
                else:
                    # For other types:
                    # If a single string was given, wrap into a list so the comprehension below always works
                    if isinstance(answer_data, str):
                        items = [answer_data]
                    else:
                        # E.g., TXT stored as tuple of strings
                        items = list(answer_data)

                    # Use dns.rdata.from_text to create rdata objects
                    rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, item) for item in items]

                # Append each rdata to an rrset and then to the response answer
                for rdata in rdata_list:
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                    rrset.add(rdata)
                    response.answer.append(rrset)

            # set AA flag (Authoritative Answer) - AA is bit 10
            response.flags |= (1 << 10)

            # send response
            server_socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            print("\nShutting down DNS server.")
            server_socket.close()
            sys.exit(0)
        except Exception as e:
            print(f"Error handling request: {e}")
            # continue serving other requests
            continue

def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print(f"DNS server is running on {BIND_ADDRESS}:{BIND_PORT} (press 'q' then Enter to quit)")

    def user_input():
        while True:
            try:
                cmd = input()
                if cmd.lower() == 'q':
                    print('Quitting...')
                    os.kill(os.getpid(), signal.SIGINT)
            except EOFError:
                # input closed
                break

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()

if __name__ == '__main__':
    run_dns_server_user()
