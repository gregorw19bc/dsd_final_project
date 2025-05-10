import os
import json
import time
import secrets
from email.mime.text import MIMEText

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from helper_methods import *

# SCOPES for send, read, modify
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
STATE_FILE = 'state.json'
CRED_FILE = 'credentials.json'
POLL_INTERVAL = 5

# --- State management ---
def load_state():
    return json.load(open(STATE_FILE)) if os.path.exists(STATE_FILE) else {}

def save_state(state):
    json.dump(state, open(STATE_FILE, 'w'))

# --- DH keypair generator ---
def generate_keypair(p, g):
    priv = secrets.randbelow(p)
    pub = pow(g, priv, p)
    return priv, pub

# --- Gmail API boilerplate ---
def get_gmail_service():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(CRED_FILE, SCOPES)
        creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as f:
            f.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

def create_message(to, subject, body):
    msg = MIMEText(body)
    msg['to'] = to
    msg['subject'] = subject
    raw = bytes_to_Base64(msg.as_bytes())
    return {'raw': raw}

def send_message(service, message):
    sent = service.users().messages().send(userId='me', body=message).execute()
    print("Sent message ID:", sent['id'])

# Aend our DH public key
def send_public_key(recipient):
    svc = get_gmail_service()
    state = load_state()

    if 'priv' not in state:
        # RFC 3526 Group 14 prime
        p = int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
        )
        g = 2
        priv, pub = generate_keypair(p, g)
        state.update({'p': str(p), 'g': str(g),
                      'priv': str(priv), 'pub': str(pub)})
        save_state(state)
    else:
        priv = int(state['priv'])
        pub  = int(state['pub'])

    # send our public key
    pub_bytes = int_to_bytes(pub)
    pub_b64 = bytes_to_Base64(pub_bytes)
    msg = create_message(recipient, 'SECURE-DH-KEY', pub_b64)
    send_message(svc, msg)

# Process incoming DH public key and derive shared secret 
def process_incoming_public_key():
    svc = get_gmail_service()
    state = load_state()
    p = int(state['p'])
    priv = int(state['priv'])

    res = svc.users().messages().list(
        userId='me', q='subject:SECURE-DH-KEY is:unread'
    ).execute()

    for m in res.get('messages', []):
        full  = svc.users().messages().get(
              userId='me', id=m['id'], format='full'
              ).execute()
        raw_body = full['payload']['body']['data']
        partner_pub_bytes = Base64_to_bytes(raw_body + '===')
        partner_pub       = bytes_to_int(partner_pub_bytes)

        # compute shared secret
        shared = pow(partner_pub, priv, p)
        state['shared'] = str(shared)
        save_state(state)

        # mark read
        svc.users().messages().modify(
            userId='me', id=m['id'],
            body={'removeLabelIds': ['UNREAD']}
        ).execute()
        print("Derived shared secret.")

# Send encrypted + authenticated message 
def send_secure_message(recipient, plaintext):
    svc = get_gmail_service()
    state = load_state()
    shared = int(state['shared'])
    key_bytes = int_to_bytes(shared)

    nonce = secrets.token_bytes(16)
    ks = generate_keystream(key_bytes, len(plaintext), nonce)
    cipher = xor_bytes(str_to_bytes(plaintext), ks)

    blob = nonce + cipher
    mac = create_mac(key_bytes, blob)

    payload = json.dumps({
        'nonce':  bytes_to_Base64(nonce),
        'cipher': bytes_to_Base64(cipher),
        'mac':    mac
    })
    msg = create_message(recipient, 'SECURE-DH-MSG', payload)
    send_message(svc, msg)

# Process and decrypt incoming secure messages 
def process_incoming_messages():
    svc = get_gmail_service()
    state = load_state()
    shared = int(state['shared'])
    key_bytes = int_to_bytes(shared)

    res = svc.users().messages().list(
        userId='me', q='subject:SECURE-DH-MSG is:unread'
    ).execute()

    for m in res.get('messages', []):
        full = svc.users().messages().get(
                   userId='me', id=m['id'], format='full'
               ).execute()
        raw_body = full['payload']['body']['data']
        payload = json.loads(Base64_to_bytes(raw_body + '===').decode())

        nonce = Base64_to_bytes(payload['nonce'])
        cipher = Base64_to_bytes(payload['cipher'])
        mac = payload['mac']

        blob = nonce + cipher
        if not verify_mac(key_bytes, blob, mac):
            print("MAC failed, skipping.")
        else:
            ks    = generate_keystream(key_bytes, len(cipher), nonce)
            plain = xor_bytes(cipher, ks)
            print("Decrypted message:", bytes_to_str(plain))

        svc.users().messages().modify(
            userId='me', id=m['id'],
            body={'removeLabelIds': ['UNREAD']}
        ).execute()

# --- Receiver main loop ---
def main_receiver():
    print("Secure Gmail DH Chat — Receiver\n")
    recipient = input("Initiator's email: ").strip()
    if not recipient:
        return

    send_public_key(recipient)
    print(f"Sent DH public key to {recipient}.\n")

    print(f"Polling every {POLL_INTERVAL}s...")
    try:
        while True:
            process_incoming_public_key()
            process_incoming_messages()
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    main_receiver()
