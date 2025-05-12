import os
import json
import secrets
import time
import base64
import email
from email.mime.text import MIMEText

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from cryptography.hazmat.primitives.asymmetric import dh

from helper_methods import (
    bytes_to_Base64,
    Base64_to_bytes,
    int_to_bytes,
    generate_keystream,
    xor_bytes,
    str_to_bytes,
    bytes_to_str,
    create_mac,
    verify_mac
)

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
STATE_FILE = 'state.json'
CRED_FILE = 'credentials.json'
POLL_INTERVAL = 5

# Load persistent state (p, g, priv, pub, shared, processed_keys)
def load_state():
    return json.load(open(STATE_FILE)) if os.path.exists(STATE_FILE) else {}

# Save our DH state back to disk
def save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f)

# Remove any existing state file to start fresh
def clear_state():
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)

# Generate safe-prime DH parameters via cryptography library
def generate_dh_params(key_size=2048, generator=2):
    params = dh.generate_parameters(generator=generator, key_size=key_size)
    nums = params.parameter_numbers()
    return nums.p, nums.g

# Produce a DH private/public keypair given p and g
def generate_keypair(p, g):
    priv = secrets.randbelow(p)
    pub = pow(g, priv, p)
    return priv, pub

# Authenticate and return a Gmail API service object
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

# Build a Gmail API message dict with raw Base64 payload
def create_message(to, subject, body):
    msg = MIMEText(body)
    msg['to'] = to
    msg['subject'] = subject
    return {'raw': bytes_to_Base64(msg.as_bytes())}

# Send a message via Gmail API
def send_message(service, message):
    sent = service.users().messages().send(userId='me', body=message).execute()
    print("Sent message ID:", sent['id'])

# Step 1: generate fresh p, g, keypair; store state; email JSON {p,g,pub}
def send_public_key(recipient):
    svc = get_gmail_service()
    state = load_state()

    print("Generating DH parameters…")
    p, g = generate_dh_params(2048, 2)
    priv, pub = generate_keypair(p, g)

    state['p'] = str(p)
    state['g'] = str(g)
    state['priv'] = str(priv)
    state['pub'] = str(pub)
    save_state(state)

    payload = json.dumps({'p': str(p), 'g': g, 'pub': str(pub)})
    msg = create_message(recipient, 'SECURE-DH-KEY', payload)
    send_message(svc, msg)

# Step 2 (initiator): poll unread SECURE-DH-KEY replies, derive shared secret
def process_incoming_public_key():
    svc = get_gmail_service()
    state = load_state()
    seen = set(state.get('processed_keys', []))

    res = svc.users().messages().list(
        userId='me', q='subject:SECURE-DH-KEY is:unread'
    ).execute()
    for m in res.get('messages', []):
        mid = m['id']
        if mid in seen:
            continue

        full = svc.users().messages().get(
            userId='me', id=mid, format='raw'
        ).execute()
        raw_b64 = full['raw']
        raw_bytes = base64.urlsafe_b64decode(raw_b64)
        msg = email.message_from_bytes(raw_bytes)

        if msg.is_multipart():
            part = next(p for p in msg.walk() if p.get_content_type() == 'text/plain')
            body = part.get_payload(decode=True).decode()
        else:
            body = msg.get_payload(decode=True).decode()

        data = json.loads(body)
        partner_pub = int(data['pub'])
        priv = int(state['priv'])
        p = int(state['p'])
        shared = pow(partner_pub, priv, p)
        state['shared'] = str(shared)

        seen.add(mid)
        state['processed_keys'] = list(seen)
        save_state(state)

        svc.users().messages().modify(
            userId='me', id=mid,
            body={'removeLabelIds': ['UNREAD']}
        ).execute()
        print("Shared secret established.")
        break

# Step 3: encrypt+MAC the plaintext under shared secret, email JSON blob
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
        'nonce': bytes_to_Base64(nonce),
        'cipher': bytes_to_Base64(cipher),
        'mac': mac
    })
    msg = create_message(recipient, 'SECURE-DH-MSG', payload)
    send_message(svc, msg)

# Step 4: poll unread SECURE-DH-MSG, verify MAC, decrypt, print
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
        data_json = json.loads(Base64_to_bytes(raw_body + '===').decode())

        nonce = Base64_to_bytes(data_json['nonce'] + '===')
        cipher = Base64_to_bytes(data_json['cipher'] + '===')
        mac = data_json['mac']
        blob = nonce + cipher

        if not verify_mac(key_bytes, blob, mac):
            print("MAC verification failed, skipping.")
        else:
            ks = generate_keystream(key_bytes, len(cipher), nonce)
            plain = xor_bytes(cipher, ks)
            print("Decrypted message:", bytes_to_str(plain))

        svc.users().messages().modify(
            userId='me', id=m['id'],
            body={'removeLabelIds': ['UNREAD']}
        ).execute()

# Orchestrates the whole flow for the initiator, then lets you send multiple messages
def main():
    clear_state()
    print("One-click DH key exchange + secure message (Initiator)\n")
    recipient = input("Enter recipient email: ").strip()
    if not recipient:
        print("No email; exiting.")
        return

    # 1) send DH params + pub
    send_public_key(recipient)

    # 2) wait for their pub & derive shared secret
    print(f"Waiting for {recipient}'s response…")
    while True:
        process_incoming_public_key()
        state = load_state()
        if 'shared' in state:
            break
        time.sleep(POLL_INTERVAL)

    # 3) loop to send multiple secure messages
    print("Shared secret established! You can now send multiple messages.")
    print("Type 'exit' or just press Enter on blank line to quit.")
    while True:
        plaintext = input("Type message (or 'exit'): ").strip()
        if not plaintext or plaintext.lower() == 'exit':
            break
        send_secure_message(recipient, plaintext)

    print("All done.")

if __name__ == "__main__":
    main()