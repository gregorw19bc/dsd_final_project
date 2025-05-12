import os
import json
import time
import secrets
import email
import base64
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
    bytes_to_str,
    create_mac,
    verify_mac
)

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
STATE_FILE = 'state.json'
CRED_FILE = 'credentials.json'
POLL_INTERVAL = 5

# Load persistent DH/chat state from disk
def load_state():
    return json.load(open(STATE_FILE)) if os.path.exists(STATE_FILE) else {}

# Save our DH state back to disk
def save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f)

# Remove any existing state file
def clear_state():
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)

# Produce DH private/public keypair with given p, g
def generate_keypair(p, g):
    priv = secrets.randbelow(p)
    pub = pow(g, priv, p)
    return priv, pub

# Authenticate and return Gmail API client
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

# Build a raw Gmail message
def create_message(to, subject, body):
    msg = MIMEText(body)
    msg['to'] = to
    msg['subject'] = subject
    return {'raw': bytes_to_Base64(msg.as_bytes())}

# Send the message via Gmail API
def send_message(service, message):
    sent = service.users().messages().send(userId='me', body=message).execute()
    print("Sent message ID:", sent['id'])

# Step 1 (receiver): poll for initiator's {p,g,pub}, generate own keypair, derive shared, send back JSON {pub}
def process_incoming_parameters_and_pub(initiator):
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
        p = int(data['p'])
        g = int(data['g'])
        partner_pub = int(data['pub'])

        priv, pub = generate_keypair(p, g)
        shared = pow(partner_pub, priv, p)

        state['p'] = str(p)
        state['g'] = str(g)
        state['priv'] = str(priv)
        state['pub'] = str(pub)
        state['shared'] = str(shared)
        seen.add(mid)
        state['processed_keys'] = list(seen)
        save_state(state)

        svc.users().messages().modify(
            userId='me', id=mid,
            body={'removeLabelIds': ['UNREAD']}
        ).execute()

        reply = json.dumps({'pub': str(pub)})
        msg2 = create_message(initiator, 'SECURE-DH-KEY', reply)
        send_message(svc, msg2)

        print("Derived shared secret and sent our public key.")
        break

# Step 2 (receiver): poll for secure messages, verify MAC, decrypt, and print
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

# Main loop for the receiver: perform key handshake, then decrypt messages
def main_receiver():
    clear_state()
    print("Secure Gmail DH Chat — Receiver\n")
    print("Press CTRL-C to quit\n")
    initiator = input("Enter initiator's email: ").strip()
    if not initiator:
        return

    print(f"Waiting for DH parameters… (poll every {POLL_INTERVAL}s)")
    while True:
        process_incoming_parameters_and_pub(initiator)
        state = load_state()
        if 'shared' in state:
            break
        time.sleep(POLL_INTERVAL)

    print("Shared secret established. Listening for secure messages…")
    try:
        while True:
            process_incoming_messages()
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    main_receiver()
