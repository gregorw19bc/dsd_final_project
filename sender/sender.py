import os
import json
import secrets
import time
from email.mime.text import MIMEText

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import email

from helper_methods import *

# SCOPES for send, read, modify
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
STATE_FILE = 'state.json'
CRED_FILE = 'credentials.json'
POLL_INTERVAL = 5

# --- State helpers ---
def load_state():
    return json.load(open(STATE_FILE)) if os.path.exists(STATE_FILE) else {}

def save_state(state):
    json.dump(state, open(STATE_FILE, 'w'))

def clear_state():
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)

# --- DH keypair generator ---
def generate_keypair(p, g):
    priv = secrets.randbelow(p)
    pub  = pow(g, priv, p)
    return priv, pub

# --- Gmail API boilerplate ---
def get_gmail_service():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(CRED_FILE, SCOPES)
        creds = flow.run_local_server(port=0)
        with open('token.json','w') as f:
            f.write(creds.to_json())
    return build('gmail','v1',credentials=creds)

def create_message(to, subject, body):
    msg = MIMEText(body)
    msg['to'] = to
    msg['subject'] = subject
    return {'raw': bytes_to_Base64(msg.as_bytes())}

def send_message(service, message):
    sent = service.users().messages().send(userId='me', body=message).execute()
    print("Sent message ID:", sent['id'])

# --- 1) Send DH public key ---
def send_public_key(recipient):
    svc = get_gmail_service()
    state = load_state()

    if 'priv' not in state:
        # 2048-bit safe prime (RFC 3526 Group 14)
        p = int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
        )
        g = 2
        priv, pub = generate_keypair(p, g)
        state.update({'p':str(p), 'g':str(g),
                      'priv':str(priv), 'pub':str(pub)})
        save_state(state)
    else:
        priv = int(state['priv'])
        pub = int(state['pub'])

    # encode & send our public key
    pub_b64 = bytes_to_Base64(int_to_bytes(pub))
    msg = create_message(recipient, 'SECURE-DH-KEY', pub_b64)
    send_message(svc, msg)

# --- 2) Process incoming DH public key & derive shared secret ---
def process_incoming_public_key():
    svc   = get_gmail_service()
    state = load_state()

    # pull or init our “seen” list
    # just makes sure we don't reuse keys
    seen = set(state.get('processed_keys', []))

    # grab all unread DH-KEYs
    res = svc.users().messages().list(
        userId='me',
        q='subject:SECURE-DH-KEY is:unread'
    ).execute()

    for m in res.get('messages', []):
        mid = m['id']
        if mid in seen:
            continue    # skip anything we’ve already handled

        # --- fetch raw MIME, peel out the exact Base64 text ---
        full     = svc.users().messages().get(
            userId='me', id=mid, format='raw'
        ).execute()
        raw_b64 = full['raw']
        raw_bytes = base64.urlsafe_b64decode(raw_b64)
        msg = email.message_from_bytes(raw_bytes)

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    pub_b64 = part.get_payload(decode=True).decode()
                    break
        else:
            pub_b64 = msg.get_payload(decode=True).decode()

        partner_pub = bytes_to_int(Base64_to_bytes(pub_b64))
        priv = int(state['priv'])
        p = int(state['p'])

        # --- derive & save shared secret ---
        shared = pow(partner_pub, priv, p)
        state['shared'] = str(shared)

        # mark this ID “done” so we never reuse it
        seen.add(mid)
        state['processed_keys'] = list(seen)

        save_state(state)

        # mark it read in Gmail
        svc.users().messages().modify(
            userId='me', id=mid,
            body={'removeLabelIds':['UNREAD']}
        ).execute()

        break

# --- 3) Send encrypted + authenticated message ---
def send_secure_message(recipient, plaintext):
    svc = get_gmail_service()
    state = load_state()
    shared = int(state['shared'])
    key_bytes = int_to_bytes(shared)

    nonce = secrets.token_bytes(16)
    ks = generate_keystream(key_bytes, len(plaintext), nonce)
    cipher = xor_bytes(str_to_bytes(plaintext), ks)

    blob = nonce + cipher
    mac  = create_mac(key_bytes, blob)

    payload = json.dumps({
        'nonce': bytes_to_Base64(nonce),
        'cipher': bytes_to_Base64(cipher),
        'mac': mac
    })
    msg = create_message(recipient, 'SECURE-DH-MSG', payload)
    send_message(svc, msg)

# --- 4) Process and decrypt incoming secure messages ---
def process_incoming_messages():
    svc = get_gmail_service()
    state = load_state()
    shared = int(state['shared'])
    key_bytes = int_to_bytes(shared)

    res = svc.users().messages().list(
        userId='me', q='subject:SECURE-DH-MSG is:unread'
    ).execute()

    for m in res.get('messages', []):
        full     = svc.users().messages().get(
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
            body={'removeLabelIds':['UNREAD']}
        ).execute()


def main():
    clear_state()
    print("One-click DH key exchange + secure message\n")
    recipient = input("Enter recipient email: ").strip()
    if not recipient:
        print("No email provided; exiting.")
        return

    # 1) send your public key
    send_public_key(recipient)
    print(f"DH public key sent to {recipient}.\n")

    # 2) loop until we derive a shared secret
    print(f"Waiting for {recipient}'s DH key…")
    while True:
        process_incoming_public_key()
        state = load_state()
        if 'shared' in state:
            print("Shared secret established.\n")
            break
        # not there yet, sleep and retry
        time.sleep(POLL_INTERVAL)

    # 3) once shared is set, send your secure message
    plaintext = input("Type your secure message: ")
    if plaintext:
        send_secure_message(recipient, plaintext)
        print("Secure message sent.\n")
    else:
        print("No message entered; skipping.\n")

if __name__ == "__main__":
    main()

