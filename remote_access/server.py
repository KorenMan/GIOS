import socket
import threading
import keyboard
import os
import json
import base64
import time
import io
from PIL import ImageGrab, Image
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad
import traceback

MSG_KEY = "KEY "
MSG_SCREEN = "SCRN"
MSG_CONTROL = "CTRL"
MSG_MSG = "MESG"
MSG_ERR = "ERR "
MSG_DISCONNECT = "BYE "
HEADER_TYPE_LEN = 4

class Server:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}
        self.lock = threading.Lock()

        self.key = RSA.generate(2048)
        self.private_key = self.key
        self.public_key = self.key.publickey()

        self.default_screen_quality = 70
        self.default_screen_scale = 0.75
        self.running = False

    def _recv(self, sock):
        """Receives data prefixed with its size."""
        size_of_size_byte = b''
        while len(size_of_size_byte) < 1:
            try:
                packet = sock.recv(1 - len(size_of_size_byte))
                if not packet: return b''
                size_of_size_byte += packet
            except socket.error:
                return b''

        size_of_size = int.from_bytes(size_of_size_byte, 'big')

        size_bytes = b''
        while len(size_bytes) < size_of_size:
            try:
                packet = sock.recv(size_of_size - len(size_bytes))
                if not packet: return b''
                size_bytes += packet
            except socket.error:
                return b''

        data_len = int.from_bytes(size_bytes, 'big')

        data = b''
        while len(data) < data_len:
            try:
                packet = sock.recv(data_len - len(data))
                if not packet: return b''
                data += packet
            except socket.error:
                return b''

        return data

    def _send(self, sock, bdata):
        """Sends data prefixed with its size."""
        if isinstance(bdata, str):
            bdata = bdata.encode('utf-8')

        data_len = len(bdata)
        size_of_size = (data_len.bit_length() + 7) // 8
        if size_of_size == 0:
            size_of_size = 1

        size_bytes = data_len.to_bytes(size_of_size, 'big')
        size_of_size_byte = size_of_size.to_bytes(1, 'big')
        message = size_of_size_byte + size_bytes + bdata

        try:
            sock.sendall(message)
            return True
        except socket.error as e:
            print(f"Socket error during send: {e}")
            return False # Indicate failure

    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            print(f"[*] Server started on {self.host}:{self.port}")

            while self.running:
                try:
                    self.server_socket.settimeout(1.0)
                    client_socket, client_address = self.server_socket.accept()
                    self.server_socket.settimeout(None)
                    print(f"[+] Connection from {client_address}")
                    # Start handling in a new thread
                    thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True)
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                     if self.running:
                         print(f"[!] Error accepting connection: {e}")
        except Exception as e:
            print(f"[!] Server main loop error: {e}")
        finally:
            print("[*] Server shutting down...")
            self.running = False
            with self.lock:
                client_sockets = [info['socket'] for info in self.clients.values()]
                self.clients.clear()
            for sock in client_sockets:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                except: pass
            if self.server_socket:
                self.server_socket.close()
            print("[*] Server stopped.")


    def handle_client(self, client_socket, client_address):
        client_addr_str = f"{client_address[0]}:{client_address[1]}"
        aes_key = None
        try:
            aes_key = self._key_exchange(client_socket, client_address)
            if not aes_key:
                 raise ConnectionError("Key exchange failed.")

            with self.lock:
                client_info = {
                    'socket': client_socket,
                    'aes_key': aes_key,
                    'sharing': False,
                    'quality': self.default_screen_quality,
                    'scale': self.default_screen_scale,
                    'last_screenshot_time': 0
                }
                self.clients[client_addr_str] = client_info
            print(f"[*] Client {client_addr_str} added and secured.")

            sender_thread = threading.Thread(target=self._sender_loop, args=(client_addr_str,), daemon=True)
            sender_thread.start()

            self._receiver_loop(client_addr_str, client_socket, aes_key)

        except (ConnectionError, socket.error, BrokenPipeError, ConnectionResetError) as e:
             print(f"[!] Connection error with {client_addr_str}: {e}")
        except Exception as e:
            print(f"[!] Unhandled error in handle_client for {client_addr_str}: {e}")
            traceback.print_exc()
        finally:
            print(f"[-] Cleaning up connection from {client_addr_str}")
            with self.lock:
                 if client_addr_str in self.clients:
                     # Set sharing to false to stop sender loop gracefully
                     self.clients[client_addr_str]['sharing'] = False
                     del self.clients[client_addr_str]
            try: client_socket.close()
            except: pass
            print(f"[*] Client {client_addr_str} removed.")


    def _receiver_loop(self, client_addr_str, client_socket, aes_key):
        """Receive and process messages from a specific client."""
        while self.running:
            with self.lock:
                if client_addr_str not in self.clients:
                    print(f"[*] Receiver loop: Client {client_addr_str} disconnected, exiting.")
                    break

            try:
                data = self._recv(client_socket)
                if not data:
                    print(f"[!] Client {client_addr_str} disconnected (received empty data).")
                    break

                if len(data) < HEADER_TYPE_LEN:
                    print(f"[!] Invalid message length from {client_addr_str}. Len: {len(data)}")
                    continue # Or break?

                msg_type = data[:HEADER_TYPE_LEN].decode('utf-8')
                encrypted_payload = data[HEADER_TYPE_LEN:]

                decrypted_payload = self._decrypt_aes(encrypted_payload, aes_key)
                if decrypted_payload:
                    self._handle_command(msg_type, decrypted_payload, client_addr_str)
                    if msg_type == MSG_DISCONNECT:
                        print(f"[*] Client {client_addr_str} sent disconnect signal.")
                        break # Exit receiver loop
                else:
                    print(f"[!] Failed to decrypt message type '{msg_type}' from {client_addr_str}")

            except (socket.error, ConnectionResetError, BrokenPipeError) as e:
                 print(f"[!] Socket error receiving from {client_addr_str}: {e}")
                 break
            except Exception as e:
                 print(f"[!] Unexpected error in receiver loop for {client_addr_str}: {e}")
                 traceback.print_exc()
                 break


    def _sender_loop(self, client_addr_str):
        print(f"[*] Sender loop started for {client_addr_str}")
        while self.running:
            client_info = None
            with self.lock:
                 if client_addr_str in self.clients:
                    client_info = self.clients[client_addr_str].copy()
                 else:
                     break

            if client_info and client_info.get('sharing'):
                 try:
                     now = time.time()
                     if now - client_info.get('last_screenshot_time', 0) >= 0.1: # ~10 FPS
                         socket_to_use = client_info['socket']
                         key_to_use = client_info['aes_key']
                         scale = client_info['scale']
                         quality = client_info['quality']

                         if self._send_screenshot(socket_to_use, key_to_use, scale, quality):
                             with self.lock:
                                if client_addr_str in self.clients:
                                    self.clients[client_addr_str]['last_screenshot_time'] = now
                         else:
                             print(f"[*] Sender loop: Failed to send screenshot, client likely gone. Exiting {client_addr_str}.")
                             break # Exit loop if send fails (socket error)

                 except Exception as e:
                     print(f"[!] Error in sender loop for {client_addr_str}: {e}")
                     traceback.print_exc()
                     break
            time.sleep(0.05 if client_info and client_info.get('sharing') else 0.2)
        print(f"[*] Sender loop stopped for {client_addr_str}")


    def _key_exchange(self, client_socket, client_address):
        try:
            public_key_bytes = self.public_key.export_key()
            if not self._send(client_socket, public_key_bytes):
                raise ConnectionError("Failed to send public key.")
            print(f"[*] Sent public key to {client_address}")

            client_socket.settimeout(15.0)
            encrypted_aes_key = self._recv(client_socket)
            client_socket.settimeout(None)

            if not encrypted_aes_key:
                 raise ConnectionError("Client disconnected before sending AES key")

            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)

            if len(aes_key) != 32:
                raise ValueError("Decrypted AES key has incorrect length")

            print(f"[*] Received and decrypted AES key from {client_address}")
            return aes_key
        except (socket.timeout, ValueError, TypeError, ConnectionError) as e:
            print(f"[!] Key exchange failed with {client_address}: {e}")
            return None
        except Exception as e:
             print(f"[!] Unexpected error during key exchange with {client_address}: {e}")
             traceback.print_exc()
             return None

    def _encrypt_aes(self, payload_dict, key):
        try:
            message_json = json.dumps(payload_dict)
            message_bytes = message_json.encode('utf-8')
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(message_bytes, AES.block_size))
            return iv + ct_bytes
        except Exception as e:
             print(f"[!] AES Encryption error: {e}")
             return None

    def _decrypt_aes(self, encrypted_payload_bytes, key):
        try:
            if len(encrypted_payload_bytes) < 16: return None
            iv = encrypted_payload_bytes[:16]
            ciphertext = encrypted_payload_bytes[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(ciphertext)
            decrypted = unpad(decrypted_padded, AES.block_size)
            message_json = decrypted.decode('utf-8')
            return json.loads(message_json)
        except Exception as e:
            print(f"[!] AES decryption error: {e}")
            return None

    def _send_message(self, client_socket, aes_key, msg_type_code, payload_dict):
        try:
            encrypted_payload = self._encrypt_aes(payload_dict, aes_key)
            if not encrypted_payload:
                print(f"[!] Failed to encrypt payload for {msg_type_code.strip()}")
                return False

            type_header = msg_type_code.ljust(HEADER_TYPE_LEN).encode('utf-8')
            full_message = type_header + encrypted_payload

            return self._send(client_socket, full_message)

        except Exception as e:
             print(f"[!] Error sending message '{msg_type_code.strip()}': {e}")
             return False

    def _handle_command(self, command_type_code, payload, client_addr_str):
        if command_type_code == MSG_KEY:
            key = payload.get('key')
            key_kind = payload.get('key_kind')
            state = payload.get('state')
            if key and state and key_kind is not None:
                self._handle_key_event(key, key_kind, state)
            else:
                print(f"[!] Invalid key_event payload from {client_addr_str}: {payload}")

        elif command_type_code == MSG_CONTROL:
             action = payload.get('action')
             with self.lock:
                 if client_addr_str not in self.clients: return
                 client_info = self.clients[client_addr_str]
                 if action == 'start':
                     client_info['sharing'] = True
                     print(f"[*] Started screen sharing for {client_addr_str}")
                 elif action == 'stop':
                     client_info['sharing'] = False
                     print(f"[*] Stopped screen sharing for {client_addr_str}")
                 elif action == 'quality':
                     try:
                         quality = int(payload.get('value', self.default_screen_quality))
                         client_info['quality'] = max(1, min(100, quality))
                         print(f"[*] Screen quality for {client_addr_str} set to {client_info['quality']}")
                     except (ValueError, TypeError): pass
                 elif action == 'scale':
                     try:
                         scale = float(payload.get('value', self.default_screen_scale))
                         client_info['scale'] = max(0.1, min(1.0, scale))
                         print(f"[*] Screen scale for {client_addr_str} set to {client_info['scale']}")
                     except (ValueError, TypeError): pass
                 else:
                     print(f"[!] Unknown screen control action: {action}")

        elif command_type_code == MSG_MSG:
            content = payload.get('content', '')
            print(f"[*] Message from {client_addr_str}: {content}")

        elif command_type_code == MSG_DISCONNECT:
             print(f"[*] Disconnect command received from {client_addr_str}.")
        else:
            print(f"[?] Unknown command type code: {command_type_code}")

    def _send_screenshot(self, client_socket, aes_key, scale, quality):
        try:
            screenshot = ImageGrab.grab()
            if scale != 1.0:
                 width, height = screenshot.size
                 new_size = (int(width * scale), int(height * scale))
                 screenshot = screenshot.resize(new_size, Image.Resampling.LANCZOS)

            img_byte_array = io.BytesIO()
            screenshot.save(img_byte_array, format='JPEG', quality=quality, optimize=True, progressive=True)
            img_bytes = img_byte_array.getvalue()
            encoded_data = base64.b64encode(img_bytes).decode('utf-8')
            payload = {'data': encoded_data}
            return self._send_message(client_socket, aes_key, MSG_SCREEN, payload)

        except Exception as e:
            print(f"[!] Error capturing/processing screenshot: {e}")
            return False # Indicate failure


    def _handle_key_event(self, key, key_kind, state):
        try:
            key_to_process = key.lower()
            key_map = {'cmd': 'win', 'alt_gr': 'alt gr'}
            key_to_process = key_map.get(key_to_process, key_to_process)

            if state == 'down':
                keyboard.press(key_to_process)
            elif state == 'up':
                keyboard.release(key_to_process)
        except Exception as e:
            print(f"[!] Error executing key event (Key: {key}, State: {state}): {e}")

    def stop(self):
        if not self.running: return
        self.running = False
        print("[*] Initiating server shutdown sequence...")

if __name__ == "__main__":
    server = Server()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Keyboard interrupt received, shutting down server.")
    except Exception as e:
         print(f"\n[!!!] Main thread encountered an error: {e}")
    finally:
         server.stop()
         print("[*] Main thread exiting.")