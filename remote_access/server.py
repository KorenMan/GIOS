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
import traceback # For detailed error printing

# --- Protocol Constants ---
MSG_KEY = "KEY "
MSG_SCREEN = "SCRN"
MSG_CONTROL = "CTRL"
MSG_MSG = "MESG"
MSG_ERR = "ERR "
MSG_DISCONNECT = "BYE "
# Ensure codes are 4 bytes
HEADER_TYPE_LEN = 4
HEADER_SIZE_LEN = 8
# --- End Protocol Constants ---

class Server:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {} # {client_addr_str: {'socket': socket, 'aes_key': key, ...}}
        self.lock = threading.Lock() # Lock for accessing clients dict

        # Generate RSA keys
        self.key = RSA.generate(2048)
        self.private_key = self.key
        self.public_key = self.key.publickey()

        # Screen sharing defaults (can be overridden per client)
        self.default_screen_quality = 70
        self.default_screen_scale = 0.75

        self.running = False


    def start(self):
        """Start the server and listen for connections"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5) # Listen backlog
            self.running = True
            print(f"[*] Server started on {self.host}:{self.port}")

            while self.running:
                try:
                    self.server_socket.settimeout(1.0) # Timeout to check self.running
                    client_socket, client_address = self.server_socket.accept()
                    self.server_socket.settimeout(None)

                    print(f"[+] Connection from {client_address}")
                    self.handle_client(client_socket, client_address)

                except socket.timeout:
                    continue # Loop back to check self.running
                except Exception as e:
                     if self.running:
                         print(f"[!] Error accepting connection: {e}")

        except Exception as e:
            print(f"[!] Server main loop error: {e}")
        finally:
            print("[*] Server shutting down...")
            self.running = False
            # Close all client sockets gracefully
            with self.lock:
                client_sockets = [info['socket'] for info in self.clients.values()]
                self.clients.clear() # Clear client list

            for sock in client_sockets:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                except:
                    pass # Ignore errors on closing already closed sockets

            if self.server_socket:
                self.server_socket.close()
            print("[*] Server stopped.")


    def handle_client(self, client_socket, client_address):
        """Handle handshake, message receiving, and screen sending for a client"""
        client_addr_str = f"{client_address[0]}:{client_address[1]}"
        aes_key = None
        client_info = None # Use a local var to store client details

        try:
            # 1. Key Exchange
            aes_key = self._key_exchange(client_socket, client_address)
            if not aes_key:
                 raise ConnectionError("Key exchange failed.")

            # 2. Store client info (needs lock)
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

            # 3. Start Sender Thread (Pass necessary info)
            sender_thread = threading.Thread(target=self._sender_loop, args=(client_addr_str,))
            sender_thread.start()

            # 4. Start Receiver Loop (Handles commands and detects disconnect)
            self._receiver_loop(client_addr_str) # Pass only addr, lookup info inside

        except (ConnectionError, socket.error, BrokenPipeError, ConnectionResetError) as e:
             print(f"[!] Connection error with {client_addr_str}: {e}")
        except Exception as e:
            print(f"[!] Unhandled error in handle_client for {client_addr_str}: {e}")
            traceback.print_exc() # Print full traceback
        finally:
            print(f"[-] Cleaning up connection from {client_addr_str}")
            # Remove client from dict (use lock)
            with self.lock:
                 if client_addr_str in self.clients:
                     del self.clients[client_addr_str]
            # Close socket
            try:
                 client_socket.close()
            except:
                 pass
            print(f"[*] Client {client_addr_str} removed.")


    def _receiver_loop(self, client_addr_str):
        """Receive and process messages from a specific client using custom protocol"""
        buffer = b""
        expected_len = -1
        msg_type = None
        header_len = HEADER_TYPE_LEN + HEADER_SIZE_LEN
        client_socket = None
        aes_key = None

        # Initial lookup for socket and key
        with self.lock:
            if client_addr_str in self.clients:
                client_socket = self.clients[client_addr_str]['socket']
                aes_key = self.clients[client_addr_str]['aes_key']
            else:
                print(f"[!] Receiver loop started for non-existent client {client_addr_str}")
                return # Exit if client already gone

        if not client_socket or not aes_key:
             print(f"[!] Critical error: Missing socket or key for receiver {client_addr_str}")
             return # Should not happen if lock is used correctly

        while self.running:
            # Check if client still exists before blocking recv
            with self.lock:
                if client_addr_str not in self.clients:
                    print(f"[*] Receiver loop: Client {client_addr_str} disconnected, exiting.")
                    break # Exit if client removed by another thread

            try:
                # Set timeout for recv to allow checking self.running and client existence
                client_socket.settimeout(1.0)
                data = client_socket.recv(4096)
                client_socket.settimeout(None) # Reset after successful recv

                if not data:
                    print(f"[!] Client {client_addr_str} disconnected (received empty data).")
                    break # Exit loop on graceful disconnect

                buffer += data

                # Process buffer for completed messages
                while True:
                     if expected_len == -1: # Waiting for header
                         if len(buffer) >= header_len:
                             # --- FIX: Remove .strip() from type_header decoding ---
                             type_header = buffer[:HEADER_TYPE_LEN].decode('utf-8')
                             # --- Keep .strip() for size_header ---
                             size_header = buffer[HEADER_TYPE_LEN:header_len].decode('utf-8').strip()
                             buffer = buffer[header_len:]
                             try:
                                 expected_len = int(size_header)
                                 # msg_type will now correctly be "KEY " (or other padded codes)
                                 msg_type = type_header
                                 # print(f"[*] Srv Recv: Type '{msg_type}', Size {expected_len}") # Debug
                             except ValueError:
                                 print(f"[!] Invalid size header from {client_addr_str}: '{size_header}'")
                                 # Protocol error - force disconnect in handle_client's finally block
                                 return # Exit receiver loop
                         else:
                             break # Need more data for header

                     if expected_len != -1 and len(buffer) >= expected_len: # Have complete payload
                         encrypted_payload = buffer[:expected_len]
                         buffer = buffer[expected_len:]

                         # Decrypt and handle
                         try:
                             decrypted_payload = self._decrypt_aes(encrypted_payload, aes_key)
                             if decrypted_payload:
                                 # Handle command based on type code and payload dict
                                 self._handle_command(msg_type, decrypted_payload, client_addr_str)
                                 # Check if it was a disconnect message
                                 if msg_type == MSG_DISCONNECT:
                                      print(f"[*] Client {client_addr_str} sent disconnect signal.")
                                      return # Exit receiver loop gracefully
                             else:
                                 print(f"[!] Failed to decrypt message type '{msg_type}' from {client_addr_str}")
                         except Exception as e:
                              print(f"[!] Error processing message from {client_addr_str}: {e}")
                              traceback.print_exc() # Log detailed error

                         # Reset for next message
                         expected_len = -1
                         msg_type = None
                     else:
                         break # Need more data for payload

            except socket.timeout:
                 continue # No data received, loop again check running/client status
            except (socket.error, ConnectionResetError, BrokenPipeError) as e:
                 print(f"[!] Socket error receiving from {client_addr_str}: {e}")
                 break # Exit loop, handle_client finally block will clean up
            except Exception as e:
                 print(f"[!] Unexpected error in receiver loop for {client_addr_str}: {e}")
                 traceback.print_exc()
                 break # Exit loop


    def _sender_loop(self, client_addr_str):
        """Periodically send screenshots to a specific client if enabled"""
        print(f"[*] Sender loop started for {client_addr_str}")
        while self.running:
            client_info = None
            # Use lock to safely access client data
            with self.lock:
                 if client_addr_str in self.clients:
                    # Get a copy or necessary fields to use outside the lock briefly
                    client_info = self.clients[client_addr_str].copy() # Shallow copy is fine
                 else:
                     print(f"[*] Sender loop: Client {client_addr_str} not found, exiting.")
                     break # Client disconnected, exit sender loop

            # Perform potentially blocking operations outside the lock
            if client_info and client_info.get('sharing'):
                 try:
                     now = time.time()
                     # Rate limiting (e.g., target ~10 FPS)
                     if now - client_info.get('last_screenshot_time', 0) >= 0.1:
                         socket_to_use = client_info['socket']
                         key_to_use = client_info['aes_key']

                         # Send screenshot (might block)
                         self._send_screenshot(socket_to_use, client_addr_str, key_to_use)

                         # Update last sent time ONLY IF send was successful (or attempted)
                         # Use lock again for the update
                         with self.lock:
                            if client_addr_str in self.clients: # Check again inside lock
                                self.clients[client_addr_str]['last_screenshot_time'] = now

                 except (socket.error, ConnectionResetError, BrokenPipeError) as e:
                     print(f"[!] Socket error sending screenshot to {client_addr_str}: {e}")
                     # Assume client disconnected, trigger cleanup by exiting loop
                     # The receiver loop or main handler will remove the client from the dict
                     break
                 except Exception as e:
                     print(f"[!] Error in sender loop for {client_addr_str}: {e}")
                     traceback.print_exc()
                     # Optional: Disable sharing for this client on error?
                     # with self.lock:
                     #    if client_addr_str in self.clients:
                     #        self.clients[client_addr_str]['sharing'] = False
                     # For now, let's just log and continue or break loop on severe errors
                     break # Exit on unexpected errors to be safe

            # Sleep briefly to avoid high CPU usage when not sending
            # Adjust sleep time based on desired responsiveness vs CPU load
            time.sleep(0.05 if client_info and client_info.get('sharing') else 0.2)

        print(f"[*] Sender loop stopped for {client_addr_str}")


    def _key_exchange(self, client_socket, client_address):
        """Perform RSA key exchange and establish AES key"""
        try:
            # 1. Send public key
            public_key_bytes = self.public_key.export_key()
            client_socket.sendall(public_key_bytes)
            print(f"[*] Sent public key to {client_address}")

            # 2. Receive encrypted AES key
            client_socket.settimeout(15.0) # Timeout for receiving AES key
            # Adjust size based on RSA key size (e.g., 256 for 2048 bit RSA)
            encrypted_aes_key = client_socket.recv(256)
            client_socket.settimeout(None) # Reset timeout

            if not encrypted_aes_key:
                 raise ConnectionError("Client disconnected before sending AES key")
            if len(encrypted_aes_key) != 256: # Validate length for 2048 RSA
                 print(f"[!] Warning: Received encrypted AES key of unexpected length {len(encrypted_aes_key)} from {client_address}")
                 # Proceed but be aware it might fail decryption

            # 3. Decrypt AES key
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)

            if len(aes_key) != 32: # Validate AES key length (256 bits)
                raise ValueError("Decrypted AES key has incorrect length")

            print(f"[*] Received and decrypted AES key from {client_address}")
            return aes_key
        except socket.timeout:
            print(f"[!] Timeout waiting for AES key from {client_address}")
            return None
        except (ValueError, TypeError, ConnectionError) as e:
            print(f"[!] Key exchange failed with {client_address}: {e}")
            return None
        except Exception as e: # Catch other potential crypto errors
             print(f"[!] Unexpected error during key exchange with {client_address}: {e}")
             traceback.print_exc()
             return None

    def _encrypt_aes(self, payload_dict, key):
        """Encrypts payload dictionary using AES. Returns bytes (IV + ciphertext)."""
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
        """Decrypts raw AES payload (IV + ciphertext). Returns dictionary."""
        try:
            if len(encrypted_payload_bytes) < 16: return None # Payload too short
            iv = encrypted_payload_bytes[:16]
            ciphertext = encrypted_payload_bytes[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(ciphertext)
            decrypted = unpad(decrypted_padded, AES.block_size)
            message_json = decrypted.decode('utf-8')
            return json.loads(message_json)
        except (ValueError, KeyError) as e: # Catches unpadding errors etc.
            print(f"[!] AES decryption/unpadding error: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"[!] JSON decoding error after decryption: {e}")
            return None
        except Exception as e:
            print(f"[!] Unexpected AES decryption error: {e}")
            return None

    def _send_message(self, client_socket, aes_key, msg_type_code, payload_dict):
        """Encrypt payload and send message with custom header"""
        try:
            encrypted_payload = self._encrypt_aes(payload_dict, aes_key)
            if not encrypted_payload:
                print(f"[!] Failed to encrypt payload for {msg_type_code.strip()}")
                return False

            # Prepare headers
            type_header = msg_type_code.ljust(HEADER_TYPE_LEN).encode('utf-8')
            size_header = str(len(encrypted_payload)).ljust(HEADER_SIZE_LEN).encode('utf-8')

            # Send all parts
            client_socket.sendall(type_header + size_header + encrypted_payload)
            # print(f"[*] Srv Sent: {msg_type_code.strip()}, Size={len(encrypted_payload)}") # Debug
            return True

        except (socket.error, BrokenPipeError) as e:
             print(f"[!] Socket error sending '{msg_type_code.strip()}': {e}")
             raise # Re-raise socket errors to be handled by caller loops
        except Exception as e:
             print(f"[!] Error sending message '{msg_type_code.strip()}': {e}")
             traceback.print_exc()
             return False


    def _handle_command(self, command_type_code, payload, client_addr_str):
        """Handle commands received from the client based on type code"""
        # print(f"[*] Handling command '{command_type_code}' from {client_addr_str}") # Debug

        if command_type_code == MSG_KEY: # Key Event
            key = payload.get('key')
            key_kind = payload.get('key_kind') # 'char' or 'special'
            state = payload.get('state') # 'down' or 'up'
            if key and state and key_kind is not None:
                self._handle_key_event(key, key_kind, state) # Pass kind too if needed
            else:
                print(f"[!] Invalid key_event payload from {client_addr_str}: {payload}")

        elif command_type_code == MSG_CONTROL: # Screen Control
             action = payload.get('action')
             # Use lock to modify shared client state
             with self.lock:
                 if client_addr_str not in self.clients:
                     print(f"[!] Control command for disconnected client {client_addr_str}")
                     return # Client disconnected

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
                     except (ValueError, TypeError):
                         print(f"[!] Invalid quality value from {client_addr_str}: {payload.get('value')}")
                 elif action == 'scale':
                     try:
                         scale = float(payload.get('value', self.default_screen_scale))
                         client_info['scale'] = max(0.1, min(1.0, scale))
                         print(f"[*] Screen scale for {client_addr_str} set to {client_info['scale']}")
                     except (ValueError, TypeError):
                          print(f"[!] Invalid scale value from {client_addr_str}: {payload.get('value')}")
                 else:
                     print(f"[!] Unknown screen control action from {client_addr_str}: {action}")

        elif command_type_code == MSG_MSG: # Simple Message (example)
            content = payload.get('content', '')
            print(f"[*] Message from {client_addr_str}: {content}")
            # Example: Echo back
            # with self.lock:
            #     if client_addr_str in self.clients:
            #          info = self.clients[client_addr_str]
            #          self._send_message(info['socket'], info['aes_key'], MSG_MSG, {'content': f"Server received: {content}"})


        elif command_type_code == MSG_DISCONNECT:
             # Already handled in receiver loop (causes loop exit)
             # Just log here if needed
             print(f"[*] Disconnect command received from {client_addr_str}.")

        else:
            print(f"[?] Unknown command type code from {client_addr_str}: {command_type_code}")


    def _send_screenshot(self, client_socket, client_addr_str, aes_key):
        """Capture, process, and send a screenshot to the client"""
        scale = self.default_screen_scale
        quality = self.default_screen_quality
        # Get current settings safely (use lock)
        with self.lock:
             if client_addr_str in self.clients:
                 client_settings = self.clients[client_addr_str]
                 scale = client_settings.get('scale', self.default_screen_scale)
                 quality = client_settings.get('quality', self.default_screen_quality)
             else:
                 # Client disconnected between check in sender_loop and here
                 print(f"[*] Screenshot cancelled for disconnected client {client_addr_str}")
                 return # Don't try to send

        try:
            screenshot = ImageGrab.grab()

            if scale != 1.0:
                 width, height = screenshot.size
                 new_size = (int(width * scale), int(height * scale))
                 # Use ANTIALIAS or LANCZOS for better resize quality
                 screenshot = screenshot.resize(new_size, Image.Resampling.LANCZOS)

            img_byte_array = io.BytesIO()
            # Optimize JPEG, progressive might be slightly smaller sometimes
            screenshot.save(img_byte_array, format='JPEG', quality=quality, optimize=True, progressive=True)
            img_bytes = img_byte_array.getvalue()
            encoded_data = base64.b64encode(img_bytes).decode('utf-8')

            # Send using the standard message function
            payload = {'data': encoded_data}
            # print(f"[*] Sending screenshot size={len(encoded_data)} to {client_addr_str}") # Debug
            if not self._send_message(client_socket, aes_key, MSG_SCREEN, payload):
                 # Error is logged within _send_message, re-raise socket errors
                 pass # Let the sender loop handle potential socket errors raised by _send_message

        except Exception as e:
            print(f"[!] Error capturing/processing screenshot for {client_addr_str}: {e}")
            # Don't raise here, just log, let sender loop decide how to proceed
            # traceback.print_exc() # Uncomment for detailed debug


    def _handle_key_event(self, key, key_kind, state):
        """Execute the keyboard event on the server using the 'keyboard' library"""
        # Note: 'keyboard' library might require root/admin privileges on Linux/macOS
        try:
            # Normalize key representation if needed (e.g., special keys)
            # The 'keyboard' library handles many common names like 'ctrl', 'shift', 'alt', 'space' etc.
            # It might struggle with less common special keys or specific representations from pynput.
            key_to_process = key.lower() # Basic normalization

            # Map pynput names to keyboard names if necessary (example)
            key_map = {
                'cmd': 'win', # Map Mac Command key to Windows key
                'alt_gr': 'alt gr',
                # Add other mappings if issues arise
            }
            key_to_process = key_map.get(key_to_process, key_to_process)

            # print(f"[*] Executing: {state} '{key_to_process}' (Kind: {key_kind})") # Debug

            if state == 'down':
                keyboard.press(key_to_process)
            elif state == 'up':
                keyboard.release(key_to_process)

        except ValueError as e:
             # keyboard library often raises ValueError for unknown key names
             print(f"[!] Warning: Keyboard library couldn't process key '{key}' (processed as '{key_to_process}'): {e}")
        except Exception as e:
            print(f"[!] Error executing key event (Key: {key}, State: {state}): {e}")
            traceback.print_exc() # Log detailed error


    def stop(self):
        """Stop the server gracefully"""
        if not self.running: return # Already stopping/stopped
        self.running = False
        print("[*] Initiating server shutdown sequence...")
        # Join server accept loop? Not directly possible with accept timeout.
        # The main loop will exit, triggering the finally block for cleanup.


if __name__ == "__main__":
    server = Server()
    server.start()

    try:
        # Keep main thread alive until Ctrl+C
        while server.running:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Keyboard interrupt received, shutting down server.")
    except Exception as e:
         print(f"\n[!!!] Main thread encountered an error: {e}")
    finally:
         if server.running: # If shutdown wasn't initiated by Ctrl+C
             server.stop()
         # Wait briefly for server thread to finish cleanup
         # server_thread.join(timeout=5.0)
         print("[*] Main thread exiting.")