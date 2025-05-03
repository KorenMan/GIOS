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

class Server:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {} # Store client info: {client_addr: {'socket': socket, 'aes_key': key, 'sharing': bool}}
        self.lock = threading.Lock() # Lock for accessing shared client data

        # Generate RSA keys
        self.key = RSA.generate(2048)
        self.private_key = self.key
        self.public_key = self.key.publickey()

        # Screen sharing settings (per client)
        self.default_screen_quality = 70 # Default JPEG quality (1-100)
        self.default_screen_scale = 0.75  # Default scale factor (0.1-1.0)

        self.running = False


    def start(self):
        """Start the server and listen for connections"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            print(f"[*] Server started on {self.host}:{self.port}")

            while self.running:
                try:
                     # Accept connections with a timeout to allow checking self.running
                    self.server_socket.settimeout(1.0)
                    client_socket, client_address = self.server_socket.accept()
                    self.server_socket.settimeout(None) # Reset timeout

                    print(f"[+] Connection from {client_address}")

                    # Start a thread to handle the client
                    client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue # Loop back to check self.running
                except Exception as e:
                     if self.running: # Don't print error if we are shutting down
                         print(f"[!] Error accepting connection: {e}")

        except Exception as e:
            print(f"[!] Server error: {e}")
        finally:
            print("[*] Server shutting down...")
            self.running = False
            # Close all client sockets
            with self.lock:
                for addr, client_info in list(self.clients.items()):
                    try:
                        client_info['socket'].shutdown(socket.SHUT_RDWR)
                        client_info['socket'].close()
                    except:
                        pass
                self.clients.clear()

            if self.server_socket:
                self.server_socket.close()
            print("[*] Server stopped.")


    def handle_client(self, client_socket, client_address):
        """Handle handshake, message receiving, and screen sending for a client"""
        client_addr_str = f"{client_address[0]}:{client_address[1]}"
        aes_key = None
        try:
            # Perform key exchange first
            aes_key = self._key_exchange(client_socket, client_address)
            if not aes_key:
                 raise ConnectionError("Key exchange failed.")

            # Store client info
            with self.lock:
                self.clients[client_addr_str] = {
                    'socket': client_socket,
                    'aes_key': aes_key,
                    'sharing': False, # Screen sharing off by default
                    'quality': self.default_screen_quality,
                    'scale': self.default_screen_scale,
                    'last_screenshot_time': 0
                }
            print(f"[*] Client {client_addr_str} added.")

            # Start sender thread (for screenshots) for this client
            sender_thread = threading.Thread(target=self._sender_loop, args=(client_addr_str,))
            sender_thread.daemon = True
            sender_thread.start()

            # Start receiver loop (for commands) for this client
            self._receiver_loop(client_socket, client_addr_str, aes_key)


        except (ConnectionError, socket.error, BrokenPipeError, ConnectionResetError) as e:
             print(f"[!] Connection error with {client_addr_str}: {e}")
        except Exception as e:
            print(f"[!] Error handling client {client_addr_str}: {e}")
        finally:
            print(f"[-] Cleaning up connection from {client_addr_str}")
            with self.lock:
                 if client_addr_str in self.clients:
                     del self.clients[client_addr_str]
            try:
                 client_socket.close()
            except:
                 pass # Socket might already be closed


    def _receiver_loop(self, client_socket, client_addr_str, aes_key):
        """Receive and process messages from a specific client"""
        buffer = b""
        payload_len = -1

        while self.running:
            try:
                # Check if client still exists (might be removed by disconnect)
                with self.lock:
                    if client_addr_str not in self.clients:
                        break # Exit if client disconnected

                # Receive data with a timeout to prevent blocking indefinitely
                client_socket.settimeout(1.0)
                data = client_socket.recv(4096)
                client_socket.settimeout(None) # Reset timeout

                if not data:
                    print(f"[!] Client {client_addr_str} disconnected (received empty data).")
                    break # Exit loop on disconnect

                buffer += data

                # Process buffer
                while True:
                     if payload_len == -1: # Waiting for length prefix
                         if len(buffer) >= 4:
                             payload_len = int.from_bytes(buffer[:4], byteorder='big')
                             buffer = buffer[4:]
                         else:
                             break # Need more data for length

                     if payload_len != -1 and len(buffer) >= payload_len: # Have complete message
                         payload_data = buffer[:payload_len]
                         buffer = buffer[payload_len:]
                         payload_len = -1 # Reset for next message

                         # Decrypt and process the message
                         try:
                             decrypted_message = self._decrypt_aes(payload_data, aes_key)
                             if decrypted_message:
                                 self._handle_command(decrypted_message, client_addr_str)
                             else:
                                 print(f"[!] Failed to decrypt message from {client_addr_str}")
                         except Exception as e:
                             print(f"[!] Error processing message from {client_addr_str}: {e}")
                     else:
                         break # Need more data for payload

            except socket.timeout:
                 continue # No data received, loop again
            except (socket.error, ConnectionResetError, BrokenPipeError) as e:
                 print(f"[!] Socket error receiving from {client_addr_str}: {e}")
                 break # Exit loop on socket error
            except Exception as e:
                 print(f"[!] Unexpected error in receiver loop for {client_addr_str}: {e}")
                 break # Exit loop on other errors


    def _sender_loop(self, client_addr_str):
        """Periodically send screenshots to a specific client if enabled"""
        while self.running:
            client_info = None
            with self.lock:
                 if client_addr_str in self.clients:
                    client_info = self.clients[client_addr_str]
                 else:
                     break # Client disconnected, exit sender loop

            if client_info and client_info['sharing']:
                 try:
                     # Simple rate limiting (e.g., ~10 FPS max)
                     now = time.time()
                     if now - client_info.get('last_screenshot_time', 0) > 0.1:
                         self._send_screenshot(client_info['socket'], client_addr_str, client_info['aes_key'])
                         # Update last sent time (even if sending failed, to avoid spamming attempts)
                         with self.lock:
                            if client_addr_str in self.clients: # Check again as client might disconnect during send
                                self.clients[client_addr_str]['last_screenshot_time'] = now

                 except (socket.error, ConnectionResetError, BrokenPipeError) as e:
                     print(f"[!] Socket error sending screenshot to {client_addr_str}: {e}")
                     # Assume client disconnected, let main handler clean up
                     break
                 except Exception as e:
                     print(f"[!] Error in sender loop for {client_addr_str}: {e}")
                     # Optionally disable sharing for this client on repeated errors
                     # with self.lock:
                     #    if client_addr_str in self.clients:
                     #        self.clients[client_addr_str]['sharing'] = False
                     break # Exit on unexpected errors for now

            # Sleep briefly regardless of sending to avoid busy-waiting
            time.sleep(0.05) # Adjust sleep time to balance responsiveness and CPU usage

        # print(f"[*] Sender loop stopped for {client_addr_str}")


    def _key_exchange(self, client_socket, client_address):
        """Perform RSA key exchange and establish AES key"""
        try:
            # Send our public key to client
            public_key_bytes = self.public_key.export_key()
            client_socket.sendall(public_key_bytes)
            print(f"[*] Sent public key to {client_address}")

            # Receive the encrypted AES key from the client
            # Add timeout for receiving key
            client_socket.settimeout(10.0)
            encrypted_aes_key = client_socket.recv(4096) # Key size is 256 bytes encrypted by 2048 RSA
            client_socket.settimeout(None) # Reset timeout

            if not encrypted_aes_key:
                 raise ConnectionError("Client disconnected before sending AES key")

            # Decrypt the AES key using our private RSA key
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            print(f"[*] Received and decrypted AES key from {client_address}")
            return aes_key
        except socket.timeout:
            print(f"[!] Timeout waiting for AES key from {client_address}")
            return None
        except Exception as e:
            print(f"[!] Key exchange failed with {client_address}: {e}")
            return None

    def _encrypt_aes(self, message_data, key):
        """Encrypt data using AES"""
        try:
            message_json = json.dumps(message_data)
            message_bytes = message_json.encode('utf-8')
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(message_bytes, AES.block_size))
            encrypted_package = {
                'iv': base64.b64encode(iv).decode('utf-8'),
                'ciphertext': base64.b64encode(ct_bytes).decode('utf-8')
            }
            return json.dumps(encrypted_package).encode('utf-8')
        except Exception as e:
             print(f"[!] AES Encryption error: {e}")
             return None

    def _decrypt_aes(self, encrypted_data, key):
        """Decrypt data using AES"""
        try:
            package_str = encrypted_data.decode('utf-8')
            data_dict = json.loads(package_str)
            iv = base64.b64decode(data_dict['iv'])
            ciphertext = base64.b64decode(data_dict['ciphertext'])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(ciphertext)
            decrypted = unpad(decrypted_padded, AES.block_size)
            message_json = decrypted.decode('utf-8')
            return json.loads(message_json)
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
            print(f"[!] AES decryption/parsing error: {e}")
            # print(f"Raw data snippet: {encrypted_data[:100]}...") # Debug
            return None
        except Exception as e:
            print(f"[!] Unexpected AES decryption error: {e}")
            return None

    def _send_message(self, client_socket, aes_key, msg_type, payload):
        """Encrypt and send a message to a specific client"""
        try:
            message_data = {'type': msg_type, **payload}
            encrypted_message = self._encrypt_aes(message_data, aes_key)
            if encrypted_message:
                # Add length prefix
                msg_len = len(encrypted_message)
                len_prefix = msg_len.to_bytes(4, byteorder='big')
                client_socket.sendall(len_prefix + encrypted_message)
                return True
            else:
                return False
        except (socket.error, BrokenPipeError) as e:
             print(f"[!] Socket error sending message type {msg_type}: {e}")
             # Let the caller handle disconnect logic
             raise # Re-raise socket errors
        except Exception as e:
             print(f"[!] Error sending message type {msg_type}: {e}")
             return False


    def _handle_command(self, message_data, client_addr_str):
        """Handle commands received from the client"""
        command_type = message_data.get('type')
        # print(f"[*] Received command from {client_addr_str}: {command_type}") # Debug

        if command_type == 'key_event':
            key = message_data.get('key')
            key_kind = message_data.get('key_kind') # Correctly get 'key_kind' from payload
            state = message_data.get('state')
            if key and state and key_kind is not None: # Check key_kind exists
                # Pass key_kind (which contains 'char' or 'special')
                self._handle_key_event(key, key_kind, state)
            else:
                print(f"[!] Invalid key_event received from {client_addr_str}: {message_data}")

        elif command_type == 'screen_control':
             action = message_data.get('action')
             with self.lock: # Lock when modifying client state
                 if client_addr_str not in self.clients: return # Client disconnected

                 client_info = self.clients[client_addr_str]
                 if action == 'start':
                     client_info['sharing'] = True
                     print(f"[*] Started screen sharing for {client_addr_str}")
                 elif action == 'stop':
                     client_info['sharing'] = False
                     print(f"[*] Stopped screen sharing for {client_addr_str}")
                 elif action == 'quality':
                     quality = int(message_data.get('value', self.default_screen_quality))
                     client_info['quality'] = max(1, min(100, quality))
                     print(f"[*] Screen quality for {client_addr_str} set to {client_info['quality']}")
                 elif action == 'scale':
                     scale = float(message_data.get('value', self.default_screen_scale))
                     client_info['scale'] = max(0.1, min(1.0, scale))
                     print(f"[*] Screen scale for {client_addr_str} set to {client_info['scale']}")

        elif command_type == 'message': # Example: Handle simple text messages
            content = message_data.get('content', '')
            print(f"[*] Message from {client_addr_str}: {content}")

        elif command_type == 'disconnect': # Optional: Handle explicit disconnect message
             print(f"[*] Client {client_addr_str} requested disconnect.")
             # The main loop will handle the cleanup when the socket closes

        else:
            print(f"[?] Unknown command type from {client_addr_str}: {command_type}")


    def _send_screenshot(self, client_socket, client_addr_str, aes_key):
        """Capture, process, and send a screenshot to the client"""
        try:
            # Get scale and quality for this specific client
            scale = self.default_screen_scale
            quality = self.default_screen_quality
            with self.lock:
                 if client_addr_str in self.clients:
                     scale = self.clients[client_addr_str]['scale']
                     quality = self.clients[client_addr_str]['quality']
                 else:
                     return # Client disconnected

            # Capture the screenshot
            screenshot = ImageGrab.grab()

            # Resize if scale is not 1.0
            if scale != 1.0:
                 width, height = screenshot.size
                 new_size = (int(width * scale), int(height * scale))
                 screenshot = screenshot.resize(new_size, Image.Resampling.LANCZOS) # Use LANCZOS for better quality resize

            # Convert to JPEG bytes
            img_byte_array = io.BytesIO()
            screenshot.save(img_byte_array, format='JPEG', quality=quality)
            img_bytes = img_byte_array.getvalue()

            # Encode as base64
            encoded_data = base64.b64encode(img_bytes).decode('utf-8')

            # Send the message
            payload = {'data': encoded_data}
            # print(f"[*] Sending screenshot to {client_addr_str}, size={len(encoded_data)}") # Debug
            if not self._send_message(client_socket, aes_key, 'screenshot', payload):
                 print(f"[!] Failed to send screenshot message to {client_addr_str}")
                 # Error handled by caller (sender_loop or handle_client)

        except Exception as e:
            print(f"[!] Error capturing/sending screenshot: {e}")
            # Consider disabling sharing for this client on error
            # with self.lock:
            #     if client_addr_str in self.clients:
            #         self.clients[client_addr_str]['sharing'] = False
            raise # Re-raise exception to be caught by sender loop


    def _handle_key_event(self, key, key_type, state):
        """Execute the keyboard event on the server using the 'keyboard' library"""
        try:
            key_to_process = key.lower() # Normalize key name

            # --- Debugging (Optional: update if you use it) ---
            # print(f"[*] Executing key event: Key='{key_to_process}', Kind='{key_kind}', State='{state}'") # Uses key_kind

            if state == 'down':
                keyboard.press(key_to_process)
            elif state == 'up':
                keyboard.release(key_to_process)

            # --- Debugging ---
            # print(f"[*] Executing key event: Key='{key_to_process}', Type='{key_type}', State='{state}'")
            # --- End Debugging ---

            if state == 'down':
                keyboard.press(key_to_process)
                # print(f"   [Keyboard Lib] Pressed: {key_to_process}") # Debug
            elif state == 'up':
                keyboard.release(key_to_process)
                # print(f"   [Keyboard Lib] Released: {key_to_process}") # Debug

        except ValueError as e:
             # keyboard library might raise ValueError for unknown keys
             print(f"[!] Warning: Unknown key '{key}' received: {e}")
        except Exception as e:
            print(f"[!] Error executing key event (Key: {key}, State: {state}): {e}")
            # Add more specific error handling if needed


    def stop(self):
        """Stop the server gracefully"""
        self.running = False
        print("[*] Initiating server shutdown...")
        # The main loop and finally block in start() will handle closing sockets.



if __name__ == "__main__":
    server = Server()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Keyboard interrupt received, shutting down server.")
        server.stop()
    except Exception as e:
         print(f"\n[!!!] Server crashed: {e}")
         server.stop() # Attempt graceful shutdown on crash