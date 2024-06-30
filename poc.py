#!/usr/bin/python3
import wave
import struct
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

banner = '''
  _______                _____                  _   
 |__   __|              / ____|                | |  
    | |_   _ _ __   ___| |     _ __ _   _ _ __ | |_ 
    | | | | | '_ \\ / _ \\ |    | '__| | | | '_ \\| __|
    | | |_| | | | |  __/ |____| |  | |_| | |_) | |_ 
    |_|\\__,_|_| |_|\\___|\\_____|_|   \\__, | .__/ \\__|
                                     __/ | |        
                                    |___/|_|        
Developed by Emrecan OKSUM in 01.07.2024 for educational purposes!
If you engage in any illegal activity the author does not take any
responsibility for it. By using this software you agree with these
terms.
'''

# Function to generate RSA keys
def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt data with RSA
def encrypt_data(data, public_key):
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

# Function to decrypt data with RSA
def decrypt_data(encrypted_data, private_key):
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data

# Function to convert bytes to octals
def bytes_to_octals(data_bytes):
    return [oct(byte) for byte in data_bytes]

# Function to convert octals back to bytes
def octals_to_bytes(octal_data):
    return bytes(int(oct_byte, 8) for oct_byte in octal_data)

# Function to save octal data to a WAV file
def save_to_wav(octal_data, filename):
    with wave.open(filename, 'w') as wav_file:
        n_channels = 1
        sampwidth = 1
        framerate = 44100
        n_frames = len(octal_data)
        comp_type = 'NONE'
        comp_name = 'not compressed'

        wav_file.setparams((n_channels, sampwidth, framerate, n_frames, comp_type, comp_name))

        # Convert octal data back to bytes for WAV file
        byte_data = [int(oct_byte, 8) for oct_byte in octal_data]
        frame_data = struct.pack('<' + 'B' * len(byte_data), *byte_data)
        wav_file.writeframes(frame_data)

# Function to read octal data from a WAV file
def read_from_wav(filename):
    with wave.open(filename, 'r') as wav_file:
        frames = wav_file.readframes(wav_file.getnframes())
        octal_data = [oct(byte) for byte in frames]
    return octal_data

# Function to serialize a key to PEM format
def serialize_key(key, private=False):
    if private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

# Function to encrypt large files by chunks
def encrypt_file_in_chunks(file_path, public_key, chunk_size=190):
    octal_data = []
    with open(file_path, 'rb') as file:
        while chunk := file.read(chunk_size):
            encrypted_chunk = encrypt_data(chunk, public_key)
            octal_data.extend(bytes_to_octals(encrypted_chunk))
    return octal_data

# Function to decrypt large files by chunks
def decrypt_file_in_chunks(octal_data, private_key, chunk_size=256):
    decrypted_data = b""
    num_chunks = len(octal_data) // chunk_size
    for i in range(num_chunks):
        chunk = octal_data[i*chunk_size:(i+1)*chunk_size]
        encrypted_chunk = octals_to_bytes(chunk)
        decrypted_chunk = decrypt_data(encrypted_chunk, private_key)
        decrypted_data += decrypted_chunk
    return decrypted_data

# Menu for user to pick actions
def menu():
    while True:
        print(banner)
        print("Select an action:")
        print("1. Generate a RSA 2048 keypair and encrypt data")
        print("2. Encrypt data with a public key")
        print("3. Decrypt data with a private key")
        print("4. Exit")
        choice = input("Enter choice (1-4): ")

        if choice == '1':
            # Generate a keypair
            private_key, public_key = generate_keypair()
            print("Generated RSA keypair:")
            print(serialize_key(private_key, private=True).decode())
            print(serialize_key(public_key).decode())
            
            # Input data to encrypt
            path = input("Enter file location to encrypt: ")
            if not os.path.isfile(path):
                print("File cannot be found!")
                continue
            
            print("Encrypting please wait...")
            octal_data = encrypt_file_in_chunks(path, public_key)
            
            # Save the octal data to a WAV file
            save_to_wav(octal_data, 'encrypted_data.wav')
            print("Data has been encrypted and saved to encrypted_data.wav")
        
        elif choice == '2':
            # Input public key file
            public_key_file = input("Enter public key file path: ")
            if not os.path.isfile(public_key_file):
                print("Public key file cannot be found!")
                continue
            
            try:
                with open(public_key_file, 'rb') as key_file:
                    public_key_pem = key_file.read()
                public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
            except Exception as e:
                print("Invalid public key format:", e)
                continue
            
            # Input data to encrypt
            path = input("Enter file location to encrypt: ")
            if not os.path.isfile(path):
                print("File cannot be found!")
                continue
            
            print("Encrypting please wait...")
            octal_data = encrypt_file_in_chunks(path, public_key)
            
            # Save the octal data to a WAV file
            save_to_wav(octal_data, 'encrypted_data.wav')
            print("Data has been encrypted and saved to encrypted_data.wav")
        
        elif choice == '3':
            # Input private key file
            private_key_file = input("Enter private key file path: ")
            if not os.path.isfile(private_key_file):
                print("Private key file cannot be found!")
                continue
            
            try:
                with open(private_key_file, 'rb') as key_file:
                    private_key_pem = key_file.read()
                private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
            except Exception as e:
                print("Invalid private key format:", e)
                continue
            
            # Read octal data from WAV file
            wav_file_loc = input("Please input the desired wav file location for decryption: ")
            if not os.path.isfile(wav_file_loc):
                print("WAV file cannot be found!")
                continue
            
            print("Reading octal blocks, please wait...")
            
            try:
                octal_data = read_from_wav(wav_file_loc)
            except Exception as e:
                print("Error reading WAV file:", e)
                continue
            
            # Decrypt data
            print("Decrypting please wait...")
            try:
                decrypted_data = decrypt_file_in_chunks(octal_data, private_key)
                output_file = 'decrypted_data.bin'
                with open(output_file, 'wb') as file:
                    file.write(decrypted_data)
                print(f"Data has been decrypted and saved to {output_file}")
            except Exception as e:
                print("Decryption failed:", e)
        
        elif choice == '4':
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")

# Run the menu
if __name__ == "__main__":
    menu()
