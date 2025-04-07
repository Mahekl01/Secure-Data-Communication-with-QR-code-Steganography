import qrcode
from cryptography.fernet import Fernet
from PIL import Image
import platform
import subprocess
import os
import urllib.parse
import io
import zlib
import base64


# ===== 1. Key Generation & Encryption Functions =====
def generate_key():
    """Generate a new encryption key"""
    return Fernet.generate_key()


def encrypt_message(message, key):
    """Encrypt a message using the key"""
    cipher = Fernet(key)
    return cipher.encrypt(message).decode('latin1')


def decrypt_message(encrypted_message, key):
    """Decrypt a message using the key"""
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_message.encode('latin1'))


# ===== 2. QR Code Generation =====
def generate_stegano_qr():
    """Generate QR code with user input"""
    public_url = input("Enter the public URL: ").strip()
    hidden_data = input("Enter the secret message to hide: ").strip()

    # Generate and display key
    key = generate_key()
    key_str = key.decode('latin1')
    print(f"\nEncryption key: {key_str}")

    # First create a QR code of the hidden data (using smallest possible version)
    hidden_qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=2,
        border=1
    )
    hidden_qr.add_data(hidden_data)
    hidden_qr.make(fit=True)

    # Create the hidden QR as a PIL image
    hidden_img = hidden_qr.make_image(fill="black", back_color="white")

    # Convert the hidden QR to bytes and compress
    img_byte_arr = io.BytesIO()
    hidden_img.save(img_byte_arr, format='PNG', optimize=True)
    img_bytes = img_byte_arr.getvalue()
    compressed_bytes = zlib.compress(img_bytes)

    # Split data if too large (for QR code version 40 with high error correction)
    max_chunk_size = 2953  # Conservative estimate for version 40-H
    chunks = [compressed_bytes[i:i + max_chunk_size] for i in range(0, len(compressed_bytes), max_chunk_size)]

    if len(chunks) > 1:
        print(f"Warning: Hidden QR code data is large and will be split into {len(chunks)} parts")

    for i, chunk in enumerate(chunks):
        # Encrypt the chunk
        encrypted_data = encrypt_message(chunk, key)
        url_encoded_data = urllib.parse.quote(encrypted_data)

        # Add chunk index if multiple chunks
        if len(chunks) > 1:
            qr_data = f"{public_url}?data={url_encoded_data}&chunk={i}&total={len(chunks)}"
        else:
            qr_data = f"{public_url}?data={url_encoded_data}"

        # Generate the main QR code
        qr = qrcode.QRCode(
            version=None,  # Auto-select version
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=4,
            border=4
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill="black", back_color="white")

        filename = f"CRYPTO_QR_{i + 1}.png" if len(chunks) > 1 else "CRYPTO_QR.png"
        img.save(filename)
        display_image(filename)
        print(f"\nQR code saved as {filename}")
        print(f"Scannable URL: {qr_data[:100]}...")  # Print first 100 chars of URL


# ===== 3. QR Code Decryption =====
def decrypt_qr():
    """Decrypt hidden message from QR"""
    qr_images = input("Enter QR code image paths (comma separated if multiple): ").strip()
    key_str = input("Enter your encryption key: ").strip()

    try:
        key = key_str.encode('latin1')
        chunks = {}

        # Handle multiple QR codes if needed
        for img_path in [p.strip() for p in qr_images.split(",") if p.strip()]:
            img = Image.open(img_path)
            decoded = decode(img)

            if decoded:
                url = decoded[0].data.decode("utf-8")
                parsed_url = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed_url.query)

                if "data" in query_params:
                    encrypted = urllib.parse.unquote(query_params["data"][0])

                    # Get chunk info if available
                    chunk_idx = int(query_params.get("chunk", [0])[0])
                    total_chunks = int(query_params.get("total", [1])[0])

                    # Decrypt the chunk
                    decrypted_chunk = decrypt_message(encrypted, key)
                    chunks[chunk_idx] = decrypted_chunk
                else:
                    print("No hidden data found in QR code")
            else:
                print(f"Failed to read QR code: {img_path}")

        # Combine chunks if multiple
        if len(chunks) > 1:
            print(f"Combining {len(chunks)} chunks...")
            combined_bytes = b''.join([chunks[i] for i in sorted(chunks.keys())])
        else:
            combined_bytes = next(iter(chunks.values()))

        # Decompress and create image
        decompressed_bytes = zlib.decompress(combined_bytes)

        # Convert bytes back to image
        hidden_qr_img = Image.open(io.BytesIO(decompressed_bytes))

        # Decode the hidden QR
        hidden_decoded = decode(hidden_qr_img)
        if hidden_decoded:
            secret = hidden_decoded[0].data.decode("utf-8")


            # Display the hidden QR
            hidden_qr_img.show()
        else:
            print("Could not decode the hidden QR code")

    except Exception as e:
        print(f"Error: {str(e)}")


# ===== 4. Helper Functions =====
def display_image(image_path):
    """Display the image using the default viewer"""
    try:
        if platform.system() == 'Windows':
            os.startfile(image_path)
        elif platform.system() == 'Darwin':
            subprocess.run(['open', image_path])
        else:
            subprocess.run(['xdg-open', image_path])
    except Exception as e:
        print(f"Couldn't display image: {str(e)}")


def decode(img):
    """Decode QR code with pyzbar"""
    from pyzbar.pyzbar import decode as qr_decode
    return qr_decode(img)


# ===== 5. Main Menu =====
def main():
    while True:
        print("\n" + "=" * 40)
        print("Secret QR Code System")
        print("1. Generate QR Code")
        print("2. Decrypt QR Code")
        print("3. Exit")
        choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            generate_stegano_qr()
        elif choice == "2":
            decrypt_qr()
        elif choice == "3":
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    # Install check
    try:
        from pyzbar.pyzbar import decode

        main()
    except ImportError:
        print("Missing requirements. Please install:")
        print("pip install qrcode pillow cryptography pyzbar")
        print("Windows users may need: pip install pyzbar[pyzbar]")