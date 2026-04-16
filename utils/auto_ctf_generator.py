import os
import random
import base64

def detect_input_type(text, file=None):
    if file:
        return 'image'
    if text:
        suspicious_keywords = ['base64', 'encrypt', 'eval', 'script']
        if any(kw in text.lower() for kw in suspicious_keywords):
            return 'crypto'
        return 'puzzle'
    return 'unknown'

def generate_flag():
    random_num = random.randint(1000, 9999)
    return f"FLAG{{auto_{random_num}}}"

def generate_crypto_ctf(text):
    flag = generate_flag()
    encoded_flag = base64.b64encode(flag.encode()).decode()
    return {
        "challenge_type": "crypto",
        "challenge": encoded_flag,
        "hint": "Decode using Base64",
        "flag": flag
    }

def generate_puzzle_ctf(text):
    flag = generate_flag()
    # Reversed string
    reversed_flag = flag[::-1]
    return {
        "challenge_type": "puzzle",
        "challenge": reversed_flag,
        "hint": "Reversed string",
        "flag": flag
    }

def generate_stego_ctf(image_path):
    from stegano import lsb
    flag = generate_flag()
    
    upload_dir = os.path.dirname(image_path)
    filename = os.path.basename(image_path)
    output_filename = f"ctf_{filename}"
    output_path = os.path.join(upload_dir, output_filename)
    
    try:
        secret_image = lsb.hide(image_path, flag)
        secret_image.save(output_path)
        return {
            "challenge_type": "stego",
            "challenge": output_filename,
            "hint": "Hidden data inside image",
            "flag": flag
        }
    except Exception as e:
        return {
            "challenge_type": "stego",
            "challenge": "Failed to generate stego challenge",
            "hint": str(e),
            "flag": flag
        }
