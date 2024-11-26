from cryptography.fernet import Fernet

key=Fernet.generate_key()

with open ('kuchbhi.key', 'wb') as kuchbhi:
    kuchbhi.write(key)