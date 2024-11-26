from cryptography.fernet import Fernet

# key=Fernet.generate_key()

# with open ('kuchbhi.key', 'wb') as kuchbhi:
#     kuchbhi.write(key)


    # kuchbhi keyfile this file is contaning actual encryption key encrypt& decrypt csv file

with open('kuchbhi.key','rb') as kuchbhi:
    key= kuchbhi.read()
print(key)