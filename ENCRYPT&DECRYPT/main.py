from cryptography.fernet import Fernet

# key=Fernet.generate_key()

# with open ('kuchbhi.key', 'wb') as kuchbhi:
#     kuchbhi.write(key)


    # kuchbhi keyfile this file is contaning actual encryption key encrypt& decrypt csv file

with open('kuchbhi.key','rb') as kuchbhi:
    key= kuchbhi.read()

print(key)

# f=Fernet(key)

# with open('student.csv','rb') as original_file:
#     original = original_file.read ()

# encrypted=f.encrypt(original)

# with open('enc_student.csv', 'wb') as encrypted_file:
#     encrypted_file.write(encrypted)

f=Fernet(key)

with open('enc_student.csv','rb') as encrypted_file:
    encrypted=encrypted_file.read()

    decrypted = f.decrypt(encrypted)


with open('dec_student.csv','wb') as decryptd_file:

    decryptd_file.write(decrypted)