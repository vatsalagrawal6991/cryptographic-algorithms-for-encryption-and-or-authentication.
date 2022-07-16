# Write your script here

class ExecuteCrypto(object): # Do not change this
    def generate_keys(self):
        """Generate keys"""

        # Write your script here
        from Crypto.Random import get_random_bytes as grb
        from Crypto.PublicKey import RSA, ECC
        from base64 import b64encode
        symmetric_key = grb(16)
        symmetric_key = b64encode(symmetric_key).decode('utf-8')
        # 16*8 = 128 bits
        key1 = RSA.generate(2048)
        key2 = RSA.generate(2048)
        public_key_sender_rsa = key1.public_key().export_key()
        private_key_sender_rsa = key1.export_key()
        public_key_receiver_rsa = key2.public_key().export_key()
        private_key_receiver_rsa = key2.export_key()
        key3 = ECC.generate(curve='P-256')
        public_key_sender_ecc = key3.public_key().export_key(format='PEM')
        private_key_sender_ecc = key3.export_key(format='PEM')
        print("Symmetric Key") # Do not change this
        print(symmetric_key) # Do not change this
        print("Sender's RSA Public Key") # Do not change this
        print(public_key_sender_rsa) # Do not change this
        print("Sender's RSA Private Key") # Do not change this
        print(private_key_sender_rsa) # Do not change this
        print("Receiver's RSA Public Key") # Do not change this
        print(public_key_receiver_rsa) # Do not change this
        print("Receiver's RSA Private Key") # Do not change this
        print(private_key_receiver_rsa) # Do not change this
        print("Sender's ECC Public Key") # Do not change this
        print(public_key_sender_ecc) # Do not change this
        print("Sender's ECC Private Key") # Do not change this
        print(private_key_sender_ecc) # Do not change this

        return symmetric_key, \
                public_key_sender_rsa, private_key_sender_rsa, \
                public_key_receiver_rsa, private_key_receiver_rsa, \
                public_key_sender_ecc, private_key_sender_ecc # Do not change this

    def generate_nonces(self):
        """Generate nonces"""

        # Write your script here
        from Crypto.Random import get_random_bytes as grb
        from base64 import b64encode
        nonce_aes_cbc = grb(16)
        nonce_aes_cbc = b64encode(nonce_aes_cbc).decode('utf-8')
        nonce_aes_ctr = grb(8)
        nonce_aes_ctr = b64encode(nonce_aes_ctr).decode('utf-8')
        nonce_encrypt_rsa = grb(16)
        nonce_encrypt_rsa = b64encode(nonce_encrypt_rsa).decode('utf-8')
        nonce_aes_cmac = grb(16)
        nonce_aes_cmac = b64encode(nonce_aes_cmac).decode('utf-8')
        nonce_hmac = grb(16)
        nonce_hmac = b64encode(nonce_hmac).decode('utf-8')
        nonce_tag_rsa = grb(16)
        nonce_tag_rsa = b64encode(nonce_tag_rsa).decode('utf-8')
        nonce_aes_gcm = grb(12)
        nonce_aes_gcm = b64encode(nonce_aes_gcm).decode('utf-8')
        nonce_ecdsa = grb(16)
        nonce_ecdsa = b64encode(nonce_ecdsa).decode('utf-8')
        print("Nonce for AES-128-CBC") # Do not change this
        print(nonce_aes_cbc) # Do not change this
        print("Nonce for AES-128-CTR") # Do not change this
        print(nonce_aes_ctr) # Do not change this
        print("NOnce for RSA-2048") # Do not change this
        print(nonce_encrypt_rsa) # Do not change this
        print("Nonce for AES-128-CMAC") # Do not change this
        print(nonce_aes_cmac) # Do not change this
        print("Nonce for SHA3-256-HMAC") # Do not change this
        print(nonce_hmac) # Do not change this
        print("Nonce for RSA-2048-SHA3-256") # Do not change this
        print(nonce_tag_rsa) # Do not change this
        print("Nonce for ECDSA") # Do not change this
        print(nonce_ecdsa) # Do not change this
        print("Nonce for AES-128-GCM") # Do not change this
        print(nonce_aes_gcm) # Do not change this

        return nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
                nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm # Do not change this

    def encrypt(self, algo, key, plaintext, nonce): # Do not change this
        """Encrypt the given plaintext"""

        # Write your script here
        if algo == 'AES-128-CBC-ENC': # Do not change this
            # Write your script here
            from Crypto.Util.Padding import pad
            from Crypto.Cipher import AES
            from base64 import b64decode, b64encode
            keyn = key
            key = b64decode(key)
            noncen = nonce
            nonce = b64decode(nonce)
            plaintext = bytes(plaintext, "utf-8")
            cp = AES.new(key, AES.MODE_CBC,iv=nonce)
            ciphertext = cp.encrypt(pad(plaintext,AES.block_size))
            key = keyn
            nonce = noncen
            plaintext = plaintext.decode()
            ciphertext = b64encode(ciphertext ).decode('utf-8')
        elif algo == 'AES-128-CTR-ENC': # Do not change this
            # Write your script here
            from Crypto.Cipher import AES
            from base64 import b64decode, b64encode
            keyn = key
            key = b64decode(key)
            noncen = nonce
            nonce = b64decode(nonce)
            plaintext = bytes(plaintext, "utf-8")
            cp = AES.new(key,AES.MODE_CTR, nonce=nonce)
            ciphertext = cp.encrypt(plaintext)
            key = keyn
            nonce = noncen
            plaintext = plaintext.decode()
            ciphertext = b64encode(ciphertext).decode('utf-8')
        elif algo == 'RSA-2048-ENC': # Do not change this
            # Write your script here
            from Crypto.PublicKey import RSA
            from Crypto.Cipher import PKCS1_OAEP as pk
            from base64 import b64encode
            from base64 import b64decode, b64encode
            keyn = plaintext
            plaintext = b64decode(plaintext)
            key1 = RSA.import_key(key)
            rs = pk.new(key1)
            ciphertext = rs.encrypt(plaintext)
            plaintext = keyn
            ciphertext = b64encode(ciphertext).decode('utf-8')
        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here


        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this

        return ciphertext # Do not change this

    def decrypt(self, algo, key, ciphertext, nonce): # Do not change this
        """Decrypt the given ciphertext"""
        # Write your script here

        if algo=='AES-128-CBC-DEC': # Do not change this
            # Write your script here
            from Crypto.Util.Padding import unpad
            from Crypto.Cipher import AES
            from base64 import b64decode
            keyn = key
            key = b64decode(key)
            noncen = nonce
            nonce = b64decode(nonce)
            ciphertextn = ciphertext
            ciphertext = b64decode(ciphertext)
            cp = AES.new(key, AES.MODE_CBC, iv=nonce)
            plaintext0 = cp.decrypt(ciphertext)
            plaintext = unpad(plaintext0, AES.block_size).decode()
            key = keyn
            nonce = noncen
            ciphertext = ciphertextn
        elif algo == 'AES-128-CTR-DEC': # Do not change this
            # Write your script here
            from Crypto.Cipher import AES
            from base64 import b64decode
            keyn = key
            key = b64decode(key)
            noncen = nonce
            nonce = b64decode(nonce)
            ciphertextn = ciphertext
            ciphertext = b64decode(ciphertext)
            cp = AES.new(key, AES.MODE_CTR, nonce=nonce)
            plaintext = cp.decrypt(ciphertext).decode()
            key = keyn
            nonce = noncen
            ciphertext = ciphertextn
        elif algo == 'RSA-2048-DEC': # Do not change this
            # Write your script here
            from Crypto.PublicKey import RSA
            from Crypto.Cipher import PKCS1_OAEP as pk
            from base64 import b64decode, b64encode
            ciphertextn = ciphertext
            ciphertext = b64decode(ciphertext)
            key1 = RSA.import_key(key)
            rs = pk.new(key1)
            plaintext = rs.decrypt(ciphertext)
            ciphertext = ciphertextn
            plaintext = b64encode(plaintext).decode('utf-8')
        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        return plaintext # Do not change this

    def generate_auth_tag(self, algo, key, plaintext, nonce): # Do not change this
        """Generate the authenticate tag for the given plaintext"""

        # Write your script here

        if algo =='AES-128-CMAC-GEN': # Do not change this
            # Write your script here
            from Crypto.Hash import CMAC
            from Crypto.Cipher import AES
            from base64 import b64decode, b64encode
            keyn = key
            key = b64decode(key)
            plaintext = bytes(plaintext, "utf-8")
            cp = CMAC.new(key, ciphermod=AES)
            cp.update(plaintext)
            auth_tag = cp.digest()
            key = keyn
            plaintext = plaintext.decode()
            auth_tag = b64encode(auth_tag).decode('utf-8')
        elif algo =='SHA3-256-HMAC-GEN': # Do not change this
            # Write your script here
            from Crypto.Hash import HMAC,SHA3_256
            from base64 import b64decode, b64encode
            keyn = key
            key = b64decode(key)
            plaintext = bytes(plaintext, "utf-8")
            cp = HMAC.new(key, digestmod=SHA3_256)
            cp.update(plaintext)
            auth_tag = cp.digest()
            key = keyn
            plaintext = plaintext.decode()
            auth_tag = b64encode(auth_tag).decode('utf-8')
        elif algo =='RSA-2048-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here
            from Crypto.Signature import pkcs1_15 as pk
            from Crypto.Hash import SHA3_256 as sh
            from Crypto.PublicKey import RSA
            from base64 import b64encode
            plaintext = bytes(plaintext, "utf-8")
            key1 = RSA.import_key(key)
            cp = sh.new(plaintext)
            auth_tag = pk.new(key1).sign(cp)
            plaintext = plaintext.decode()
            auth_tag = b64encode(auth_tag).decode('utf-8')
        elif algo =='ECDSA-256-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here
            from Crypto.Signature import DSS
            from Crypto.Hash import SHA3_256 as sh
            from Crypto.PublicKey import ECC
            from base64 import b64encode
            plaintext = bytes(plaintext, 'utf-8')
            key1 = ECC.import_key(key)
            cp = sh.new(plaintext)
            cp1 = DSS.new(key1, 'fips-186-3')
            auth_tag = cp1.sign(cp)
            plaintext = plaintext.decode()
            auth_tag = b64encode(auth_tag).decode('utf-8')
        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here


        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return auth_tag # Do not change this

    def verify_auth_tag(self, algo, key, plaintext, nonce, auth_tag): # Do not change this
        """Verify the authenticate tag for the given plaintext"""

        # Write your script here

        if algo =='AES-128-CMAC-VRF': # Do not change this
            # Write your script here
            from Crypto.Hash import CMAC
            from Crypto.Cipher import AES
            from base64 import b64decode
            keyn = key
            key = b64decode(key)
            auth_tagn = auth_tag
            auth_tag = b64decode(auth_tag)
            plaintext = bytes(plaintext, "utf-8")
            cp = CMAC.new(key, ciphermod=AES)
            cp.update(plaintext)
            auth_tag_valid = "True"
            try:
                cp.verify(auth_tag)
            except ValueError:
                auth_tag_valid = "False"
            key=keyn
            plaintext = plaintext.decode()
            auth_tag = auth_tagn
        elif algo =='SHA3-256-HMAC-VRF': # Do not change this
            # Write your script here
            from Crypto.Hash import HMAC, SHA3_256
            from base64 import b64decode
            keyn = key
            key = b64decode(key)
            auth_tagn = auth_tag
            auth_tag = b64decode(auth_tag)
            plaintext = bytes(plaintext, "utf-8")
            cp = HMAC.new(key, digestmod=SHA3_256)
            cp.update(plaintext)
            auth_tag_valid = "True"
            try:
                cp.verify(auth_tag)
            except ValueError:
                auth_tag_valid = "False"
            key =keyn
            plaintext = plaintext.decode()
            auth_tag = auth_tagn
        elif algo =='RSA-2048-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            from Crypto.Signature import pkcs1_15 as pk
            from Crypto.Hash import SHA3_256 as sh
            from Crypto.PublicKey import RSA
            from base64 import b64decode
            plaintext = bytes(plaintext, "utf-8")
            key1 = RSA.import_key(key)
            cp = sh.new(plaintext)
            auth_tagn = auth_tag
            auth_tag = b64decode(auth_tag)
            auth_tag_valid = "True"
            try:
                pk.new(key1).verify(cp, auth_tag)
            except (ValueError, TypeError):
                auth_tag_valid = "False"
            plaintext = plaintext.decode()
            auth_tag = auth_tagn

        elif algo =='ECDSA-256-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            from Crypto.Signature import DSS
            from Crypto.Hash import SHA3_256 as sh
            from Crypto.PublicKey import ECC
            from base64 import b64decode
            auth_tagn = auth_tag
            auth_tag = b64decode(auth_tag)
            plaintext = bytes(plaintext, "utf-8")
            key1 = ECC.import_key(key)
            cp = sh.new(plaintext)
            cp1 = DSS.new(key1, 'fips-186-3')
            auth_tag_valid = "True"
            try:
                cp1.verify(cp, auth_tag)
            except:
                auth_tag_valid = "False"
            plaintext = plaintext.decode()
            auth_tag = auth_tagn

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return auth_tag_valid # Do not change this

    def encrypt_generate_auth(self, algo, key_encrypt, key_generate_auth, plaintext, nonce): # Do not change this
        """Encrypt and generate the authentication tag for the given plaintext"""

        # Write your script here
        if algo == 'AES-128-GCM-GEN': # Do not change this
            # Write your script here
            from Crypto.Cipher import AES
            from base64 import b64decode, b64encode
            keyn = key_encrypt
            key_encrypt = b64decode(key_encrypt)
            noncen = nonce
            nonce = b64decode(nonce)
            plaintext = bytes(plaintext, "utf-8")
            cp = AES.new(key_encrypt, AES.MODE_GCM, nonce=nonce)
            ciphertext, auth_tag = cp.encrypt_and_digest(plaintext)
            key_encrypt = keyn
            nonce = noncen
            plaintext = plaintext.decode()
            ciphertext = b64encode(ciphertext).decode('utf-8')
            auth_tag = b64encode(auth_tag).decode('utf-8')

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key_encrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_generate_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return ciphertext, auth_tag # Do not change this

    def decrypt_verify_auth(self, algo, key_decrypt, key_verify_auth, ciphertext, nonce, auth_tag): # Do not change this
        """Decrypt and verify the authentication tag for the given plaintext"""

        # Write your script here

        if algo == 'AES-128-GCM-VRF': # Do not change this
            # Write your script here
            from Crypto.Cipher import AES
            from base64 import b64decode
            keyn = key_decrypt
            key_decrypt = b64decode(key_decrypt)
            noncen = nonce
            nonce = b64decode(nonce)
            ciphertextn = ciphertext
            ciphertext = b64decode(ciphertext)
            auth_tagn = auth_tag
            auth_tag = b64decode(auth_tag)
            cp = AES.new(key_decrypt, AES.MODE_GCM, nonce=nonce)
            auth_tag_valid = "True"
            try :
                plaintext = cp.decrypt_and_verify(ciphertext, auth_tag).decode()
            except (ValueError, KeyError):
                auth_tag_valid = "False"
                cpa = AES.new(key_decrypt, AES.MODE_GCM, nonce=nonce)
                plaintext = cpa.decrypt(ciphertext).decode()
            nonce = noncen
            key_decrypt = keyn
            ciphertext = ciphertextn
            auth_tag = auth_tagn
        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key_decrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_verify_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return plaintext, auth_tag_valid # Do not change this

if __name__ == '__main__': # Do not change this
    ExecuteCrypto() # Do not change this
