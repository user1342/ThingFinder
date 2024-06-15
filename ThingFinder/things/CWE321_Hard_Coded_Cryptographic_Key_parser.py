import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE321_Hard_Coded_Cryptographic_KeyParser(IngestClass):

    def parser(self, code):
        # Regular expressions to match relevant patterns in the C code
        crypto_key_pattern = r'(\w+)\s*=\s*(\'[^\']*\')'
        crypto_key_hash_pattern = r'CryptHashData\((BYTE\s+cryptoKey,.*\)'
        crypto_key_encrypt_pattern = r'CryptEncrypt\((HCRYPTHASH\s+NULL,.*\)'

        # Find all occurrences of the crypto key assignment pattern
        matches = re.findall(crypto_key_pattern, code)

        # If a match is found, check if the crypto key is hard-coded or read from the console
        if matches:
            for match in matches:
                crypto_key, crypto_key_value = match
                # Check if the crypto key value is a hard-coded string
                if crypto_key_value.strip('\'') != '':
                    # Check if the crypto key is used in a hash or encryption operation
                    if re.search(crypto_key_hash_pattern, code) or re.search(crypto_key_encrypt_pattern, code):
                        return True

        return False
