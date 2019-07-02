## Program generuje dowolną ilość kluczy prywatnych oraz przekształca je w opcjonalnie w adresy Legacy bądź SegWit.
## Następnie odpytuje blockstream.info i oblicza saldo danego konta.
## To tylko zabawa szansa na to że trafi się na tzw kolizję jest więcej niż mała.
##
## Kod jest zlepkiem kilku rozwiązań. Mój wkład jest niewielki. Jest sporo do optymalizacji.
## 
## Generowanie Bech32 zostało zajebane z tutoriala umieszczonego na YouTube przez Shlomi Zeltsinger.
## Który wykorzysuje kod napisany przez Pietera Wuille. Jednego z głównych devów Bitcoin core/ Blockstream.
## Kod generujący adress legacy został zajebany z Reddit od usera nykee-J.
##
## (https://github.com/sipa/bech32/tree/master/ref/python)
## (https://github.com/zeltsi/segwit_tutorial/tree/master/addresses)
## (https://www.youtube.com/channel/UCi9Mf3veSDDIMdGGtPmPu1g)
## (https://www.reddit.com/r/Bitcoin/comments/7tzq3w/generate_your_own_private_key_5_lines_of_python/)
## (https://github.com/blockstream/esplora/blob/master/API.md)
## 
## tested in python 3.6.8
## potrzebne dodatkowe moduły ecdsa, base58, requests
## Done by Atari_XE ( wypok AD 2019)


import random, ecdsa, hashlib, base58, binascii, requests

## BECH32 (https://github.com/sipa/bech32/tree/master/ref/python)
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_create_checksum(hrp, data):
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def bech32_decode(bech):
    """Validate a Bech32 string, and determine HRP and data."""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None)
    if not all(x in CHARSET for x in bech[pos+1:]):
        return (None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]
    if not bech32_verify_checksum(hrp, data):
        return (None, None)
    return (hrp, data[:-6])

def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def decode(hrp, addr):
    """Decode a segwit address."""
    hrpgot, data = bech32_decode(addr)
    if hrpgot != hrp:
        return (None, None)
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)
    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return (None, None)
    return (data[0], decoded)

def encode(hrp, witver, witprog):
    """Encode a segwit address."""
    ret = bech32_encode(hrp, [witver] + convertbits(witprog, 8, 5))
    if decode(hrp, ret) == (None, None):
        return None
    return ret

def privkey_generator():
    
    d ={}
    private_key = (random.getrandbits(256)).to_bytes(32, byteorder="little", signed=False)
    fullkey = '80' + binascii.hexlify(private_key).decode()
    sha256a = hashlib.sha256(binascii.unhexlify(fullkey)).hexdigest()
    sha256b = hashlib.sha256(binascii.unhexlify(sha256a)).hexdigest()
    WIF = base58.b58encode(binascii.unhexlify(fullkey+sha256b[:8]))
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    
    d["pkey"] = private_key
    d["Wk"] = WIF
    d["sk"] = signing_key
    d["vk"] = verifying_key
    return d

def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

def generator_segwit(a):
    
    number = a
    for n in range(number):

        d = privkey_generator()
        private_key = d["pkey"]
        WIF = d["Wk"]
        signing_key = d["sk"]
        verifying_key = d["vk"]
        
##        SegWit tutorial (https://github.com/zeltsi/segwit_tutorial/tree/master/addresses)
##        Shlomi Zeltsinger (https://www.youtube.com/channel/UCi9Mf3veSDDIMdGGtPmPu1g)
        x_cor = bytes.fromhex(verifying_key.to_string().hex())[:32]
        y_cor = bytes.fromhex(verifying_key.to_string().hex())[32:]

        if int.from_bytes(y_cor, byteorder="big", signed=True) % 2 == 0:
            public_key = bytes.fromhex(f'02{x_cor.hex()}')
        else:
             public_key = bytes.fromhex(f'03{x_cor.hex()}')

        sha256_key = hashlib.sha256(public_key)
        ripemd160_key = hashlib.new("ripemd160")
        ripemd160_key.update(sha256_key.digest())

        keyhash = ripemd160_key.digest()
        P2WPKH_V0 = bytes.fromhex(f'0014{keyhash.hex()}')

        sha256_P2WPKH_V0 = hashlib.sha256(P2WPKH_V0)
        ripemd160_P2WPKH_V0 = hashlib.new("ripemd160")
        ripemd160_P2WPKH_V0.update(sha256_P2WPKH_V0.digest())

        scripthash = ripemd160_P2WPKH_V0.digest()
        P2SH_P2WPKH_V0 = bytes.fromhex(f'a9{scripthash.hex()}87')

        flagged_scripthash = bytes.fromhex(f'05{scripthash.hex()}')
        checksum = hashlib.sha256(hashlib.sha256(flagged_scripthash).digest()).digest()[:4]

        bin_addr = flagged_scripthash + checksum
        nested_address = base58.b58encode(bin_addr)
        bech32 = encode('bc', 0, keyhash)

        i = n + 1

        stradress = str(nested_address.decode())
        balance = sprawdz_balance_blockstream(stradress)
            
        if balance == 0:
            print("{:25} | {:35} | {:46} | {:20}".format("Bitcoin Address " + str(i), str(nested_address.decode()), str(bech32), str(balance) + " BTC"))
        else:
            print("{:25} | {:35} | {:46} | {:20}".format("Bitcoin Address " + str(i), str(nested_address.decode()), str(bech32), str(balance) + " BTC"))
            print("Private Key", str(i) + ": " + private_key.hex())
            print("Private Key  WIF", str(i) + ": " + WIF.decode())
            break
        
def generator_legacy(a):
    
    number = a
    for n in range(number):
        d = privkey_generator()
        private_key = d["pkey"]
        WIF = d["Wk"]
        signing_key = d["sk"]
        verifying_key = d["vk"]
##        Zajebane z Reddita (https://www.reddit.com/r/Bitcoin/comments/7tzq3w/generate_your_own_private_key_5_lines_of_python/)

        publ_key = '04' + binascii.hexlify(verifying_key.to_string()).decode()
        hash160 = ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest()
        publ_addr_a = b"\x00" + hash160
        checksum = hashlib.sha256(hashlib.sha256(publ_addr_a).digest()).digest()[:4]
        publ_addr_b = base58.b58encode(publ_addr_a + checksum)
        i = n + 1

        stradress = str(publ_addr_b.decode())
        balance = sprawdz_balance_blockstream(stradress)
               
        if balance == 0:
            print("{:25} | {:35} | {:20}".format("Bitcoin Address " + str(i), publ_addr_b.decode(), str(balance) + " BTC"))
        else:
            print("{:25} | {:35} | {:20}".format("Bitcoin Address " + str(i), publ_addr_b.decode(), str(balance) + " BTC"))
            print('Private Key    ', str(i) + ": " + WIF.decode())
            break
        
    
def sprawdz_balance_blockstream(a):
    
    addr = a    
    response = requests.get('https://blockstream.info/api/address/' + addr)

    if response.status_code == 200:
        content = response.json()
        b = (int(content['chain_stats']['funded_txo_sum']) - int(content['chain_stats']['spent_txo_sum'])) / 10**8
    else:
        print("Err: ", response.status_code)
        
    return b
    
wybor = int(input("Jeżeli chcesz generować adresy Legacy wciśnij 1, jeżeli SegWit wciśnij 2 :"))

if wybor == 1:
    ilosc = int(input("Podaj ilość kluczy:"))
    generator_legacy(ilosc)
elif wybor == 2:
    ilosc = int(input("Podaj ilość kluczy:"))
    generator_segwit(ilosc)
else:
    print("Nie ma takiej opcji")
    
print("koniec")
