import cuda_crypt as cc
import ctypes

# create seed:
seed_h = (ctypes.c_ubyte * cc.SEED_SIZE)()
check = cc.ed25519_create_seed(seed_h)
if check != 0:
	raise ValueError("Failed to create seed")

# create key
public_key = (ctypes.c_ubyte * cc.PUB_KEY_SIZE)()
private_key = (ctypes.c_ubyte * cc.PRIV_KEY_SIZE)()
cc.ed25519_create_keypair(public_key, private_key, seed_h)

# sign
message = b"message"
msg_array = (ctypes.c_ubyte * len(message))(*message)
signature = (ctypes.c_ubyte * cc.SIG_SIZE)()
cc.ed25519_sign(msg_array, public_key, private_key, signature)

# verify
is_valid = cc.ed25519_verify(signature, msg_array, public_key)
print(f"Signature valid: {is_valid}")