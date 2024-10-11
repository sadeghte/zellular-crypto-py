import cuda_crypt as cc
from cuda_crypt.wrapper import ed25519_set_verbose
import sys, os, time, random

def is_prime(n):
    # Handle special cases
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    
    # Check from 5 to sqrt(n) using 6k ± 1 rule
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    
    return True

def main(argv):

	os.environ["VERBOSE"] = "1"

	# Check if the required number of arguments is provided
	if (len(argv) - 1) != 1:
		raise ValueError(f"usage: {argv[0]} <num_signatures>")
	
	num_signatures = int(argv[1])
	if num_signatures <= 0:
		raise ValueError("num_signatures should be > 0")

	messages = []
	signatures = []
	pubs = []
	privs = []

	print(f"preparing data...")
	for i in range(num_signatures):
		msg = b'12345678'
		pub_key, priv_key = cc.create_keypair()

		messages.append(msg)
		pubs.append(pub_key)
		privs.append(priv_key)

	print(f"signing {num_signatures} messages...")
	signatures = cc.sign_many(messages, pubs, privs);

	for i in range(min(100, num_signatures)):
		# Call ed25519_sign to generate the signature
		ret_sign = cc.sign(
			messages[i],  # Message to sign
			pubs[i],  # Public key
			privs[i],  # Private key
		)

		# Check if the computed signature matches the one in the packet
		# if ctypes.memcmp(packet.signature, signature, cc.SIG_SIZE) != 0:
		# 	raise ValueError("Invalid signature!")
		if ret_sign != signatures[i]:
			raise ValueError("Invalid signature!")

		# Verify the signature
		ret_verify = cc.verify(
			messages[i],
			signatures[i],  # Signature to verify
			pubs[i]  # Public key for verification
		)

		if ret_verify != 1:
			raise ValueError("Invalid signature!")

	# corrupt signatures in the prime indexes
	for i in range(num_signatures):
		if is_prime(i):
			sign = bytearray(signatures[i])
			sign[0] = 0 if sign[0] != 0 else 1 
			signatures[i] = bytes(sign)
	
	print(f"verifing {num_signatures} messages...")
	start = time.time()
	verified = cc.verify_many(signatures, messages, pubs)
	end = time.time()

	# check correct and corrupted signatures
	for i in range(num_signatures):
		if is_prime(i) == verified[i] == 1:
			raise ValueError("Invalid signature!");

	print(f"count: {num_signatures}, time: {end-start:.2f} sec, verifies/sec: {num_signatures/(end-start):.2f}");

	return 0;

if __name__ == "__main__":
	sys.exit(main(sys.argv));