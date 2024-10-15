import cuda_crypt as cc
import sys, os, time, math
from concurrent.futures import ProcessPoolExecutor
import itertools


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

def create_data(chunk_size):
	msgs = []
	pubs = []
	privs = []
	for i in range(chunk_size):
		msg = b'12345678'
		pub_key, priv_key = cc.create_keypair()

		msgs.append(msg)
		pubs.append(pub_key)
		privs.append(priv_key)
	return msgs, pubs, privs

def generate_large_data_parallel(total_size, num_chunks):
    chunk_size = math.ceil(total_size / num_chunks)  # Split the data into equal chunks
    with ProcessPoolExecutor() as executor:
        # Distribute the work across CPU cores
        result = list(executor.map(create_data, [chunk_size] * num_chunks))
    return result

def main(argv):

	os.environ["VERBOSE"] = "1"

	# Check if the required number of arguments is provided
	if (len(argv) - 1) != 1:
		raise ValueError(f"usage: {argv[0]} <num_signatures>")
	
	num_signatures = int(argv[1])
	if num_signatures <= 0:
		raise ValueError("num_signatures should be > 0")

	print(f"preparing data...")
	start = time.time()
	all_data = generate_large_data_parallel(num_signatures, os.cpu_count())
	msgs, pubs, privs = zip(*all_data)

	msgs = list(itertools.chain.from_iterable(msgs))
	pubs = list(itertools.chain.from_iterable(pubs))
	privs = list(itertools.chain.from_iterable(privs))

	print(f"time: {time.time() - start:.2f}, len: {len(msgs)}\n")

	print(f"signing {num_signatures} messages...")
	signatures = cc.sign_many(msgs, pubs, privs);

	for i in range(min(100, num_signatures)):
		# Call ed25519_sign to generate the signature
		ret_sign = cc.sign(
			msgs[i],  # Message to sign
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
			msgs[i],
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
	joined_data = [signatures[i]+pubs[i]+msgs[i] for i in range(len(signatures))]

	padding_size = cc.padding_size()
	data = bytearray(num_signatures * padding_size)
	for i, item in enumerate(joined_data):
		data[i * padding_size:(i + 1) * padding_size] = item.ljust(padding_size, b'\0')

	message_lens = [len(m) for m in msgs]
	start = time.time()
	verified = cc.verify_many(data, message_lens)
	end = time.time()

	# check correct and corrupted signatures
	for i in range(num_signatures):
		if is_prime(i) == (verified[i] == 1):
			raise ValueError("Invalid signature!");

	print(f"count: {num_signatures}, time: {end-start:.2f} sec, verifies/sec: {num_signatures/(end-start):.2f}");

	return 0;

if __name__ == "__main__":
	sys.exit(main(sys.argv));