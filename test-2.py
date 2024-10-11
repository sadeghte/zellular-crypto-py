import cuda_crypt.wrapper as cc
import ctypes, sys, os, random, time, threading

PACKET_SIZE = 512

class StreamerMeta(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_size_t),
        ("num_retransmits", ctypes.c_uint64),
        ("addr", ctypes.c_uint16 * 8),
        ("port", ctypes.c_uint16),
        ("v6", ctypes.c_bool)
    ]

class StreamerPacket(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.c_uint8 * PACKET_SIZE),
        ("meta", StreamerMeta)
    ]

class Packet(ctypes.Structure):
    _fields_ = [
        ("signature", ctypes.c_uint8 * cc.SIG_SIZE),
        ("public_key", ctypes.c_uint8 * cc.PUB_KEY_SIZE),
        ("private_key", ctypes.c_uint8 * cc.PRIV_KEY_SIZE),
        ("message_len", ctypes.c_uint32),
        ("message", ctypes.c_uint8 * 8)
    ]

    # Custom accessor method
    def __getitem__(self, key):
        if key in dict(self._fields_):
            return getattr(self, key)
        else:
            raise KeyError(f"Field '{key}' not found in structure.")
    
class VerifyCpuCtx(ctypes.Structure):
    _fields_ = [
        ("elems_h", ctypes.POINTER(cc.gpu_Elems)),  # Assuming this is a pointer to another structure
        ("num_elems", ctypes.c_uint32),
        ("total_packets", ctypes.c_uint32),
        ("total_signatures", ctypes.c_uint32),
        ("message_lens", ctypes.POINTER(ctypes.c_uint32)),
        ("public_key_offsets", ctypes.POINTER(ctypes.c_uint32)),
        ("private_key_offsets", ctypes.POINTER(ctypes.c_uint32)),
        ("signature_offsets", ctypes.POINTER(ctypes.c_uint32)),
        ("message_start_offsets", ctypes.POINTER(ctypes.c_uint32)),
        ("out_h", ctypes.POINTER(ctypes.c_uint8)),
        ("use_non_default_stream", ctypes.c_uint8)
    ]

def LOG(message, *args):
    # Check if verbosity is enabled from the environment variable
    if os.getenv("VERBOSE") == "1":
        # Use string formatting for the message and arguments
        print(message % args);

def verify_proc(vctx):
	LOG("Start verify_proc");
	cc.ed25519_verify_many(
		vctx.elems_h,
		vctx.num_elems,
		ctypes.sizeof(StreamerPacket),  # Replace with appropriate packet size
		vctx.total_packets,
		vctx.total_signatures,
		vctx.message_lens,
		vctx.public_key_offsets,
		vctx.signature_offsets,
		vctx.message_start_offsets,
		vctx.out_h,
		vctx.use_non_default_stream,
		);
	LOG("Done verify_proc");

def get_diff(start, end):
	return end - start  # Convert seconds to microseconds
	
def get_time():
    return time.time()

def main(argv):
	arg = 0
	verbose = False

	# Check for the "-v" verbose flag
	while arg < len(argv):
		if argv[arg] == "-v":
			verbose = True
			arg += 1
		else:
			break

	# Check if the required number of arguments is provided
	if (len(argv) - arg) != 4:
		print(f"usage: {argv[0]} [-v] <num_signatures> <num_elems> <num_threads> <use_non_default_stream>")
		return 1

	cc.ed25519_set_verbose(verbose)
	os.environ["VERBOSE"] = "1" if verbose else "0"

	# Parse arguments and validate them
	try :
		num_signatures_per_elem = int(argv[arg])
		arg += 1
		if num_signatures_per_elem <= 0:
			raise ValueError("num_signatures_per_elem should be > 0")

		num_elems = int(argv[arg])
		arg += 1
		if num_elems <= 0:
			raise ValueError("num_elems should be > 0")

		num_threads = int(argv[arg])
		arg += 1
		if num_threads <= 0:
			raise ValueError("num_threads should be > 0")

		use_non_default_stream = int(argv[arg])
		arg += 1
		if use_non_default_stream not in (0, 1):
			raise ValueError("non_default_stream should be 0 or 1")
		
		LOG(F"streamer size: {ctypes.sizeof(StreamerPacket)} elems size: {ctypes.sizeof(cc.gpu_Elems)}\n");
	
		# Host allocate
		seed_h = (ctypes.c_uint8 * (num_signatures_per_elem * cc.SEED_SIZE))()
		message_h = b"abcd1234"
		msg_array = (ctypes.c_ubyte * len(message_h))(*message_h)
		message_h_len = len(message_h)

		total_signatures = num_elems * num_signatures_per_elem

		# Allocate arrays (equivalent to ed25519_alloc)
		message_lens = (ctypes.c_uint32 * total_signatures)()
		signature_offsets = (ctypes.c_uint32 * total_signatures)()
		public_key_offsets = (ctypes.c_uint32 * total_signatures)()
		private_key_offsets = (ctypes.c_uint32 * total_signatures)()
		message_start_offsets = (ctypes.c_uint32 * total_signatures)()

		# Fill offsets and lengths
		for i in range(total_signatures):
			base_offset = i * ctypes.sizeof(StreamerPacket)
			signature_offsets[i] = base_offset + Packet.signature.offset
			public_key_offsets[i] = base_offset + Packet.public_key.offset
			private_key_offsets[i] = base_offset + Packet.private_key.offset
			message_start_offsets[i] = base_offset + Packet.message.offset
			message_lens[i] = message_h_len

		# Create a list of verify_cpu_ctx_t structures
		vctx = [VerifyCpuCtx() for _ in range(num_threads)]

		# Populate each context with the previously allocated arrays
		for i in range(num_threads):
			vctx[i].message_lens = message_lens
			vctx[i].signature_offsets = signature_offsets
			vctx[i].public_key_offsets = public_key_offsets
			vctx[i].private_key_offsets = private_key_offsets
			vctx[i].message_start_offsets = message_start_offsets
			vctx[i].use_non_default_stream = use_non_default_stream

		packets_h = (StreamerPacket * num_signatures_per_elem)()
		total_packets = 0

		elems_h = (cc.gpu_Elems * num_elems)()

		for i in range(num_elems):
			elems_h[i].num = num_signatures_per_elem
			elems_h[i].elems = ctypes.cast(ctypes.pointer(packets_h[0]), ctypes.POINTER(ctypes.c_uint8))

			total_packets += num_signatures_per_elem

		LOG("initing messages...\n");
		for i in range(num_signatures_per_elem):
			packet = ctypes.cast(ctypes.byref(packets_h[i]), ctypes.POINTER(Packet)).contents
			ctypes.memmove(packet.message, message_h, message_h_len)

		out_size = total_signatures * ctypes.sizeof(ctypes.c_uint8)
		for i in range(num_threads):
			vctx[i].num_elems = num_elems
			vctx[i].out_h = (ctypes.c_uint8 * out_size)()
			vctx[i].elems_h = elems_h
			vctx[i].total_signatures = total_signatures
			vctx[i].total_packets = total_packets

		LOG(F"creating {num_signatures_per_elem} keypairs...\n");
		num_keypairs_to_create = min(100, num_signatures_per_elem)
		public_keys = (ctypes.c_uint8 * (num_keypairs_to_create * cc.PUB_KEY_SIZE))()
		private_keys = (ctypes.c_uint8 * (num_keypairs_to_create * cc.PRIV_KEY_SIZE))()

		for i in range(num_keypairs_to_create):
			ret = cc.ed25519_create_seed(seed_h)  # Call your function to create a seed
			if ret != 0:
				raise ValueError("Invalid seed!")

			# Create key pair
			cc.ed25519_create_keypair(
				ctypes.cast(ctypes.byref(public_keys, cc.PUB_KEY_SIZE * i), ctypes.POINTER(ctypes.c_uint8)),
				ctypes.cast(ctypes.byref(private_keys, cc.PRIV_KEY_SIZE * i), ctypes.POINTER(ctypes.c_uint8)),
				seed_h
			)

		for i in range(num_signatures_per_elem):
			packet = ctypes.cast(ctypes.byref(packets_h[i]), ctypes.POINTER(Packet)).contents
			# Get a random index for the public and private keys
			j = random.randint(0, num_keypairs_to_create - 1)  # Random index

			# Copy the public key and private key to the packet
			ctypes.memmove(packet.public_key, ctypes.byref(public_keys, j * cc.PUB_KEY_SIZE), cc.PUB_KEY_SIZE)
			ctypes.memmove(packet.private_key, ctypes.byref(private_keys, j * cc.PRIV_KEY_SIZE), cc.PRIV_KEY_SIZE)

		signatures_h = (ctypes.c_uint8 * (cc.SIG_SIZE * total_signatures))()

		start = get_time()
		cc.ed25519_sign_many(
			vctx[0].elems_h,
			vctx[0].num_elems,
			ctypes.sizeof(StreamerPacket),  # Assuming StreamerPacket is defined
			vctx[0].total_packets,
			vctx[0].total_signatures,
			vctx[0].message_lens,
			vctx[0].public_key_offsets,
			vctx[0].private_key_offsets,
			vctx[0].message_start_offsets,
			signatures_h,
			1
		)
		end = get_time()
		diff = get_diff(start, end)
		print(f"time diff: {diff:.6f} total: {vctx[0].total_signatures} "
			f"signs/sec: {vctx[0].total_signatures / diff:.6f}")

		# Copy signatures into packets
		for i in range(num_signatures_per_elem):
			packet = ctypes.cast(ctypes.byref(packets_h[i]), ctypes.POINTER(Packet)).contents
			ctypes.memmove(packet.signature, ctypes.byref(signatures_h, i * cc.SIG_SIZE), cc.SIG_SIZE)

		num_sigs_to_check = min(100, num_signatures_per_elem)
		LOG(f"checking {num_sigs_to_check} signatures")

		for i in range(num_sigs_to_check):
			j = random.randint(0, num_signatures_per_elem - 1)  # Random index
			packet = ctypes.cast(ctypes.byref(packets_h[j]), ctypes.POINTER(Packet)).contents

			# Create a signature buffer
			signature = (ctypes.c_uint8 * cc.SIG_SIZE)()

			# Call ed25519_sign to generate the signature
			ret_sign = cc.ed25519_sign(
				msg_array,  # Message to sign
				packet.public_key,  # Public key
				packet.private_key,  # Private key
				signature,  # Output signature
			)

			# Check if the computed signature matches the one in the packet
			# if ctypes.memcmp(packet.signature, signature, cc.SIG_SIZE) != 0:
			# 	raise ValueError("Invalid signature!")
			if bytes(packet.signature) != bytes(signature):
				raise ValueError("Invalid signature!")

			# Verify the signature
			ret_verify = cc.ed25519_verify(
				packet.signature,  # Signature to verify
				msg_array,  # Message that was signed
				packet.public_key  # Public key for verification
			)

			if ret_verify != 1:
				raise ValueError("Invalid signature!")
		
		threads = []
		start = get_time()

		# Create and start threads
		for i in range(num_threads):
			thread = threading.Thread(target=verify_proc, args=(vctx[i],))
			threads.append(thread)
			thread.start()
			
		# Join threads and check results
		for i in range(num_threads):
			threads[i].join()  # Wait for each thread to complete

		# Record the end time
		end = get_time()

		# Calculate total and time difference
		total = num_threads * total_signatures
		diff = end - start
		print(f"time diff: {diff:.6f} total: {total} verifies/sec: {(total / diff):.2f}")

		# Verify output from each thread
		for thread in range(num_threads):
			LOG("ret:")
			verify_failed = False
			for i in range(out_size):
				# Assuming vctx[thread].out_h is an array-like structure
				if vctx[thread].out_h[i] != 1:
					verify_failed = True
			
			LOG("\n")
			assert not verify_failed  # Ensure verify_failed is False

	except ValueError as e:
		print(e)
		return 1

	# Rest of the function logic would go here
	return 0;

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]));