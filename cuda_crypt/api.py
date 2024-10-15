import cuda_crypt.wrapper as cc
import os, time, ctypes, math


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
        ("private_key", ctypes.c_uint8 * cc.PRIV_KEY_SIZE),
        ("signature", ctypes.c_uint8 * cc.SIG_SIZE),
        ("public_key", ctypes.c_uint8 * cc.PUB_KEY_SIZE),
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
        ("num_iterations", ctypes.c_int),
        ("use_non_default_stream", ctypes.c_uint8)
    ]

def get_diff(start, end):
	return end - start  # Convert seconds to microseconds
	
def get_time():
    return time.time()

def LOG(message, *args):
    # Check if verbosity is enabled from the environment variable
    if os.getenv("VERBOSE") == "1":
        # Use string formatting for the message and arguments
        print(message % args);

def create_keypair():
	# create seed:
	seed_h = (ctypes.c_ubyte * cc.SEED_SIZE)()
	check = cc.ed25519_create_seed(seed_h)
	if check != 0:
		raise ValueError("Failed to create seed")

	# create key
	public_key = (ctypes.c_ubyte * cc.PUB_KEY_SIZE)()
	private_key = (ctypes.c_ubyte * cc.PRIV_KEY_SIZE)()
	cc.ed25519_create_keypair(public_key, private_key, seed_h)

	return bytes(public_key), bytes(private_key)

def sign(msg: bytes, pub_key, priv_key):
	public_key = (ctypes.c_ubyte * cc.PUB_KEY_SIZE)(*pub_key)
	private_key = (ctypes.c_ubyte * cc.PRIV_KEY_SIZE)(*priv_key)


	msg_array = (ctypes.c_ubyte * len(msg))(*msg)
	signature = (ctypes.c_ubyte * cc.SIG_SIZE)()
	cc.ed25519_sign(msg_array, public_key, private_key, signature)

	return bytes(signature)

def verify(msg: bytes, sign: bytes, pub_key: bytes):
	msg_buf = (ctypes.c_ubyte * len(msg))(*msg)
	signature = (ctypes.c_ubyte * cc.SIG_SIZE)(*sign)
	public_key = (ctypes.c_ubyte * cc.PUB_KEY_SIZE)(*pub_key)

	return cc.ed25519_verify(signature, msg_buf, public_key)

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
      
def sign_many(messages: list[bytes], pub_keys: list[bytes], priv_keys: list[bytes]):
	count = len(messages);
	if count != len(pub_keys) or count != len(priv_keys):
		raise ValueError("parameters length must be same") 
	
	prepare_start = get_time();

	# Allocate arrays (equivalent to ed25519_alloc)
	message_lens = (ctypes.c_uint32 * count)()
	signature_offsets = (ctypes.c_uint32 * count)()
	public_key_offsets = (ctypes.c_uint32 * count)()
	private_key_offsets = (ctypes.c_uint32 * count)()
	message_start_offsets = (ctypes.c_uint32 * count)()

	# Fill offsets and lengths
	for i in range(count):
		base_offset = i * ctypes.sizeof(StreamerPacket)
		signature_offsets[i] = base_offset + Packet.signature.offset
		public_key_offsets[i] = base_offset + Packet.public_key.offset
		private_key_offsets[i] = base_offset + Packet.private_key.offset
		message_start_offsets[i] = base_offset + Packet.message.offset
		message_lens[i] = len(messages[i])

	# Allocating packets memory
	packets_h = (StreamerPacket * count)()

	# Initing packets...
	for i in range(count):
		packet = ctypes.cast(ctypes.byref(packets_h[i]), ctypes.POINTER(Packet)).contents

		# copy message to the packet
		# ctypes.memmove(packet.message, messages[i], len(messages[i]))
		msg_len = len(messages[i])
		packet.message[:msg_len] = messages[i][:msg_len]

		# Copy the public key and private key to the packet
		# ctypes.memmove(packet.public_key, ctypes.byref(pub_keys[i], i * cc.PUB_KEY_SIZE), cc.PUB_KEY_SIZE)
		packet.public_key[:cc.PUB_KEY_SIZE] = pub_keys[i][:cc.PUB_KEY_SIZE]

		# Copy private keys into the packet
		packet.private_key[:cc.PRIV_KEY_SIZE] = priv_keys[i][:cc.PRIV_KEY_SIZE]
	
	gpu_elem = cc.gpu_Elems(
		num = count,
		elems = ctypes.cast(ctypes.pointer(packets_h[0]), ctypes.POINTER(ctypes.c_uint8))
	)
	

	# Create verify_cpu_ctx_t structure
	out_size = count * ctypes.sizeof(ctypes.c_uint8)
	out_h = (ctypes.c_uint8 * out_size)()
      
	vctx = VerifyCpuCtx(
		elems_h = ctypes.pointer(gpu_elem),
        num_elems = 1,
		total_packets=count,
		total_signatures=count,
		message_lens = message_lens,
		public_key_offsets = public_key_offsets,
		private_key_offsets = private_key_offsets,
		signature_offsets = signature_offsets,
		message_start_offsets = message_start_offsets,
		out_h = out_h,
		use_non_default_stream = 1,
	)
      
	gpu_start = get_time()
	signatures_h = (ctypes.c_uint8 * (cc.SIG_SIZE * count))()
	cc.ed25519_sign_many(
		vctx.elems_h,
		vctx.num_elems,
		ctypes.sizeof(StreamerPacket),  # Replace with appropriate packet size
		vctx.total_packets,
		vctx.total_signatures,
		vctx.message_lens,
		vctx.public_key_offsets,
		vctx.private_key_offsets,
		vctx.message_start_offsets,
		signatures_h,
		vctx.use_non_default_stream,
	);
	gpu_end = get_time()

	prepare_time = gpu_start - prepare_start
	gpu_time = gpu_end - gpu_start
	LOG(f"sign) prepare: {prepare_time:.2f} sec,  gpu: {gpu_time:.2f} sec")
	LOG(f"sign) over-all performance: {count/(prepare_time+gpu_time):.2f},  gpu performance: {count/gpu_time:.2f}\n")

	return [bytes(signatures_h[i*cc.SIG_SIZE:(i+1)*cc.SIG_SIZE]) for i in range(count)]

def padding_size():
	return ctypes.sizeof(StreamerPacket);

def verify_many(joined_data: bytearray, msg_lens: list[int]) :
	count = len(msg_lens);

	# Allocate arrays (equivalent to ed25519_alloc)
	message_lens = (ctypes.c_uint32 * count)()
	signature_offsets = (ctypes.c_uint32 * count)()
	public_key_offsets = (ctypes.c_uint32 * count)()
	message_start_offsets = (ctypes.c_uint32 * count)()

	# Fill offsets and lengths
	offset_shift = Packet.signature.offset
	for i in range(count):
		base_offset = i * ctypes.sizeof(StreamerPacket)
		signature_offsets[i] = base_offset + Packet.signature.offset - offset_shift
		public_key_offsets[i] = base_offset + Packet.public_key.offset - offset_shift
		message_start_offsets[i] = base_offset + Packet.message.offset - offset_shift
		message_lens[i] = msg_lens[i]

	prepare_start = get_time()

	# Initing packets...
	total_size = padding_size() * count
	gpu_elem = cc.gpu_Elems(
		num = count,
		elems = (ctypes.c_uint8 * total_size).from_buffer(joined_data)
	)
	
	out_size = count * ctypes.sizeof(ctypes.c_uint8)
	out_h = (ctypes.c_uint8 * out_size)()
      
	prepare_end = get_time()
      
	gpu_start = get_time()
	cc.ed25519_verify_many(
		elems=ctypes.pointer(gpu_elem),
		num_elems=1,
		message_size=ctypes.sizeof(StreamerPacket),  # Replace with appropriate packet size
		total_packets=count,
		total_signatures=count,
		message_lens=message_lens,
		public_key_offsets=public_key_offsets,
		signature_offsets=signature_offsets,
		message_start_offsets=message_start_offsets,
		out=out_h,
		use_non_default_stream=1,
	);
	gpu_end = get_time()

	prepare_time = prepare_end - prepare_start
	gpu_time = gpu_end - gpu_start
	LOG(f"verify) copy: prepare: {prepare_time:.2f} sec,  gpu: {gpu_time:.2f} sec")
	LOG(f"verify) over-all performance: {count/(gpu_end-prepare_start):.2f},  gpu performance: {count/gpu_time:.2f}\n")

	return bytes(out_h)
