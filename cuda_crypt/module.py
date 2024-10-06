import ctypes
import os
from ctypes import POINTER, c_ubyte, c_int, c_uint32, c_size_t, c_char_p, Structure

# Load the shared library
module_dir = os.path.dirname(__file__)
cuda_crypt = ctypes.CDLL(os.path.join(module_dir, 'libcuda-crypt.so'))

# Constants
SHA512_SIZE = 64
PUB_KEY_SIZE = 32
PRIV_KEY_SIZE = 64
SEED_SIZE = 32
SCALAR_SIZE = 32
SIG_SIZE = 64

# Define gpu_Elems structure
class gpu_Elems(Structure):
    _fields_ = [("elems", POINTER(c_ubyte)),
                ("num", c_uint32)]

# Function Signatures

# ed25519_create_seed
cuda_crypt.ed25519_create_seed.argtypes = [POINTER(c_ubyte)]
cuda_crypt.ed25519_create_seed.restype = c_int

# ed25519_create_keypair
cuda_crypt.ed25519_create_keypair.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte)]
cuda_crypt.ed25519_create_keypair.restype = None

# ed25519_sign
cuda_crypt.ed25519_sign.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_size_t, POINTER(c_ubyte), POINTER(c_ubyte)]
cuda_crypt.ed25519_sign.restype = None

# ed25519_sign_many
cuda_crypt.ed25519_sign_many.argtypes = [
    POINTER(gpu_Elems), c_uint32, c_uint32, c_uint32, c_uint32,
    POINTER(c_uint32), POINTER(c_uint32), POINTER(c_uint32), POINTER(c_uint32),
    POINTER(c_ubyte), c_ubyte
]
cuda_crypt.ed25519_sign_many.restype = None

# ed25519_verify
cuda_crypt.ed25519_verify.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_uint32, POINTER(c_ubyte)]
cuda_crypt.ed25519_verify.restype = c_int

# ed25519_verify_many
cuda_crypt.ed25519_verify_many.argtypes = [
    POINTER(gpu_Elems), c_uint32, c_uint32, c_uint32, c_uint32,
    POINTER(c_uint32), POINTER(c_uint32), POINTER(c_uint32), POINTER(c_uint32),
    POINTER(c_ubyte), c_ubyte
]
cuda_crypt.ed25519_verify_many.restype = None

# ed25519_set_verbose
cuda_crypt.ed25519_set_verbose.argtypes = [ctypes.c_bool]
cuda_crypt.ed25519_set_verbose.restype = None

# ed25519_license
cuda_crypt.ed25519_license.argtypes = []
cuda_crypt.ed25519_license.restype = c_char_p

# ed25519_init
cuda_crypt.ed25519_init.argtypes = []
cuda_crypt.ed25519_init.restype = ctypes.c_bool

# cuda_host_register
cuda_crypt.cuda_host_register.argtypes = [ctypes.c_void_p, c_size_t, c_uint32]
cuda_crypt.cuda_host_register.restype = c_int

# cuda_host_unregister
cuda_crypt.cuda_host_unregister.argtypes = [ctypes.c_void_p]
cuda_crypt.cuda_host_unregister.restype = c_int

# ed25519_get_checked_scalar
cuda_crypt.ed25519_get_checked_scalar.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
cuda_crypt.ed25519_get_checked_scalar.restype = c_int

# ed25519_check_packed_ge_small_order
cuda_crypt.ed25519_check_packed_ge_small_order.argtypes = [POINTER(c_ubyte)]
cuda_crypt.ed25519_check_packed_ge_small_order.restype = c_int


# Python Wrappers for the Methods

def ed25519_create_seed(seed_h) -> bytes:
    return cuda_crypt.ed25519_create_seed(seed_h)

def ed25519_create_keypair(public_key, private_key, seed):
    return cuda_crypt.ed25519_create_keypair(public_key, private_key, seed)

def ed25519_sign(message: bytes, public_key: bytes, private_key: bytes, signature) -> bytes:
    cuda_crypt.ed25519_sign(signature, message, len(message), public_key, private_key)

def ed25519_verify(signature: bytes, message: bytes, public_key: bytes) -> int:
    sig_array = (c_ubyte * SIG_SIZE)(*signature)
    msg_array = (c_ubyte * len(message))(*message)
    pk_array = (c_ubyte * PUB_KEY_SIZE)(*public_key)
    
    return cuda_crypt.ed25519_verify(sig_array, msg_array, len(message), pk_array)

def ed25519_sign_many(elems: gpu_Elems, num_elems: int, message_size: int, total_packets: int, total_signatures: int, 
                      message_lens: list, public_key_offsets: list, private_key_offsets: list, message_start_offsets: list,
                      signatures_out: bytearray, use_non_default_stream: int):
    
    # msg_lens_array = (c_uint32 * len(message_lens))(*message_lens)
    # pk_offsets_array = (c_uint32 * len(public_key_offsets))(*public_key_offsets)
    # sk_offsets_array = (c_uint32 * len(private_key_offsets))(*private_key_offsets)
    # msg_start_offsets_array = (c_uint32 * len(message_start_offsets))(*message_start_offsets)
    # signatures_out_array = (c_ubyte * len(signatures_out))(*signatures_out)

    # cuda_crypt.ed25519_sign_many(elems, num_elems, message_size, total_packets, total_signatures,
    #                              msg_lens_array, pk_offsets_array, sk_offsets_array, msg_start_offsets_array,
    #                              signatures_out_array, use_non_default_stream)

    cuda_crypt.ed25519_sign_many(elems, num_elems, message_size, total_packets, total_signatures,
                                 message_lens, public_key_offsets, private_key_offsets, message_start_offsets,
                                 signatures_out, use_non_default_stream)

def ed25519_verify_many(elems: gpu_Elems, num_elems: int, message_size: int, total_packets: int, total_signatures: int, 
                        message_lens: list, public_key_offsets: list, private_key_offsets: list, message_start_offsets: list,
                        out: bytearray, use_non_default_stream: int):

    # msg_lens_array = (c_uint32 * len(message_lens))(*message_lens)
    # pk_offsets_array = (c_uint32 * len(public_key_offsets))(*public_key_offsets)
    # sk_offsets_array = (c_uint32 * len(private_key_offsets))(*private_key_offsets)
    # msg_start_offsets_array = (c_uint32 * len(message_start_offsets))(*message_start_offsets)
    # out_array = (c_ubyte * len(out))(*out)

    # cuda_crypt.ed25519_verify_many(elems, num_elems, message_size, total_packets, total_signatures,
    #                                msg_lens_array, pk_offsets_array, sk_offsets_array, msg_start_offsets_array,
    #                                out_array, use_non_default_stream)

    cuda_crypt.ed25519_verify_many(elems, num_elems, message_size, total_packets, total_signatures,
                                   message_lens, public_key_offsets, private_key_offsets, message_start_offsets,
                                   out, use_non_default_stream)
    
def ed25519_set_verbose(val: bool) -> None:
    """
    Sets the verbose mode on or off.
    
    :param val: A boolean indicating whether to set verbose mode.
    """
    cuda_crypt.ed25519_set_verbose(val)

def ed25519_license() -> str:
    """
    Returns the license string of the ed25519 library.
    
    :return: A string containing the library's license.
    """
    license_str = cuda_crypt.ed25519_license()
    return license_str.decode('utf-8')

def ed25519_init() -> bool:
    """
    Initializes the ed25519 library.
    
    :return: A boolean indicating success or failure.
    """
    return cuda_crypt.ed25519_init()

def cuda_host_register(ptr: ctypes.c_void_p, size: int, flags: int) -> int:
    """
    Registers memory with CUDA to allow page-locked memory transfers.
    
    :param ptr: A pointer to the memory.
    :param size: The size of the memory to register.
    :param flags: Flags for memory registration.
    :return: An integer result (0 for success).
    """
    return cuda_crypt.cuda_host_register(ptr, size, flags)

def cuda_host_unregister(ptr: ctypes.c_void_p) -> int:
    """
    Unregisters previously registered memory with CUDA.
    
    :param ptr: A pointer to the memory.
    :return: An integer result (0 for success).
    """
    return cuda_crypt.cuda_host_unregister(ptr)

def ed25519_get_checked_scalar(in_scalar: bytes) -> bytes:
    """
    Ensures the scalar is correctly clamped for ed25519.
    
    :param in_scalar: A 32-byte scalar input.
    :return: A 32-byte checked scalar output.
    """
    out_scalar = (c_ubyte * SCALAR_SIZE)()
    in_scalar_array = (c_ubyte * SCALAR_SIZE)(*in_scalar)
    
    result = cuda_crypt.ed25519_get_checked_scalar(out_scalar, in_scalar_array)
    
    if result != 0:
        raise ValueError("Failed to check scalar")
    
    return bytes(out_scalar)

def ed25519_check_packed_ge_small_order(packed_group_element: bytes) -> int:
    """
    Checks if a packed group element has a small order.
    
    :param packed_group_element: A 32-byte packed group element.
    :return: An integer result (0 for success).
    """
    packed_array = (c_ubyte * PUB_KEY_SIZE)(*packed_group_element)
    return cuda_crypt.ed25519_check_packed_ge_small_order(packed_array)
