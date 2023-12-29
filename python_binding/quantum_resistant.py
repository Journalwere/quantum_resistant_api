# quantum_resistant.py

from ctypes import CDLL, c_char_p

# Load the compiled C library
libquantum_resistant = CDLL('./build/libquantum_resistant.so')

# Define function prototypes
encrypt = libquantum_resistant.quantum_resistant_encrypt
encrypt.argtypes = [c_char_p, c_char_p]
encrypt.restype = None

decrypt = libquantum_resistant.quantum_resistant_decrypt
decrypt.argtypes = [c_char_p, c_char_p]
decrypt.restype = None
