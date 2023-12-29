// quantum_resistant.js

const ffi = require('ffi');

// Load the compiled C library
const libquantum_resistant = ffi.Library('./build/libquantum_resistant', {
    'quantum_resistant_encrypt': ['void', ['string', 'string']],
    'quantum_resistant_decrypt': ['void', ['string', 'string']],
});

// Export the functions
module.exports = {
    encrypt: libquantum_resistant.quantum_resistant_encrypt,
    decrypt: libquantum_resistant.quantum_resistant_decrypt,
};
