// Contains the require override which makes below code work;
require('crypto-pkg')(true); // true enables the require override

// uses custom require to decrypt and require as string
const decrypted = require('./enc.js');