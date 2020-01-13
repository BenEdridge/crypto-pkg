// Loading the Module.require prototype override
// Inspired by https://github.com/boblauer/mock-require/blob/master/index.js
// https://stackoverflow.com/questions/27948300/override-the-require-function/34186494
// https://stackoverflow.com/questions/17581830/load-node-js-module-from-string-in-memory
// https://github.com/floatdrop/require-from-string/blob/master/index.js

'use strict';
const mod = require('module');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const vm = require('vm');
const pkg = require(`./package.json`);

// cipher block modes see: https://csrc.nist.gov/publications/detail/sp/800-38d/final
const AES_GCM = 'aes-256-gcm'; // Supports 16 byte IV
const AES_OCB = 'aes-256-ocb'; // Supports 15 byte IV (max)

const loadCommandFromEncryptedFile = (path) => {
  checkPkg();
  console.log('Loading Encrypted Data...');
  const decryptionKey = crypto.pbkdf2Sync(pkg.encryption_key, 'salt', 100000, 32, 'sha512');
  const fileBuffer = fs.readFileSync(path);

  //OCB IV
  const extractedIv = fileBuffer.slice(0, 15);
  const extractedTag = fileBuffer.slice(15, 31);
  const encryptedData = fileBuffer.slice(31);

  // For IV of 16
  //const extractedIv = fileBuffer.slice(0, 16);
  //const extractedTag = fileBuffer.slice(16, 32);
  //const encryptedData = fileBuffer.slice(32);

  const decipher = crypto.createDecipheriv(AES_OCB, decryptionKey, extractedIv, { authTagLength: 16 });
  // Should be always called before final
  decipher.setAuthTag(extractedTag);

  //decipher.setAAD('hello');
  let decrypted = decipher.update(encryptedData);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString('utf8');
};

const writeCommandToEncryptedFile = (command, path) => {
  checkPkg();
  const encryptionKey = crypto.pbkdf2Sync(pkg.encryption_key, 'salt', 100000, 32, 'sha512');

  const randomIv = crypto.randomBytes(15);
  const cipher = crypto.createCipheriv(AES_OCB, encryptionKey, randomIv, { authTagLength: 16 });

  // cipher.setAAD('hello');
  let encrypted = cipher.update(Buffer.from(command, 'utf8'));
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  // Should only be called after final
  const tag = cipher.getAuthTag();
  const dataToWrite = Buffer.concat([randomIv, tag, encrypted]);

  fs.writeFileSync(path, dataToWrite);
};

const checkPkg = () => {
  if (!pkg.encryption_key) {
    throw Error('No encryption_key field in package.json');
  }
}

function encryptedRequire(path) {
  requireFromString(loadCommandFromEncryptedFile(path));
}

function encryptedEval(path) {
  eval(loadCommandFromEncryptedFile(path));
}

function encryptedRunInVm(path) {
  const script = loadCommandFromEncryptedFile(path);
  vm.runInContext(script);
}

// https://github.com/floatdrop/require-from-string/blob/master/index.js
function requireFromString(code, filename, opts) {
  if (typeof filename === 'object') {
    opts = filename;
    filename = undefined;
  }

  opts = opts || {};
  filename = filename || crypto.createHash('SHA512').update(code).digest('hex');

  opts.appendPaths = opts.appendPaths || [];
  opts.prependPaths = opts.prependPaths || [];

  if (typeof code !== 'string') {
    throw new Error('code must be a string, not ' + typeof code);
  }

  let paths = mod._nodeModulePaths(path.dirname(filename));

  let parent = module.parent;
  let m = new mod(filename, parent);
  m.filename = filename;
  m.paths = [].concat(opts.prependPaths).concat(paths).concat(opts.appendPaths);
  m._compile(code, filename);

  let exports = m.exports;
  parent && parent.children && parent.children.splice(parent.children.indexOf(m), 1);

  return exports;
};

// https://stackoverflow.com/questions/7367850/node-js-require-function-and-parameters
module.exports = function (overrideRequire) {

  // if this is true then we override the require function
  if (overrideRequire) {

    const originalRequire = mod.prototype.require;

    mod.prototype.require = function (path) {

      if (mod.builtinModules.includes(path)) {
        console.log(`Built-in module: "${path}" Decryption not possible`);
        return originalRequire.apply(this, arguments);
      } else {
        console.log('Decrypting then requiring', path);
        const string = loadCommandFromEncryptedFile(path);
        requireFromString(string);

        // return originalRequire.apply(this, arguments);
        // return mod._load(this.path, this);
      }
    };

    return {
      loadCommandFromEncryptedFile,
      writeCommandToEncryptedFile,
      encryptedEval,
      encryptedRunInVm
    }

  } else {
    return {
      encryptedEval,
      encryptedRequire,
      encryptedRunInVm,
      loadCommandFromEncryptedFile,
      writeCommandToEncryptedFile
    }
  }
}