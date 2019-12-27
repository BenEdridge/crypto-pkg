const fs = require('fs');
const crypto = require('crypto');

const pkg = require(`../../package.json`);

// cipher block modes see: https://csrc.nist.gov/publications/detail/sp/800-38d/final
const AES_GCM = 'aes-256-gcm'; // Supports 16 byte IV
const AES_OCB = 'aes-256-ocb'; // Supports 15 byte IV (max)

const loadCommandFromEncryptedFile = () => {
  checkPkg();
  console.log('Loading Encrypted Data...');
  const decryptionKey = crypto.pbkdf2Sync(pkg.encryption_key, 'salt', 100000, 32, 'sha512');
  const fileBuffer = fs.readFileSync('./start.js.encrypted');

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

const writeCommandToEncryptedFile = (command) => {
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

  fs.writeFileSync('./start.js.encrypted', dataToWrite);
};

const checkPkg = () => {
  if(!pkg.encryption_key){
    throw Error('No encryption_key field in package.json');
    process.exit(1);
  }
}

// Self invoking function that decrypts code
// const exec = ((retrieverFn) => {
//   const command = 
//   `
//   const exec = require('child_process').exec;
//   exec('npm install --help', function callback(error, stdout, stderr){
//     console.log(stdout);
//   });
//   `;

//   writeCommandToEncryptedFile(command);

//   const script = retrieverFn();
//   // vm.runInThisContext(script);
//   eval(script);
// })(loadCommandFromEncryptedFile);

module.exports = {
  loadCommandFromEncryptedFile,
  writeCommandToEncryptedFile
}