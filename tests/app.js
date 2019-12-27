const cryptopkg = require('crypto-pkg');
const vm = require('vm');

  const command = 
  `
    const exec = require('child_process').exec;
    exec('npm install --help', function callback(error, stdout, stderr){
      console.log(stdout);
    });
  `;

// Writes the above into a file
cryptopkg.writeCommandToEncryptedFile(command);

// Loads the above and decrypts based on the password in the pack
const decryptedCommand = cryptopkg.loadCommandFromEncryptedFile();

// vm.runInThisContext(decryptedCommand); // require will fail
eval(decryptedCommand);