const http = require('http');
const fs = require('fs');
const {
    generateKeyPairSync,
    sign,
    verify,
    publicEncrypt,
    privateDecrypt
} = require('crypto');

const loveLetter = fs.readFileSync('./love-letter.txt', 'utf-8');

const boyKeys = generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
    },
    privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
    }
});

const girlKeys = generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
    },
    privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
    }
});

const msg = new Buffer.from(loveLetter);
const enc = publicEncrypt(girlKeys.publicKey, msg);

const signature = sign('sha256', enc, boyKeys.privateKey);
const isValid = verify('sha256', enc, boyKeys.publicKey, signature);

const caesarShift = function (str, amount) {
    // Wrap the amount
    if (amount < 0) {
      return caesarShift(str, amount + 26);
    }
  
    // Make an output variable
    let output = "";
  
    // Go through each character
    for (let i = 0; i < str.length; i++) {
      // Get the character we'll be appending
      let c = str[i];
  
      // If it's a letter...
      const regExp = /[a-z]/i;
      if (regExp.test(c)) {
        // Get its code
        let code = str.charCodeAt(i);
  
        // Uppercase letters
        if (code >= 65 && code <= 90) {
          c = String.fromCharCode(((code - 65 + amount) % 26) + 65);
        }
  
        // Lowercase letters
        else if (code >= 97 && code <= 122) {
          c = String.fromCharCode(((code - 97 + amount) % 26) + 97);
        }
      }
  
      // Append
      output += c;
    }
  
    // All done!
    return output;
  };
  
  const symMsg = caesarShift(msg.toString(), 1);

// ***************************************************************  

// Create a server
const server = http.createServer((req, res) => {
    const pathName = req.url;
    
    if(pathName === '/'){
        res.writeHead(200, {'Content-type': 'text/html',});
        res.end('<h1>Welcome my love!</h1>');
    }
    else if(pathName === '/symmetric'){
        res.writeHead(200, {'Content-type': 'text/html',});
        
        res.end(`
            <h3>Symmetric Key is: 1</h3>
            <br>
            <h3>Encrypted message is:</h3>
            <p>${symMsg}</p>
        `);
    }
    else if(pathName === '/asymmetric'){
        res.writeHead(200, {'Content-type': 'text/html',});
        if (isValid) {
            const dec = privateDecrypt(girlKeys.privateKey, enc);
            res.end(`
                <h3>Asymmetric Key is:</h3>
                <p>${boyKeys.publicKey}</p>
                <br>
                <h3>Encrypted message is:</h3>
                <p>${enc.toString()}</p>
            `);
        }
    }
    else{
        res.writeHead(404, {'Content-type': 'text/html',});
        res.end('<h1>OOPS! Page not found!</h1>');
    }
});

server.listen(8000, '127.0.0.1', ()=> {
    console.log('Listening to requests on port 8000');
})