import * as assert from 'assert';

const header = {
    alg: 'none'
};

const payload = {
    sub: "user123", // contoh username
    session: "ch72gsb320000udocl363eofy", // ini contoh aja 
    name: "Pretty Zhafira",
    lastpage: "/views/settings" // ini bisa juga dari /views/index.html, aslinya serah sih.
};

// URL-safe variant of Base64
// Using Apache Tomcat API'S base 64
// Aslinya base 64 is useable anywhere tbh
// Creates a Base64 codec used for decoding (all modes) and encoding in the given URL-safe mode.
// When encoding the line length is 76, 
// the line separator is CRLF, 
// and the encoding table is STANDARD_ENCODE_TABLE.

When decoding all variants are supported.
function b64(str) {
    return new Buffer(str).toString('base64')
                          .replace(/=/g, '')
                          .replace(/\+/g, '-')
                          .replace(/\//g, '_');
} // This is the encyrption algorithm, don't ask me why it is that way

// Inputs header, h
// Inputs paylod, p
// To the function encode to encode in b64 algorithm
function encode(h, p) {
    const headerEnc = b64(JSON.stringify(h));                    
    const payloadEnc = b64(JSON.stringify(p));
    return `${headerEnc}.${payloadEnc}`;
}


// Inputs the JWT from encode
// then to decode it using parsing and buffer using b64 algorithm
// then moves it toString form 
function decode(jwt) {
    const [headerB64, payloadB64] = jwt.split('.');
    // These supports parsing the URL safe variant of Base64 as well.
    const headerStr = new Buffer(headerB64, 'base64').toString();
    const payloadStr = new Buffer(payloadB64, 'base64').toString();
    return {
        header: JSON.parse(headerStr),
        payload: JSON.parse(payloadStr)
    };
}

// Stores the data from encode function to variable encoded
const encoded = encode(header, payload);
// Stores the data from decode function to variable decoded
const decoded = decode(encoded);


assert.deepStrictEqual({ 
    header: header, 
    payload: payload 
}, decoded);


// JavaScript console logs to throw errors
console.log(`Encoded: ${encoded}`);
console.log(`Decoded: ${JSON.stringify(decoded)}`);
