import * as assert from 'assert';
import bigInt from 'big-integer';
import jwt from 'jsonwebtoken';


export const privateKey = { 
    size: 2048
};  

// You can get these numbers with:
// openssl rsa -inform PEM -text -noout < testkey.pem


const secret = 'my-secret-key';

const publicRsaKey = `-----BEGIN PUBLIC KEY----- 
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----`;

const privateRsaKey = `-----BEGIN RSA PRIVATE KEY----- 
MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQABAoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==
-----END RSA PRIVATE KEY-----`;

const publicEcdsaKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEucQ/nQfEgmk5i5czxYtI1TWacrF+
FEXcuIFdf0P6NP3ai7P8r7F40KQn4qqLvAvu7kEAvRRPNVm7nvxxpJdQnQ==
-----END PUBLIC KEY-----`;

const privateEcdsaKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEOnd9s41dBNbV9FLRfmi/5vcTbbgX14aIgpuFxqIMUMoAoGCCqGSM49
AwEHoUQDQgAEucQ/nQfEgmk5i5czxYtI1TWacrF+FEXcuIFdf0P6NP3ai7P8r7F4
0KQn4qqLvAvu7kEAvRRPNVm7nvxxpJdQnQ==
-----END EC PRIVATE KEY-----`;

const signed = {
    hs256: jwt.sign(payload, secret, { 
        algorithm: 'HS256',
        expiresIn: '5s' 
    }),

    rs256: jwt.sign(payload, privateRsaKey, {
        algorithm: 'RS256',
        expiresIn: '5s'
    }),

    es256: jwt.sign(payload, privateEcdsaKey, {
        algorithm: 'ES256',
        expiresIn: '5s'
    }) 
};

const decodedEncryption = {
    hs256: jwt.verify(signed.hs256, secret, {
        // Never forget to make this explicit to prevent
        // signature stripping attacks
        algorithms: ['HS256'], 
    }),

    rs256: jwt.verify(signed.rs256, publicRsaKey, {
        // Never forget to make this explicit to prevent
        // signature stripping attacks
        algorithms: ['RS256'], 
    }),

    es256: jwt.verify(signed.es256, publicEcdsaKey, {
        // Never forget to make this explicit to prevent
        // signature stripping attacks
        algorithms: ['ES256'], 
    })
};



privateKey.n = bigInt('00c900c367fe9ad3893a9b69e59cf0' +
                    '65a93f2e431a731463c57796b27fe1' +
                    'd345535d8350b7dd436cf72a0fee54' +
                    '0a6a200f447a80c8d3833db068ef64' +
                    'b6f62f056be40a3db283cf4ddb3d0f' +
                    '26904cefa5f3573d17f80ac221aab5' +
                    '0a212bf381fc5d7a2e5df9cdbc6d86' +
                    'bdb298c1e2ca3ea0c9aeb0dcbe20db' +
                    'a565aa31dc019ccd2c15d05890720c' +
                    'e16eaec46adae1d1ec24531a79be31' +
                    '7bdd61d7642c7b9d6cdeb0ee06caa1' +
                    'f0b42d5b6844574d1e9f9fc763c2f2' +
                    '2e52e255caf20c26ce3c1cec5e855d' +
                    '079f89075d2ff933a41c9eee05b099' +
                    'c49dd5300b276e1b23b5298ebdf46f' +
                    '4daf07bb77ff315c5a831da1f9e1a0' +
                    '8dedff3fdbbd5155480478f5a2261a' +
                    '5941', 16);

privateKey.d = bigInt('1dc96f2bca1f4799de85897bed75f2' +
                    '9ad23218dfa28e32fae06e04a5cee1' +
                    '70349a770b4f340af9eae6e0d580be' +
                    'ca5b55e7dfff95c3427fb1d4db2521' +
                    'b7f9dfe3cd37774d2d1b5b7e51de1c' +
                    'e8e57dde29e193bc2995ee8eeead45' +
                    '8304f06122f4f75647b6ed362f44f8' +
                    '77af0b8c804c27a7bbab9a0ad2f3b9' +
                    'df0709bc80c0abe6c90518999a19d0' +
                    'c0910a7fb46cd3a2c77c1fea297cc5' +
                    'c91640bde500322f225abf22baf69e' +
                    '45c0e53286f323381cd9bf8ef3837a' +
                    '2cc5c944778880834d081bcd01d9f2' +
                    '456c3a4a7e51a4acb2c3c0908b8755' +
                    '93117258f012f63e5cb25b84944940' +
                    'ef413dd29022f090ff93457638ebf9' +
                    '1e3658fe91fcb2f4b489d8981ce732' +
                    'c1', 16);

// You can get these numbers with:
// openssl rsa -pubin -inform PEM -text -noout < pubtestkey.pem
// Adding a publicKey consisting of the privateKey's size to secure the JWT
export const publicKey = {
    size: privateKey.size,
    n: privateKey.n,
    e: bigInt(0x10001)
};

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

function b64(str) {
    return new Buffer(str).toString('base64')
                          .replace(/=/g, '')
                          .replace(/\+/g, '-')
                          .replace(/\//g, '_');
} // This is the encyrption algorithm, don't ask me why it is that way

// ------------------ CLIENT SIDE --------------
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
// -------------------------------------------------

// -- STORES THE ENCRYPTION KE VARIABLE YANG CONSTANT ---
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
console.log(`Decoded: ${JSON.stringify(decoded.hs256)}`);


// Check that the token is invalid after 5 seconds.
setTimeout(() => {
    assert.throws(() => {
        jwt.verify(signed.hs256, secret, {
            algorithms: ['HS256']
        });
    });
    process.exit();
}, 5100);









