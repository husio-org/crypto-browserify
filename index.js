exports.DEFAULT_ENCODING = 'buffer';

var SecureRandom=require('./lib/Random').SecureRandom,
    secureRandom=new SecureRandom(),
    DiffieHellman=require("./lib/rv/DiffieHellman"),
    MODE_ENCRYPTOR= 1,
    MODE_DECRYPTOR=0;

/**
 * Random Bytes Generation.
 * It is actually executed synchronously in all cases, but will respect the callback interface.
 * @type {*}
 */
exports.randomBytes=function(l,cb){
    var rb,ret;
    rb=new Array(l);
    secureRandom.nextBytes(rb);
    ret=new Buffer(rb,"binary");
    if(cb) cb(ret);
    return ret;
};

/**
 * Diffie Hellman
 */

exports.getDiffieHellman=function(group){
    switch(group){
        case ('modp2'):
            return new DiffieHellman("MODPG",2);
            break;
        case ('modp14'):
            return new DiffieHellman("MODPG",14);
            break;
        default:
            throw Error("crypto-browserify: DiffieHellman: "+group+" not implemented");
    }
};

/**
 * Utility for data normalization
 * @param hash
 * @constructor
 */
function normalizeData(chunk,encoding){
    if (typeof chunk !== 'string' && !Buffer.isBuffer(chunk))
        throw new TypeError('invalid data');

    if(typeof chunk == 'string'){
        encoding=encoding || "utf8";
        chunk=new Buffer(chunk,encoding);
    }
    return chunk;
}

/**
 * A Generic Digest Adapter to NodeJS API.
 *
 * Will adapt any hash function that returns a HEX string to the NODE API.
 * TODO: streaming support is rudimentary (should extend transform stream)!
 */

function DigestAdapter(hash){

    var Base64=require("./lib/crypto-js/enc-base64").enc.Base64, Hex=require("./lib/crypto-js").enc.Hex;

    this.update=function(chunk,encoding){
        // apply encoding if provided
        var data=normalizeData(chunk,encoding);
        // convert to base64 prior to sending to alg
        hash.update(Base64.parse(data.toString("base64")));
        return this;
    }

    this.digest=function(encoding){
        // convert the digest to HEX
        var hexRet=hash.finalize().toString(Hex), ret=new Buffer(hexRet,"hex");
        // deliver in the required encoding
        if(encoding) return ret.toString(encoding);
        else return ret;
    }
}

/**
 * Hash Support
 */

exports.getHashes=function(){
    return ["sha1","sha256","md5"];
}

exports.createHash=function(alg){
    var CryptoJS, hash;
    switch(alg){
        case ('sha1'):
            CryptoJS=require('./lib/crypto-js/sha1');
            hash=CryptoJS.algo.SHA1.create();
            break;
        case ('sha256'):
            CryptoJS=require('./lib/crypto-js/sha256');
            hash=CryptoJS.algo.SHA256.create();
            break;
        case ('sha512'):
            CryptoJS=require('./lib/crypto-js/sha512');
            hash=CryptoJS.algo.SHA512.create();
            break;
        case ('sha3'):
            CryptoJS=require('./lib/crypto-js/sha3');
            hash=CryptoJS.algo.SHA3.create();
            break;
        case ('md5'):
            CryptoJS=require('./lib/crypto-js/md5');
            hash=CryptoJS.algo.MD5.create();
            break;
        default:
            throw Error("crypto-browserify: Hash: "+alg+" not implemented");
    }

    return new DigestAdapter(hash);

};

/**
 * Ciphers
 * @type {Array}
 */

function CipherivAdapter(MODE, Cipher,keyBuffer,ivBuffer,options){
    var Base64=require("./lib/crypto-js/enc-base64").enc.Base64,
        Hex=require("./lib/crypto-js").enc.Hex,
        key = Hex.parse(keyBuffer.toString("hex")),
        iv  = Hex.parse(ivBuffer.toString("hex")),
        autoPadding=true,
        cipher;

    options.iv=iv;
    if(MODE==MODE_ENCRYPTOR) cipher=Cipher.createEncryptor(key,options);
    else cipher= Cipher.createDecryptor(key,options);

    this.update=function(chunk,iencoding,oencoding){
        var e, r,data;
        // apply encoding if provided
        data=normalizeData(chunk,iencoding);
        // convert to base64 prior to sending to alg
        e=cipher.process(Base64.parse(data.toString("base64")));
        r=new Buffer(e.toString(Base64),"base64");
        if(oencoding)return r.toString(oencoding);
        else return r;
    }

    this.final=function(oencoding){
        var r,e;
        e=cipher.finalize()
        r=new Buffer(e.toString(Hex),"hex");
        if(oencoding)return r.toString(oencoding);
        else return r;
    }

    this.setAutoPadding=function(auto){
        autoPadding=auto;
        if(!auto){
            // to match nodejs behaviour, it seems
            // sometimes required to have 1 buffered frame for unpadding.
            //TODO: this is a workaround
            cipher._minBufferSize = 0;
        }
    }
}

function createCipherIV(MODE, alg,keyBuffer,ivBuffer){
    var CryptoJS, cipher, key, iv, options={};
    switch(alg){
        case ('aes-256-cbc'):
            CryptoJS=require('./lib/crypto-js/aes');
            cipher=CryptoJS.algo.AES;
            options.mode=CryptoJS.mode.CBC;
            //TODO: this is a workaround
            options.padding=CryptoJS.pad.NoPadding;
            options.keySize=256/32;
            break;
        default:
            throw Error("crypto-browserify: Cipher-iv: "+alg+" not implemented");
    }

    return new CipherivAdapter(MODE, cipher,keyBuffer,ivBuffer,options);
};

exports.createCipheriv=function(alg,key,iv){
    return createCipherIV(MODE_ENCRYPTOR,alg,key,iv);
};


exports.createDecipheriv=function(alg,key,iv){
    return createCipherIV(MODE_DECRYPTOR,alg,key,iv);
};

/**
 * HMAC
 * @type {Array}
 */

exports.createHmac=function(alg,keyBuffer){
    var CryptoJS, hmac,
        Hex=require("./lib/crypto-js").enc.Hex,
        key = Hex.parse(keyBuffer.toString("hex"));

    switch(alg){
        case ('md5'):
            CryptoJS=require('./lib/crypto-js/hmac-md5');
            hmac=CryptoJS.algo.HMAC.create(CryptoJS.algo.MD5,key);
            break;
        default:
            throw Error("crypto-browserify: Hmac: "+alg+" not implemented");
    }

    return new DigestAdapter(hmac);

};


/**
 * By default, there is no inmplementation of the following:
 */
var unimplemented=[
    'getCiphers',
    'createCredentials',
    'Hmac',
    'createCipher',
    'Cipher',
    'createDecipher',
    'Decipher',
    'createSign',
    'Sign',
    'createVerify',
    'Verify',
    'createDeffieHellman',
    'DiffieHellman',
    'pbkdf2',
    'pseudoRandomBytes'
];

/**
 * Add one export for each informing the developer
 */
unimplemented.forEach(
    function (name) {
        exports[name] = function () {
            throw new Error('crypto-browserify: sorry, '+ name +' not implemented yet')
        }
    }
);