/**
 * Diffie Hellman implementation by Rafael del Valle
 * User: rafael
 * Date: 9/7/13
 * Time: 8:38 AM
 */

var BigInteger=require("./../BigInteger"),
    SecureRandom=require("./../Random").SecureRandom,
    secureRandom=new SecureRandom();


/**
 * More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)
 * RFC: 3526
 * @type {{14: {g: generator, p: prime number}}}
 */
var MODPG={
    2:{
        g: new BigInteger("2"),
        p: new BigInteger("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff",16),
        kl:1024
    },
    14:{
        g: new BigInteger("2"),
        p: new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",16),
        kl:2048
    }
}



/**
 * Diffie Hellman implementation based on BigInteger. Most functions implemented in-constructor closure.
 * Private items kept private.
 * @param g the generator or "MODP" if a RFC3526 group is to be used
 * @param p the prime or group id if RFC3526 group is to be used
 * @param kl the key length to use for private value (bytes)
 * @constructor
 */
function DiffieHellman(g,p){
    if(!(this instanceof DiffieHellman)) return new DiffieHellman(g,p,kl);
    var privateValue,publicValue,masterValue,kl;

    // Normalize the construction parameter, can be either g,n or an entry in MODP
    if(typeof g == "string"){
        var id=p;
        g=MODPG[id].g;
        p=MODPG[id].p;
        kl=MODPG[id].kl;
    }

    function generatePrivateValue(){
        // generate a secure random key of kl bits
        if(!privateValue) privateValue=new BigInteger(kl,secureRandom);
    }

    function generatePublicValue(){
        generatePrivateValue();
        if(!publicValue){
            publicValue=g.modPow(privateValue,p);
        }
    }

    this.getPublicValue=function(){
        generatePublicValue();
        return publicValue;
    }

    this.computeMasterValue=function(peerPublicValue){
        generatePrivateValue();
        generatePublicValue();
        if(!masterValue) masterValue=peerPublicValue.modPow(privateValue,p);
        return masterValue;
    }

    this.getPrimeBI=function(){
        return p;
    }

    this.getGeneratorBI=function(){
        return g;
    }

    return this;
}


/**
 * Utility method to adapt to nodejs interface
 * @param encoding
 */
DiffieHellman.prototype.generateKeys=function(encoding){
    var pk=this.getPublicValue(),
        ret=pk.toBuffer();
    if(encoding) return ret.toString(encoding);
    else return ret;
}

/**
 * Utility method to adapt to nodejs interface
 * @type {*}
 */
DiffieHellman.prototype.computeSecret=function(peerKey,iencoding,encoding){
    var peerPublicValue,masterValue;
    if(iencoding) peerKey=new Buffer(peerKey,iencoding);
    peerPublicValue=new BigInteger(peerKey);
    masterValue=this.computeMasterValue(peerPublicValue);
    if(encoding) return masterValue.toBuffer().toString(encoding);
    else return masterValue.toBuffer();
}


/**
 * Utility method to adapt to nodejs interface
 * @param encoding
 */
DiffieHellman.prototype.getPrime=function(encoding){
    var p=this.getPrimeBI(),
        ret=p.toBuffer();
    if(encoding) return ret.toString(encoding);
    else return ret;
}

/**
 * Utility method to adapt to nodejs interface
 * @param encoding
 */
DiffieHellman.prototype.getGenerator=function(encoding){
    var g=this.getGeneratorBI(),
        ret=g.toBuffer();
    if(encoding) return ret.toString(encoding);
    else return ret;
}


module.exports=DiffieHellman;