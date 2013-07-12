/**
 * User: rafael
 * Date: 9/7/13
 * Time: 7:12 AM
 */


var nodeCrypto=require('crypto'),
    browserCrypto=require('..'),
    expect=require("chai").expect;


describe("Will test Node Crypto",function(){
    it("will require the list of hashes",function(){
        console.log('HASHES:'+nodeCrypto.getHashes());
    });
});

describe("It will test unimplemented APIs",function(){
    it("Will try to request a DiffieHellman",function(){
        var fn=function(){
            new browserCrypto.createSign();
        }
        expect(fn).to.throw(Error,/not implemented/);
    });
});

describe("It will test randomBytes generation",function(){
    it("will test sync generation",function(){
        var b=browserCrypto.randomBytes(64);
        expect(b).to.be.instanceof(Buffer);
        expect(b.length).equal(64);
    });
});


describe("Will compare hash algorithms in node and browserify",function(){

    describe("Will run simple, not streaming tests, only one update/digest",function(){
        var cleanText="Hello World this is me from Täby or España", cleanBinary=[2,78,235,128,132,27,45,89,243,38,43,20,234,32,135,123];

        function hashSample(hash){
            return hash.update(cleanText,'utf8').digest('hex');
        }

        function hashBinSample(hash){
            return hash.update(new Buffer(cleanBinary)).digest('hex');
        }

        describe("Will test with UTF8 samples", function(){

            it("will test sha1",function(){
                console.log("DEBUG:");
                console.log("SHA1N:"+hashSample(nodeCrypto.createHash('sha1')));
                console.log("SHA1B:"+hashSample(browserCrypto.createHash('sha1')));

                expect(hashSample(nodeCrypto.createHash('sha1'))).equal(hashSample(browserCrypto.createHash('sha1')));
            });

            it("will test sha256",function(){
                expect(hashSample(nodeCrypto.createHash('sha256'))).equal(hashSample(browserCrypto.createHash('sha256')));
            });

            it("will test sha512",function(){
                expect(hashSample(nodeCrypto.createHash('sha512'))).equal(hashSample(browserCrypto.createHash('sha512')));
            });

            // Sha3 is not yet supported in Nodejs
            xit("will test sha3",function(){
                expect(hashSample(nodeCrypto.createHash('sha3'))).equal(hashSample(browserCrypto.createHash('sha3')));
            });

            it("will test md5",function(){
                expect(hashSample(nodeCrypto.createHash('md5'))).equal(hashSample(browserCrypto.createHash('md5')));
            });
        });

        describe("Will test with binary samples", function(){

            it("will test sha1 with bin data",function(){
                expect(hashBinSample(nodeCrypto.createHash('sha1'))).equal(hashBinSample(browserCrypto.createHash('sha1')));
            });

            it("will test sha256 with bin data",function(){
                expect(hashBinSample(nodeCrypto.createHash('sha256'))).equal(hashBinSample(browserCrypto.createHash('sha256')));
            });

            it("will test md5 with bin data",function(){
                expect(hashBinSample(nodeCrypto.createHash('md5'))).equal(hashBinSample(browserCrypto.createHash('md5')));
            });
        });

        describe("Will test HMAC",function(){
            var key=new Buffer("HMAC Secret","utf8");

            it("will test md5",function(){
                expect(hashSample(nodeCrypto.createHmac('md5',key))).equal(hashSample(browserCrypto.createHmac('md5',key)));
            });

        });

    });

    describe("Will run CipherIV tests",function(){
        var key=new Buffer('b0e54e5dd0dd398f5d64ed158dd5a63ebfb39b3ff0326770d1e6794562116c93',"hex"),
            iv=new Buffer('075410787d892e856500398c2b0c1936',"hex"),
            message= new Buffer("Hello World hola mundo mundo mundo","utf8");


        it("Will test AES encryption",function(){
            var cipherN=nodeCrypto.createCipheriv("aes-256-cbc",key,iv),
                cipherB=browserCrypto.createCipheriv("aes-256-cbc",key,iv);

            //cipherN.setAutoPadding(false);
            //cipherB.setAutoPadding(false);

            expect(cipherN.update(message).toString('base64')).equals(cipherB.update(message).toString('base64'));
            expect(cipherN.final("hex")).equals(cipherB.final("hex"));

        });

        it("Will test AES decryption node(AES) -> browser(AES)",function(){
            var cipher=nodeCrypto.createCipheriv("aes-256-cbc",key,iv),
                decipher=browserCrypto.createDecipheriv("aes-256-cbc",key,iv),
                e, d,  r;

            e=cipher.update(message);

            d=new Buffer(decipher.update(e,"buffer","binary"),"binary");

            e=cipher.final();

            r=Buffer.concat([d,decipher.update(e),decipher.final()]);

            expect(r.toString('utf8')).equals(message.toString('utf8'));
        });

        it("Will test AES decryption browser(AES) -> node(AES)",function(){
            var cipher=browserCrypto.createCipheriv("aes-256-cbc",key,iv),
                decipher=nodeCrypto.createDecipheriv("aes-256-cbc",key,iv),
                e, d,  r;

            e=cipher.update(message);

            d=new Buffer(decipher.update(e,"buffer","binary"),"binary");

            e=cipher.final();

            r=Buffer.concat([d,decipher.update(e),decipher.final()]);

            expect(r.toString('utf8')).equals(message.toString('utf8'));
        });

    });

});

