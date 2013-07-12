/**
 * Tests of the encapsulation of googlecode CryptoJS v3
 *
 * User: rafael
 * Date: 10/7/13
 * Time: 9:02 AM
 */

var expect=require("chai").expect;


describe("Will test the CryptoJS library encapsulation in NodeJS",function(){

    describe("Will test hash algorithms",function(){

        it("Will try an MD5 sample",function(){
            var CryptoJS=require("../lib/crypto-js/md5"),
                hash = CryptoJS.MD5("Message");
            console.log("CryptoJS MD5:" + hash);
        });

        it("Will try an SHA1 sample",function(){
            var CryptoJS=require("../lib/crypto-js/sha1"),
                hash = CryptoJS.SHA1("Message");
            console.log("CryptoJS SHA1:" + hash);
        });

        it("Will try an SHA256 sample",function(){
            var CryptoJS=require("../lib/crypto-js/sha256"),
                hash = CryptoJS.SHA256("Message");
            console.log("CryptoJS SHA256:" + hash);
        });

        it("Will try an SHA224 sample",function(){
            var CryptoJS=require("../lib/crypto-js/sha224"),
                hash = CryptoJS.SHA224("Message");
            console.log("CryptoJS SHA224:" + hash);
        });

        it("Will try an SHA512 sample",function(){
            var CryptoJS=require("../lib/crypto-js/sha512"),
                hash = CryptoJS.SHA512("Message");
            console.log("CryptoJS SHA512:" + hash);
        });

        it("Will try an SHA3 sample",function(){
            var CryptoJS=require("../lib/crypto-js/sha3"),
                hash = CryptoJS.SHA3("Message");
            console.log("CryptoJS SHA3:" + hash);
        });

        it("Will try an SHA384 sample",function(){
            var CryptoJS=require("../lib/crypto-js/sha384"),
                hash = CryptoJS.SHA384("Message");
            console.log("CryptoJS SHA384:" + hash);
        });


    });

    describe("Will test ciphers",function(){

        it("Will test AES",function(){
            var CryptoJS=require("../lib/crypto-js/aes"),
                encrypted = CryptoJS.AES.encrypt("Message", "Secret Passphrase"),
                decrypted = CryptoJS.AES.decrypt(encrypted, "Secret Passphrase");
                console.log("AES:" + encrypted);
                expect(decrypted.toString(CryptoJS.enc.Utf8)).equals("Message");
        });

    });

    describe("Will test hmac",function(){

        it("Will test MD5-HMAC",function(){
            var CryptoJS=require("../lib/crypto-js/hmac-md5"),
            hash = CryptoJS.HmacMD5("Message", "Secret Passphrase");
        });

    });


});



