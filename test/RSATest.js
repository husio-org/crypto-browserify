/**
 * User: rafael
 * Date: 8/7/13
 * Time: 5:23 PM
 */


var crypto=require("crypto"),
    fs=require("fs"),
    path=require("path"),
    RSA=require("../lib/cryptico/RSA"),
    expect=require("chai").expect;


describe("Will test crypto RSA ",function(){

    /**
     * The following commands where useful for creating this test data:
     *
     * openssl genrsa -out privkey.pem 2048
     * openssl rsa -pubin -inform PEM -text -noout < pubkey.pem
     */

    var public=fs.readFileSync(path.join(__dirname,"pubkey.pem")),
        pub_modulus="00af8e8349cc231cb569015af80593ddf8453021e06dcd459d51eda39ae1776549081596ebe55cc658ccf074474b9627af3cc6b938fa595c8d8766fe8fb55332339e75815758ee42c74b2d1bd460c22ea3fb526624aafb9b6690ad278fe470af78da6db6ca7b6f60507f92f9c997b2a149a87e30dd6361898b5455ffebbf15813d44099f6ad75f6904b81ce168024d781e2c2efba56c8066313810dd6a5b2af28a7d29addada9534966a05c64aae72eeb7aef4162a74d2a91a38913b5c359f199488f58f18b47f2d096d2ac78f743ea3accd65137a3b5e90a06e7f487fd9f1ad0875c2ba0c1079b36492de3924161c2e4740d379a0060190816bf633d97cceef1f",
        pub_exponent="10001",
        pri_exponent="4d09b5d5318e8aef94a7b29aba1fdc3d316760c65288ccaeafa01fb63c909f52c00871550d2e7c1fc5b712dfa26cbef7682d3064af7f7d5ce1f9316630c4d477d066721eb978bcb725e7229a3ce7997dfe30778049c3e5bac96c22bb431cabf3d5ae65934f3d5dbf956c12cf0311b133588c1fb757001b5297ecb1446b72ed6611e76649a288ef4b92d8acf9d20d476bc6ef233434eb0556047d6b4118b312f7db3736dac01499c816abb39f411f7b1cf987a4624fefd944e5a69ef49d2fc06abcc907c79e510d301d6185d8898bb1b459f91770692b01b32f9b849e93e40883dccef2a9c81b55f9a7d5c2a202e171f4e0c4c994e852118c4e6c07509a8e3861",
        private=fs.readFileSync(path.join(__dirname,"privkey.pem")),
        message="HELLO WORLD";

    it("will test to sign with crypto",function(){
        var signer=crypto.createSign("RSA-SHA1"),
            verifier=crypto.createVerify("RSA-SHA1"),
            s,v;

        signer.update(message);
        s=signer.sign(private);

        verifier.update(message);
        v=verifier.verify(public,s);
        expect(v).to.be.true;
    });


    it ("will test Tom Wu's RSA", function(){
        var rsa=new RSA(),
            e,d;

        rsa.generate(512,"03");
        e=rsa.encrypt(message);
        d=rsa.decrypt(e);

        expect(d).to.equal(message);
    });



    it("Will sign with node and check with tw's",function(){
        var signer=crypto.createSign("RSA-SHA1"),
            rsa=new RSA(),
            s,v;

        signer.update(message);
        s=signer.sign(private);

        rsa.setPublic(pub_modulus,pub_exponent);
        v=rsa.verifyHexSignatureForMessage(s.toString("hex"),message);
        expect(v).to.be.true;

        v=rsa.verifyHexSignatureForMessage(s.toString("hex"),"HOLA MUNDO");
        expect(v).to.be.false;
    });

    it("will try to sign with tw/cryptico and verify with node",function(){
        var verifier=crypto.createVerify("RSA-SHA1"),
            rsa=new RSA(),
            s,v;
            rsa=new RSA();
            rsa.setPrivate(pub_modulus,pub_exponent,pri_exponent);
            s=rsa.signStringWithSHA1(message);

            verifier.update(message,"utf8");
            v=verifier.verify(public,s,"hex");
            expect(v).to.be.true;
    });

});