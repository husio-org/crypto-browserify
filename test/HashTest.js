/**
 *
 * Some tests to check the library is working, the following websites helped in the process:
 *
 * Online Calculator for several hashes
 * http://www.fileformat.info/tool/hash.htm
 *
 * User: rafael
 * Date: 8/7/13
 * Time: 3:49 PM
 */

var SHA256=require("../lib/cryptico/webkit/SHA256"),
    SHA1=require("../lib/cryptico/webkit/SHA1"),
    MD5=require("../lib/cryptico/webkit/MD5"),
    expect=require("chai").expect;


describe("It will test hasing algorithms",function(){
    var clearText="Hello World!";

    it("Will test SHA-256",function(){
        var result=SHA256(clearText);
        expect(result).equal("7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069");
    });

    it("Will test the SHA-1", function(){
        var result=SHA1(clearText);
        expect(result).equal("2ef7bde608ce5404e97d5f042f95f89f1c232871");
    });
    it("Will test the MD5", function(){
        var result=MD5(clearText);
        expect(result).equal("ed076287532e86365e841e92bfc50d8c");
    });
})