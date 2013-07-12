/**
 * User: rafael
 * Date: 8/7/13
 * Time: 4:45 PM
 */


var SecureMath=require("../lib/Random").SecureMath,
    SecureRandom=require("../lib/Random").SecureRandom,
    expect=require("chai").expect;


describe("Will test the Random module",function(){
    it("Will test SecureMath has a seedRandom method",function(){
        expect(SecureMath.seedrandom).to.be.a("function");
    });

    it("Will test that Math doesn't have the seedrandom method",function(){
        expect(Math.seedrandom).to.be.an("undefined");
    });

    it("Will test to initialize seedrandom with the sample seed",function(){
        var r1,r2;
        SecureMath.seedrandom("hello");
        r1=SecureMath.random();
        r2=SecureMath.random();
        expect(r1).equal(0.5463663768140734);
        expect(r2).equal(0.4397379377059223);
    });

    it("Will test to get some SecureRandom.nextBytes",function(){
        var r,r=new Array(32),sr=new SecureRandom();
        sr.nextBytes(r);
        for(i=0;i<32;i++) expect(r[i]).within(0,255);
    });


});