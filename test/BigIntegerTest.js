/**
 *
 * Some tests to check the library is working, the following websites helped in the process:
 *
 * An Online BIG INT calculator
 * http://www.javascripter.net/math/calculators/100digitbigintcalculator.htm
 *
 *
 * User: rafael
 * Date: 8/7/13
 * Time: 3:16 PM
 */

var BigInteger=require("../lib/BigInteger"),
    expect=require("chai").expect;


describe("Will test the BigInteger library",function(){
    it("Will create a couple of BigIntegers and dive them",function(){
        var biA=new BigInteger("1234567890123456789012345678901234567890"),
            biB=new BigInteger("212345678901234567890"),
            biR=biA.divide(biB);
        expect(biR.toString()).equals("5813953439088696562");
    });

    it("Will create an BI from hex", function(){
        var bi=new BigInteger("00FF",16);
        expect(bi.intValue()).equal(255);
    });

    it("Will create an BI from Buffer", function(){
        var b=new Buffer([0x08,0x00]),// this is 2048
            bi=new BigInteger(b), r;
        r=bi.add(new BigInteger("1"));
        expect(r.toString()).equal("2049");
    });

    it("Will convert a BI to Buffer", function(){
        var bi=new BigInteger("2048"),
            r=bi.add(new BigInteger("1")),
            b=r.toBuffer();
        expect(b.toString("hex")).equal("0801");
    })
});