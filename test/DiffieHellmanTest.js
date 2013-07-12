/**
 *
 * Testing DH functionality, the following webs were useful.
 * http://dkerr.home.mindspring.com/diffie_hellman_calc.html
 *
 * User: rafael
 * Date: 9/7/13
 * Time: 8:56 AM
 */


var DiffieHelman=require('../lib/rv/DiffieHellman'),
    BigInteger=require('../lib/BigInteger'),
    crypto=require('crypto'),
    cryptob=require('..'),
    expect=require('chai').expect;

describe("Will test DiffieHellman",function(){

    // this is a development test
    // requires to set a fixed key in the implementation. disabled.
    xit("will test DH ", function(){
        var dh= new DiffieHelman(new BigInteger("2"),new BigInteger("997"),8),
            mv=dh.computeMasterValue(new BigInteger("216"));
            console.log('DH Public Value:'+dh.getPublicValue().toString());
            console.log('DH Master Value:'+mv.toString());
    });

    xit("will test DH group 14 ", function(){
        var dh= new DiffieHelman("MODP",14),
            mv=dh.computeMasterValue(new BigInteger("216"));

        console.log('DH Public Value:'+dh.getPublicValue().toString());
        console.log('DH Master Value:'+mv.toString());

    });

    /**
     * Both implementation will use modp14 to generate each own public key,
     * after the interchange the, they should arrive to the same secret.
     * TODO:Random failures
     * possible related issue: sometimes returns MSB00s
     */
    it("will negotiate a DH modp14 session key between crypto and crypto-browserify",function(){
        var dh=crypto.getDiffieHellman('modp14'),
            dhb=cryptob.getDiffieHellman('modp14'),
            pk=dh.generateKeys(),
            pkb=dhb.generateKeys();

        //console.log("");
        //console.log("KEYA:"+dh.computeSecret(pkb).toString('hex'));
        //console.log("KEYB:"+dhb.computeSecret(pk).toString('hex'));
        expect(dh.computeSecret(pkb).toString('hex')).equals(dhb.computeSecret(pk).toString('hex'));
    });

    /**
     * Both implementation will use modp2 to generate each own public key,
     * after the interchange the, they should arrive to the same secret.
     * TODO:Fix required: complains about key length
     */
    xit("will negotiate a DH modp2 session key between crypto and crypto-browserify",function(){
        var dh=crypto.getDiffieHellman('modp2'),
            dhb=cryptob.getDiffieHellman('modp2'),
            pk=dh.generateKeys(),
            pkb=dhb.generateKeys();

        console.log("");
        console.log("PUBA:"+pk.toString('hex'));
        console.log("PUBB:"+dhb.toString('hex'));

        console.log("KEYA:"+dh.computeSecret(pkb).toString('hex'));
        console.log("KEYB:"+dhb.computeSecret(pk).toString('hex'));
        expect(dh.computeSecret(pkb).toString('hex')).equals(dhb.computeSecret(pk).toString('hex'));
    });



})