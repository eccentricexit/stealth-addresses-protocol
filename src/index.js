import BN from 'bn.js';
import {eddsa as EdDSA} from 'elliptic';
import crypto from 'crypto';
import keccakHash from 'keccak';
import utils from 'ethereumjs-util'

const ec = new EdDSA('ed25519');
const G = [ec.g.x,ec.g.y];

//Bob
const aKeys = ec.keyFromSecret("spendKey");
const a = aKeys.priv();
const A = aKeys.pub();
const bKeys = ec.keyFromSecret("viewKey");
const b = bKeys.priv();
const B = bKeys.pub();

//Bob gives A and B to Alice

//Alice
const rKeys = ec.keyFromSecret("rKeys");
const r = rKeys.priv();
const R = rKeys.pub();

//P = H(r*A)*G+B      //cryptonote whitepaper
//Alice signs a transaction sending S tokens to
//P address. She also includes R in the
//transaction.

//whitepaper implementation (P = H(r*A)*G+B )
let P = A.mul(r);
P = H(P.toString());
P = ec.g.mul(new BN(P));
P = P.add(B);

console.log(P);

//Bob checks every transaction by calculating
//P' with his private a key. If P' == P, he is
//the recipient of that transaction.
//P' = H(aR)G+bG     //cryptonote whitepaper

let _P = R.mul(a);
_P = H(_P.toString());
_P = ec.g.mul(new BN(_P));
_P = _P.add(ec.g.mul(b));

console.log(_P);
//Bob sees that P == _P so he knows he is the recipient
//of that transaction. He can calculate _P private key
//using his private keys a and b
//p = H(aR)+b

let _p = R.mul(a).toString();
_p = new BN(H(_p).toString()).add(b);

let pKey = ec.keyFromSecret(_p);

//testing private key...
const msg = "there is no spoon.";
const msgHash = H(msg);
const signature = pKey.sign(msgHash).toHex();
console.log(pKey.verify(msgHash, signature));

function H(input){
  return keccakHash('keccak256').update(input).digest('hex');
}
