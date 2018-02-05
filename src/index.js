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

// || is concatenation
//P = H(r*A || n)*G+B //cryptonote standard
//P = H(r*A)*G+B      //cryptonote whitepaper
//Alice signs a transaction sending S tokens to
//P address. She also includes R in the
//transaction.

//whitepaper naive implementation (P = H(r*A)*G+B )
let P = [A.x.mul(r),A.y.mul(r)];
P = '0x'+H(utils.toBuffer(P)).toString();
P = new BN(P);
P = [G[0].mul(P),G[1].mul(P)];
P[0] = B.x.add(P[0]);
P[1] = B.y.add(P[1]);


//Bob checks every transaction by calculating
//P' with his a key. If P' == P, he is
//the recipient of that transaction.
//P' = H(a*R||n)*G+B //cryptonote standards
//P' = H(aR)G+bG     //cryptonote whitepaper

let _P = [R.x.mul(a),R.y.mul(a)]; //a*R;
_P ='0x'+H(utils.toBuffer(_P)).toString(); //H(a*R)
_P = new BN(_P);
_P = [G[0].mul(_P),G[1].mul(_P)];
const bTimesG = [G[0].mul(b),G[1].mul(b)];
_P = [P[0].add(bTimesG[0]),P[1].add(bTimesG[1])];

console.log(P);
console.log(_P);


function H(input){
  return keccakHash('keccak256').update(input).digest('hex');
}
