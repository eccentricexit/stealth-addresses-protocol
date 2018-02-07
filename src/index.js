import BN from 'bn.js';
import {eddsa as EdDSA} from 'elliptic';
import crypto from 'crypto';
import keccakHash from 'keccak';
import utils from 'ethereumjs-util'

const ec = new EdDSA('ed25519');
const G = [ec.g.x,ec.g.y];

//Candidate X keys publishes A and B
const aKeys = ec.keyFromSecret("spendKey");
const a = aKeys.priv();
const A = aKeys.pub();
const bKeys = ec.keyFromSecret("viewKey");
const b = bKeys.priv();
const B = bKeys.pub();

//Voter computes a random key
const rKeys = ec.keyFromSecret(crypto.randomBytes(64).toString('hex'));
const r = rKeys.priv();
const R = rKeys.pub();

//Voter computes P with Candidate X's public keys
//P=H(rA)G+B    per CN paper
//P=H(rA||n)G+B per cns006, where || is concatenation and n is the index of the
//tx encoded as varint.
const P = ec.g.mul(new BN(H(A.mul(r).encode('hex')))).add(B).encode('hex');
//and signs a transaction to P, publishing R.

//Candidate X checks every transaction
//_P=H(aR)G+B // whitepaper
//P=H(aR||n)G+B per cns006, where || is concatenation and n is the index of the
//tx encoded as varint.
const _P = ec.g.mul(new BN(H(R.mul(a).encode('hex')))).add(B).encode('hex');
//Once he finds _P == P he knows he is the recipient of that vote
console.log(P===_P);

//He can calculate the corresponding private key _p using his private keys
//_p = H(aR) + b
const _p = new BN(H(R.mul(a).encode('hex'))).add(b);
console.log(ec.g.mul(_p).encode('hex')===_P);


function H(input){
  return keccakHash('keccak256').update(input).digest('hex');
}
