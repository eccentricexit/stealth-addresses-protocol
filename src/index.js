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

//Alice computes a random key
const rKeys = ec.keyFromSecret("rKeys");
const r = rKeys.priv();
const R = rKeys.pub();

//Alice computes P with bobs A and B:
//P=H(rA)G+B
//and signs a transaction to P, publishing R.

//Bob checks every transaction
//_P=H(aR)G+B
//Once he finds _P == P he knows he is the recipient of that tx
console.log(A.mul(r));
console.log(R.mul(a));

function H(input){
  return keccakHash('keccak256').update(input).digest('hex');
}
