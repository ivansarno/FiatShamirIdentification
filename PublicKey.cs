/*
    FiatShamirIdentification

    Copyright 2015 Ivan Sarno

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
//version V.2.0 alpha

﻿using System.Numerics;


namespace FiatShamirIdentification
{
    public class PublicKey
    {
        private readonly BigInteger _key;
        private readonly BigInteger _modulus;

        internal PublicKey(BigInteger key, BigInteger modulus)
        {
            _key = key;
            _modulus = modulus;
        }

        public Verifier GetVerifier()
        {
            return new Verifier(_key, _modulus);
        }
        
        public byte[] Export()
        {
            var key = _key.ToByteArray();
            var modulus = _modulus.ToByteArray();
            var length = BitConverter.GetBytes(Convert.ToUInt16(key.length);
            var result = new byte[2 + key.length + modulus.length]
            length.CopyTo(result, 0);
            key.CopyTo(result, 2);
            modulus.CopyTo(result, 2+key.length)
            return result;
        }
        
        public static PublicKey Import(byte[] rawKey)
        {
            var length = BitConverter.ToUInt16(rawKey, 0);
            var key = new byte[length];
            Array.Copy(rawKey, 2, key, 0, length);
            var modulus = new byte[rawKey.length - 2 - length];
            Array.Copy(rawKey, 2, modulus, 2+length, modulus.length);
            return new PublicKey(new BigInteger(key), new BigInteger());
        }
    }
}
