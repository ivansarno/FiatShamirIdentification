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
//version V.2.0

using System;
using System.Numerics;


namespace FiatShamirIdentification
{
    public sealed class PublicKey
    {
        private readonly BigInteger _key;
        private readonly BigInteger _modulus;

        internal PublicKey(BigInteger key, BigInteger modulus)
        {
            _key = key;
            _modulus = modulus;
        }

        // internal BigInteger Key => _key;

        // internal BigInteger Modulus => _modulus;


        /// <summary>
        /// Return the Verifier associated at this PublicKey to an identification session.
        /// </summary>
        /// <returns>Verifier associated at this PublicKey</returns>
        public Verifier GetVerifier()
        {
            return new Verifier(_key, _modulus);
        }


        /// <summary>
        /// Return a binary representation of the PublicKey.
        /// User can use this to restore the key with ResumeKey method.
        /// </summary>
        /// <returns>bytes array represented the PublicKey</returns>
        public byte[] SaveKey()
        {
            var key = _key.ToByteArray();
            var modulus = _modulus.ToByteArray();
            var length = BitConverter.GetBytes(key.Length);
            return length.Concat(key, modulus);
        }


        /// <summary>
        /// This method restore a PublicKey exported with SaveKey method
        /// </summary>
        /// <param name="rawKey">bytes array represented a PublicKey</param>
        /// <exception cref="ArgumentException">the bytes array not represents a PublicKey</exception>
        /// <returns>the PublicKey resumed from the byte array</returns>
        public static PublicKey ResumeKey(byte[] rawKey)
        {
            try
            {
                var length = BitConverter.ToInt32(rawKey, 0);
                return new PublicKey(new BigInteger(rawKey.Slice(4, 4 + length)), new BigInteger(rawKey.Slice(4 + length)));
            }
            catch (ArgumentException)
            {

                throw new ArgumentException("rawKey bytes array not represents a PublicKey");
            }
        }

        internal static bool EqTest(PublicKey first, PublicKey second)
        {
            return first._key == second._key && first._modulus == second._modulus;
        }
    }
}
