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
//version V.2.0 beta

using System;
using System.Numerics;


namespace FiatShamirIdentification
{
    [Serializable]
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
        /// User can use this to restore the key with Import method.
        /// </summary>
        /// <returns>bytes array represented the PublicKey</returns>
        public byte[] Export()
        {
            var key = _key.ToByteArray();
            var modulus = _modulus.ToByteArray();
            var length = BitConverter.GetBytes(Convert.ToUInt16(key.Length));
            var result = new byte[2 + key.Length + modulus.Length];
            length.CopyTo(result, 0);
            key.CopyTo(result, 2);
            modulus.CopyTo(result, 2 + key.Length);
            return result;
        }


        /// <summary>
        /// Convert a bytes array represented a PublicKey to a PublicKey.
        /// This method restore a PublicKey exported with ToByteArray method
        /// </summary>
        /// <param name="rawKey">bytes array represented a PublicKey</param>
        /// <exception cref="ArgumentException">the bytes array not represents a PublicKey</exception>
        public PublicKey(byte[] rawKey)
        {
            try
            {
                var length = BitConverter.ToUInt16(rawKey, 0);
                var key = new byte[length];
                Array.Copy(rawKey, 2, key, 0, length);
                var modulus = new byte[rawKey.Length - 2 - length];
                Array.Copy(rawKey, 2, modulus, 2 + length, modulus.Length);
                _key = new BigInteger(key);
                _modulus = new BigInteger(modulus);
            }
            catch (ArgumentException)
            {

                throw new ArgumentException("rawKey bytes array not represents a PublicKey");
            }
        }
    }
}
