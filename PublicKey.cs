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
//version V.2.2

using System;
using System.Collections.Generic;
using System.Numerics;

namespace FiatShamirIdentification
{
    [Serializable]
    public sealed class PublicKey : IEquatable<PublicKey>
    {
        internal PublicKey(BigInteger key, BigInteger modulus, uint size)
        {
            Key = key;
            Modulus = modulus;
            Size = size;
        }

        internal BigInteger Key { get; }

        internal BigInteger Modulus { get; }

        private uint Size { get; }

        public bool Equals(PublicKey other)
        {
            return other != null &&
                   Key.Equals(other.Key) &&
                   Modulus.Equals(other.Modulus) &&
                   Size.Equals(other.Size);
        }


        /// <summary>
        ///     Return the Verifier associated at this PublicKey to an identification session.
        /// </summary>
        /// <returns>Verifier associated at this PublicKey</returns>
        public Verifier GetVerifier()
        {
            return new Verifier(this);
        }

        /// <summary>
        ///     Return the Verifier associated at this PublicKey to an identification session.
        /// </summary>
        /// <param name="secretNumber">user's secret number</param>
        /// <returns>Verifier associated at this PublicKey</returns>
        public PrivateKey ResumePrivateKey(BigInteger secretNumber)
        {
            if (secretNumber * secretNumber % Modulus != Key)
                throw new ArgumentException("secretNumber not valid");
            return new PrivateKey(secretNumber, Modulus, Size);
        }


        /// <summary>
        ///     Return a binary representation of the PublicKey.
        ///     User can use this to restore the key with ResumeKey method.
        /// </summary>
        /// <returns>bytes array represented the PublicKey</returns>
        public byte[] SaveKey()
        {
            var key = Key.ToByteArray();
            var modulus = Modulus.ToByteArray();
            var length = BitConverter.GetBytes(key.Length).Concat(BitConverter.GetBytes(Size));
            return length.Concat(key, modulus);
        }


        /// <summary>
        ///     This method restore a PublicKey exported with SaveKey method
        /// </summary>
        /// <param name="rawKey">bytes array represented a PublicKey</param>
        /// <exception cref="ArgumentException">the bytes array not represents a PublicKey</exception>
        /// <returns>the PublicKey resumed from the byte array</returns>
        public static PublicKey ResumeKey(byte[] rawKey)
        {
            try
            {
                var length = BitConverter.ToInt32(rawKey, 0);
                var wordSize = BitConverter.ToUInt32(rawKey, 4);
                return new PublicKey(new BigInteger(rawKey.Slice(8, 8 + length)),
                    new BigInteger(rawKey.Slice(8 + length)), wordSize);
            }
            catch (ArgumentException)
            {
                throw new ArgumentException("rawKey bytes array not represents a PublicKey");
            }
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as PublicKey);
        }

        public static bool operator ==(PublicKey key1, PublicKey key2)
        {
            return EqualityComparer<PublicKey>.Default.Equals(key1, key2);
        }

        public static bool operator !=(PublicKey key1, PublicKey key2)
        {
            return !(key1 == key2);
        }
    }
}