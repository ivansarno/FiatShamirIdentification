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
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace FiatShamirIdentification
{
    [Serializable]
    public sealed class PrivateKey : IEquatable<PrivateKey>
    {
        internal PrivateKey(BigInteger key, BigInteger modulus, uint size)
        {
            Key = key;
            Modulus = modulus;
            Size = size;
        }

        internal BigInteger Key { get; }

        internal uint Size { get; }

        internal BigInteger Modulus { get; }

        public bool Equals(PrivateKey other)
        {
            return other != null &&
                   Key.Equals(other.Key) &&
                   Modulus.Equals(other.Modulus) &&
                   Size == other.Size;
        }

        /// <summary>
        ///     Return the PublicKey associated at this PrivateKey to send to servers for the Identifications.
        /// </summary>
        /// <returns>PublicKey associated at this PrivateKey</returns>
        public PublicKey GetPublicKey()
        {
            return new PublicKey(Key * Key % Modulus, Modulus, Size);
        }

        /// <summary>
        ///     Return the Proover associated at this PrivateKey to an identification session.
        /// </summary>
        /// <returns>Proover associated at this PrivateKey</returns>
        public Proover GetProover(RandomNumberGenerator gen)
        {
            return new Proover(this, gen);
        }


        /// <summary>
        ///     Create a new PrivateKey
        /// </summary>
        /// <param name="gen">secure random number generation</param>
        /// <param name="wordSize">length in bytes of the key's modulus</param>
        /// <param name="threads">number of threads to use for the generation</param>
        /// <param name="precision">precision of primality test, error=1/2^(2*precision)</param>
        /// <returns>new private key</returns>
        public static PrivateKey NewKey(RandomNumberGenerator gen, uint wordSize = 128, int threads = 2,
            uint precision = 60)
        {
            if (wordSize < 128 || gen == null)
                throw new ArgumentException("wordSize < 128 or gen == null");
            
            precision = Math.Max(precision, 60); 
            BigInteger modulus;
            if (threads < 2)
                modulus = SeqGenMod(new GeneratorWrap(gen, wordSize / 2), wordSize, precision);
            else modulus = ParGenMod(new GeneratorWrap(gen, wordSize / 2), wordSize, threads, precision);

            var key = GenKey(new GeneratorWrap(gen, wordSize), modulus);

            return new PrivateKey(key, modulus, wordSize);
        }

        /// <summary>
        ///     Create a new PrivateKey from a secret number.
        /// </summary>
        /// <param name="secretNumber">user's secret number to use to in key creation</param>
        /// <param name="gen">secure random number generation</param>
        /// <param name="wordSize">length in bytes of the key's modulus</param>
        /// <param name="threads">number of threads to use for the generation</param>
        /// <param name="precision">precision of primality test, error=1/2^(2*precision)</param>
        /// <returns>new private key</returns>
        public static PrivateKey NewKey(BigInteger secretNumber, RandomNumberGenerator gen, uint wordSize = 128,
            int threads = 2, uint precision = 60)
        {
            if (wordSize < 128 || gen == null)
                throw new ArgumentException("wordSize < 128 or gen == null");

            precision = Math.Max(precision, 60); 
            BigInteger modulus;
            if (threads < 2)
                modulus = SeqGenMod(new GeneratorWrap(gen, wordSize / 2), wordSize, precision);
            else modulus = ParGenMod(new GeneratorWrap(gen, wordSize / 2), wordSize, threads, precision);
            
            if (!KeyCheck(secretNumber, modulus))
                throw new ArgumentException("secret number < UInt64.MaxValue");
            
            return new PrivateKey(secretNumber, modulus, wordSize);
        }

        //Generates the modulus using one thread
        private static BigInteger SeqGenMod(GeneratorWrap gen, uint wordSize, uint precision)
        {
            IPrime generator = new SequentialPrime(gen.GetInt(), precision, wordSize);
            var firstPrime = gen.GetBig();
            var secondPrime = gen.GetBig();

            while (!SecurityCheck(firstPrime, secondPrime)) secondPrime = gen.GetBig();

            firstPrime = generator.NextPrime(firstPrime);
            secondPrime = generator.NextPrime(secondPrime);

            return firstPrime * secondPrime;
        }

        //Generates the modulus using more thread
        private static BigInteger ParGenMod(GeneratorWrap gen, uint wordSize, int threads, uint precision)
        {
            IPrime mainGenerator, workerGenerator;
            //threads distribution for primes creation
            if (threads < 4)
            {
                mainGenerator = new SequentialPrime(gen.GetInt(), precision, wordSize);
                workerGenerator = new SequentialPrime(gen.GetInt(), precision, wordSize);
            }
            else
            {
                mainGenerator = new ParallelPrime(gen.GetInt(), precision, wordSize, threads - threads / 2);
                workerGenerator = new ParallelPrime(gen.GetInt(), precision, wordSize, threads / 2);
            }

            //primes creation
            var firstPrime = gen.GetBig();
            var secondPrime = gen.GetBig();
            while (!SecurityCheck(firstPrime, secondPrime)) secondPrime = gen.GetBig();

            var worker = new Task<BigInteger>(() => workerGenerator.NextPrime(firstPrime));
            worker.Start();
            secondPrime = mainGenerator.NextPrime(secondPrime);

            worker.Wait();
            firstPrime = worker.Result;
            worker.Dispose();

            return firstPrime * secondPrime;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static BigInteger GenKey(GeneratorWrap gen, BigInteger modulus)
        {
            var key = gen.GetBig() % modulus;
            while (!KeyCheck(key, modulus))
            {
                key = gen.GetBig() % modulus;
            }
            return key;
        }

        //checks whether the numbers found to comply with safety conditions
        private static bool SecurityCheck(BigInteger first, BigInteger second)
        {
            var distance = BigInteger.Pow(first - second, 4);
            var modulus = first * second;
            if (modulus >= distance)
                return false;

            distance = BigInteger.Abs(modulus - BigInteger.Pow(first, 2));
            if (distance < uint.MaxValue)
                return false;

            distance = BigInteger.Abs(modulus - BigInteger.Pow(second, 2));
            return distance >= uint.MaxValue;
        }
        
        //checks the key to comply with safety conditions
        private static bool KeyCheck(BigInteger key, BigInteger modulus)
        {
            var square = key * key;
            var squareMod = square % modulus;
            return key > 3 && BigInteger.GreatestCommonDivisor(squareMod, modulus) == 1 &&
                BigInteger.GreatestCommonDivisor(key, modulus) == 1 && square != squareMod;
        }

        /// <summary>
        ///     Return a binary representation of the PrivateKey.
        ///     User can use this to restore the key with ResumeKey method.
        /// </summary>
        /// <returns>bytes array represented the PrivateKey</returns>
        public byte[] SaveKey()
        {
            var key = Key.ToByteArray();
            var modulus = Modulus.ToByteArray();
            var length = BitConverter.GetBytes(key.Length).Concat(BitConverter.GetBytes(Size));
            return length.Concat(key, modulus);
        }


        /// <summary>
        ///     Convert a bytes array represented a PrivateKey to a PrivateKey.
        ///     This method restore a PrivateKey exported with SaveKey method
        /// </summary>
        /// <param name="rawKey">bytes array represented a PrivateKey</param>
        /// <exception cref="ArgumentException">the bytes array not represents a PrivateKey</exception>
        /// <returns>the PrivateKey resumed from the byte array</returns>
        public static PrivateKey ResumeKey(byte[] rawKey)
        {
            try
            {
                var length = BitConverter.ToInt32(rawKey, 0);
                var wordSize = BitConverter.ToUInt32(rawKey, 4);
                return new PrivateKey(new BigInteger(rawKey.Slice(8, 8 + length)),
                    new BigInteger(rawKey.Slice(8 + length)), wordSize);
            }
            catch (ArgumentException)
            {
                throw new ArgumentException("rawKey bytes array not represents a PrivateKey");
            }
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as PrivateKey);
        }

        public static bool operator ==(PrivateKey key1, PrivateKey key2)
        {
            return EqualityComparer<PrivateKey>.Default.Equals(key1, key2);
        }

        public static bool operator !=(PrivateKey key1, PrivateKey key2)
        {
            return !(key1 == key2);
        }
    }
}