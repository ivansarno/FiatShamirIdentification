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
using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading.Tasks;


namespace FiatShamirIdentification
{
    public class PrivateKey
    {
        private readonly BigInteger _key;
        private readonly BigInteger _modulus;

        internal PrivateKey(BigInteger key, BigInteger modulus)
        {
            _key = key;
            _modulus = modulus;
        }

        public PublicKey GetPublicKey()
        {
            return new PublicKey(_key*_key%_modulus, _modulus);
        }

        public Proover GetProover(RandomNumberGenerator gen)
        {
            return new Proover(_key, _modulus, gen);
        }

        public static PrivateKey GeneratesKey(RandomNumberGenerator gen, uint wordSize = 128, int threads = 2,
            uint precision = 20)
        {
            if (precision < 1 || wordSize < 8 || gen == null)
                throw new ArgumentException("precision < 1 or wordSize < 8 or gen == null");

            BigInteger modulus;
            if (threads < 2)
                modulus = SeqGenMod(new GeneratorWrap(gen, wordSize/2), wordSize, precision);
            else modulus = ParGenMod(new GeneratorWrap(gen, wordSize/2), wordSize, threads, precision);

            var key = GenKey(new GeneratorWrap(gen, wordSize), modulus);

            return new PrivateKey(key, modulus);
        }

        //Generates the modulus using one thread
        private static BigInteger SeqGenMod(GeneratorWrap gen, uint wordSize, uint precision)
        {
            IPrime generator = new SeqPrime(gen.GetInt(), precision, wordSize);
            var firstPrime = gen.GetBig();
            var secondPrime = gen.GetBig();

            while (!SecurityCheck(firstPrime, secondPrime))
            {
                secondPrime = gen.GetBig();
            }

            firstPrime = generator.NextPrime(firstPrime);
            secondPrime = generator.NextPrime(secondPrime);

            return firstPrime * secondPrime;
        }

        //Generates the modulus using more thread
        private static BigInteger ParGenMod(GeneratorWrap gen, uint wordSize, int threads, uint precision)
        {
            IPrime mainGenerator, workerGenerator;
            //threads' distribution for primes creation
            if (threads < 4)
            {
                mainGenerator = new SeqPrime(gen.GetInt(), precision, wordSize);
                workerGenerator = new SeqPrime(gen.GetInt(), precision, wordSize);
            }
            else
            {
                mainGenerator = new ParPrime(gen.GetInt(), precision, wordSize, threads - threads / 2);
                workerGenerator = new ParPrime(gen.GetInt(), precision, wordSize, threads / 2);
            }

            //primes creation
            var firstPrime = gen.GetBig();
            var secondPrime = gen.GetBig();
            while (!SecurityCheck(firstPrime, secondPrime))
            {
                secondPrime = gen.GetBig();
            }

            Task<BigInteger> worker = new Task<BigInteger>(workerGenerator.NextPrime, firstPrime);
            worker.Start();
            secondPrime = mainGenerator.NextPrime(secondPrime);

            worker.Wait();
            firstPrime = worker.Result;
            worker.Dispose();

            return firstPrime*secondPrime;
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static BigInteger GenKey(GeneratorWrap gen, BigInteger modulus)
        {
            var key = gen.GetBig()%modulus;
            while (key * key % modulus == 0)//avoid private key or public key == 0
            {
                key = gen.GetBig() % modulus;
            }
            return key;
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool SecurityCheck(BigInteger first, BigInteger second)
        {
            return true;
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
        
        public static PrivateKey Import(byte[] rawKey)
        {
            var length = BitConverter.ToUInt16(rawKey, 0);
            var key = new byte[length];
            Array.Copy(rawKey, 2, key, 0, length);
            var modulus = new byte[rawKey.length - 2 - length];
            Array.Copy(rawKey, 2, modulus, 2+length, modulus.length);
            return new PrivateKey(new BigInteger(key), new BigInteger());
        }
    }
}
