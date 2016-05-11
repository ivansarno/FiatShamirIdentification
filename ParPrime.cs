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
//version V.2.1

using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Threading;


namespace FiatShamirIdentification
{
    /// <summary>
    /// Utility for prime numbers.
    /// parallel version.
    /// for internal use.
    /// </summary>
    internal class ParPrime: IPrime
    {
        private readonly uint _precision; //precision of Miller-Rabin primality test
        private readonly Random _generator;
        private bool _continue;
        private readonly uint _size;
        private BigInteger _current;
        private readonly AutoResetEvent _wait;
        private readonly int _threads;
        private int _pass;

        /// <summary>
        ///  </summary>
        /// <param name="seed">seed of random number generator</param>
        /// <param name="precision">precision of Miller-Rabin test, error = 1/2^(2*precision)</param>
        /// <param name="wordSize">length in bytes of number generated</param>
        /// <param name="threads">number of threads to use</param>
        public ParPrime(int seed, uint precision = 20, uint wordSize = 128, int threads = 2)
        {
            if (precision < 5 || wordSize < 8 || threads < 2)
                throw new ArgumentException("precision < 5 or wordSize < 8 or threads < 2");
            _precision = precision;
            _generator = new Random(seed);
            _size = wordSize;
            _wait = new AutoResetEvent(false);
            _threads = threads;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private bool MRpredicate1(ref BigInteger y, ref BigInteger z, ref BigInteger number)
        {
            return _continue && BigInteger.ModPow(y, z, number) == 1;
        }

        private bool MRpredicate2(ref BigInteger y, ref BigInteger number, ref BigInteger z, uint w)
        {
            if (!_continue)
                return false;
            uint i = 0;
            BigInteger pow2 = 1;
            bool cond = (BigInteger.ModPow(y, z, number) == number - 1);

            while (!cond && i < w)
            {
                i++;
                pow2 <<= 1;
                cond = (BigInteger.ModPow(y, pow2 * z, number) == number - 1);
            }

            return i != w;
        }

        private bool MRtest(ref BigInteger number, byte[] buffer, Random generator)
        {
            uint w;
            BigInteger z;


            MRscomposition(ref number, out w, out z);

            bool ris = true;
            uint i = 0;

            while (_continue && ris && i < _precision)
            {
                //extract a random number
                generator.NextBytes(buffer);
                buffer[buffer.Length - 1] &= 127; //forces a positive number
                var y = new BigInteger(buffer);
                ////
                y = y % number;
                while (y < 2) //avoids extraction of 0 and 1
                {
                    y += generator.Next();
                    y = y % number;
                }
                //test
                ris = (BigInteger.GreatestCommonDivisor(y, number) == 1) &&
                      (MRpredicate1(ref y, ref z, ref number) || MRpredicate2(ref y, ref number, ref z, w));
                i++;
            }
            return ris;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void MRscomposition(ref BigInteger number, out uint w, out BigInteger z)
        {
            z = number - 1;
            w = 0;
            while ((z & 1) == 0)
            {
                w++;
                z >>= 1;
            }
        }


        /// <summary>
        /// Primality test.
        /// </summary>
        /// <param name="number">number to test</param>
        /// <returns>true if number is prime</returns>
        public bool IsPrime(ref BigInteger number)
        {
            if (number == 2)
                return true;
            if ((number & 1) == 0)
                return false;

            return number > 2 && MRtest(ref number, new byte[_size], _generator);
        }

        /// <summary>
        /// Return the first prime number following the argument.
        /// </summary>
        /// <param name="number">current number</param>
        /// <returns>next prime number</returns>
        public BigInteger NextPrime(BigInteger number)
        {
            if (number < 2)
                return 2;
            if ((number & 1) == 0)
                number++;
            _current = number;
            _continue = true;
            _pass = 1;

            for (int i = 0; i < _threads; i++)
            {
                ThreadPool.QueueUserWorkItem(Routine, i);
            }

            _wait.WaitOne();
            return _current;
        }

        /// <summary>
        /// Version to use with threads.
        /// Return the first prime number following the argument.
        /// </summary>
        /// <param name="current">_current number</param>
        /// <returns>next prime number</returns>
        public BigInteger NextPrime(object current)
        {
            var number = (BigInteger) current;
            if (number < 2)
                return 2;
            if ((number & 1) == 0)
                number++;
            _current = number;
            _continue = true;
            _pass = 1;

            for (int i = 0; i < _threads; i++)
            {
                ThreadPool.QueueUserWorkItem(Routine, i);
            }

            _wait.WaitOne();
            return _current;
        }

        //thread's routine
        private void Routine(object threadId)
        {
            var id = (int) threadId;
            var increment = _threads * 2;
            var number = _current + 2*id;
            var buffer = new byte[_size];
            var generator = new Random(_generator.Next()); //local generator

            while (_continue && !MRtest(ref number, buffer, generator))
                number += increment;

            var pass = Interlocked.CompareExchange(ref _pass, 0, 1);
            if (pass == 0) return;
            _continue = false;
            _current = number;
            _wait.Set();
        }
    }
}
