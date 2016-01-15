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
//version V.1.0

using System.Numerics;

namespace FiatShamirIdentification
{
    /// <summary>
    /// Utility for prime numbers.
    /// for internal use, for now.
    /// </summary>
    internal interface IPrime
    {
        /// <summary>
        /// Version to use with threads.
        /// Return the first prime number following the argument.
        /// </summary>
        /// <param name="current">current number</param>
        /// <returns>next prime number</returns>
        BigInteger NextPrime(object current);

        /// <summary>
        /// Return the first prime number following the argument.
        /// </summary>
        /// <param name="number">current number</param>
        /// <returns>next prime number</returns>
        BigInteger NextPrime(BigInteger number);

        /// <summary>
        /// Primality test.
        /// </summary>
        /// <param name="number">number to test</param>
        /// <returns>true if number is prime</returns>
        bool IsPrime(ref BigInteger number);
    }
}