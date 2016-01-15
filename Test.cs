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
using System.Security.Cryptography;

namespace FiatShamirIdentification
{
    public class Test
    {
        /// <summary>
        /// Simple test.
        /// </summary>
        /// <param name="wordSize">number of byte of the key</param>
        /// <param name="testPrecision">percision of the test, error = 1/2^precision</param>
        /// <returns>result of the test</returns>
        public static bool DefaultTest(uint wordSize=128, uint testPrecision=20)
        {
            if (wordSize < 8 || testPrecision < 1)
            {
                System.Console.WriteLine("ZKFS test invalid input\n");
                return false;
            }

            uint iteration = 0;
            bool choice;
            BigInteger number;
            bool result = true;
            KeyGen kg = new KeyGen();
            var gen = new RNGCryptoServiceProvider();
            kg.KeyCreate(gen, wordSize);
            Verifier verifier = new Verifier(kg.PublicKey, kg.Module);
            Proover proover = new Proover(kg.PrivateKey, kg.Module, gen);
            
            //test with key
            while (iteration < testPrecision && result)
            {
                number = proover.Step1();
                choice = verifier.Step1(ref number);
                number = proover.Step2(choice);
                verifier.Step2(number);
                result = verifier.CheckState();
                iteration++;
            }

            if (!result) //if not verified, fail
            {
                System.Console.WriteLine("ZKFS test ERROR\n");
                gen.Dispose();
                return false;
            }

            
            //test without key
            BigInteger falseKey = kg.PrivateKey - (kg.PrivateKey/3); 
            proover = new Proover(falseKey, kg.Module, gen);
            iteration = 0;
            while (iteration < testPrecision && result)
            {
                number = proover.Step1();
                choice = verifier.Step1(ref number);
                number = proover.Step2(choice);
                verifier.Step2(number);
                result = verifier.CheckState();
                iteration++;
            }

            if (result) //if verified, fail
            {
                System.Console.WriteLine("ZKFS test ERROR\n");
                gen.Dispose();
                return false;
            }
            
            System.Console.WriteLine("ZKFS test OK\n");
            gen.Dispose();
            return true;
        }


        /// <summary>
        /// Customizable version with full KeyGen parameters.
        /// </summary>
        /// <param name="wordSize">number of byte of the key</param>
        /// <param name="testPrecision">percision of the test, error = 1/2^precision</param>
        /// <param name="primePrecision">percision of primality test, error = 1/2^(2*precision)</param>
        /// <param name="generator">random number generator, it is not disposed</param>
        /// <param name="primeDistance">distance between 2 prime, for security</param>
        /// <param name="threads">number of threads to use</param>
        /// <returns>result of the test</returns>
        public static bool CustomTest(uint wordSize, uint testPrecision, uint primePrecision, RandomNumberGenerator generator, ulong primeDistance=uint.MaxValue, int threads = 1)
        {
            if (wordSize < 8 || testPrecision < 1)
            {
                System.Console.WriteLine("ZKFS test invalid input\n");
                return false;
            }

            uint iteration = 0;
            bool choice;
            BigInteger number;
            bool result = true;
            KeyGen kg = new KeyGen();
            kg.ParallelKeyCreate(generator, wordSize, primeDistance, primePrecision, threads);
            Verifier v = new Verifier(kg.PublicKey, kg.Module);
            Proover p = new Proover(kg.PrivateKey, kg.Module, generator);

            //test with key
            while (iteration < testPrecision && result)
            {
                number = p.Step1();
                choice = v.Step1(ref number);
                number = p.Step2(choice);
                v.Step2(number);
                result = v.CheckState();
                iteration++;
            }

            if (!result) //if not verified, fail
            {
                System.Console.WriteLine("ZKFS test ERROR\n");
                return false;
            }

            //test without key
            BigInteger falseKey = kg.PrivateKey - (kg.PrivateKey / 3);
            p = new Proover(falseKey, kg.Module, generator);
            iteration = 0;
            while (iteration < testPrecision && result)
            {
                number = p.Step1();
                choice = v.Step1(ref number);
                number = p.Step2(choice);
                v.Step2(number);
                result = v.CheckState();
                iteration++;
            }

            if (result) //if verified, fail
            {
                System.Console.WriteLine("ZKFS test ERROR\n");
                return false;
            }

            System.Console.WriteLine("ZKFS test OK\n");
            return true;
        }
    }
}
