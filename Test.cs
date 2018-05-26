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
using System.Numerics;
using System.Security.Cryptography;

namespace FiatShamirIdentification
{
    public class Test
    {
        /// <summary>
        ///     Simple test.
        /// </summary>
        /// <param name="wordSize">number of byte of the key</param>
        /// <param name="testPrecision">percision of the test, error = 1/2^precision</param>
        /// <returns>result of the test</returns>
        public static bool DefaultTestVerbose(uint wordSize = 128, uint testPrecision = 20)
        {
            if (!DefaultTest(wordSize, testPrecision))
            {
                Console.WriteLine("FiatShamirIdentification test ERROR\n");
                return false;
            }

            Console.WriteLine("FiatShamirIdentification test OK\n");
            return true;
        }


        /// <summary>
        ///     Customizable version with full NewKey parameters.
        /// </summary>
        /// <param name="wordSize">number of byte of the key</param>
        /// <param name="testPrecision">percision of the test, error = 1/2^precision</param>
        /// <param name="primePrecision">percision of primality test, error = 1/2^(2*precision)</param>
        /// <param name="generator">random number generator, it is not disposed</param>
        /// <param name="threads">number of threads to use</param>
        /// <returns>result of the test</returns>
        public static bool CustomTestVerbose(uint wordSize, uint testPrecision, uint primePrecision,
            RandomNumberGenerator generator, int threads = 1)
        {
            if (!CustomTest(wordSize, testPrecision, primePrecision, generator, threads))
            {
                Console.WriteLine("FiatShamirIdentification test ERROR\n");
                return false;
            }

            Console.WriteLine("FiatShamirIdentification test OK\n");
            return true;
        }

        public static bool RepresentationTestVerbose()
        {
            if(!RepresentationTest())
            {
                Console.WriteLine("Representation Test OK.\n");
                return true;
            }
            Console.WriteLine("Representation Test ERROR.\n");
            return false;
        }

        /// <summary>
        ///     Simple test.
        /// </summary>
        /// <param name="wordSize">number of byte of the key</param>
        /// <param name="testPrecision">percision of the test, error = 1/2^precision</param>
        /// <returns>result of the test</returns>
        public static bool DefaultTest(uint wordSize = 128, uint testPrecision = 20)
        {
            var generator = new RNGCryptoServiceProvider();
            var result = CustomTest(wordSize, testPrecision, 20, generator);
            generator.Dispose();
            return result;
        }


        /// <summary>
        ///     Customizable version with full NewKey parameters.
        /// </summary>
        /// <param name="wordSize">number of byte of the key</param>
        /// <param name="testPrecision">percision of the test, error = 1/2^precision</param>
        /// <param name="primePrecision">percision of primality test, error = 1/2^(2*precision)</param>
        /// <param name="generator">random number generator, it is not disposed</param>
        /// <param name="threads">number of threads to use</param>
        /// <returns>result of the test</returns>
        public static bool CustomTest(uint wordSize, uint testPrecision, uint primePrecision,
            RandomNumberGenerator generator, int threads = 1)
        {
            if (wordSize < 64 || testPrecision < 1)
                throw new ArgumentNullException("FiatShamirIdentification test invalid input\n");

            uint iteration = 0;
            bool choice;
            BigInteger number;
            var result = true;
            var priv = PrivateKey.NewKey(generator, wordSize, threads, primePrecision);
            var pub = priv.GetPublicKey();
            var verifier = pub.GetVerifier();
            var proover = priv.GetProover(generator);

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
                return false;


            //test without key
            var genwrap = new GeneratorWrap(generator, wordSize);
            var falseKey = new PrivateKey(genwrap.GetBig(), genwrap.GetBig(), wordSize);
            proover = new Proover(falseKey, generator);
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

            return !result;
        }

        public static bool RepresentationTest()
        {
            var originalPriv = PrivateKey.NewKey(new RNGCryptoServiceProvider());
            var newPriv = PrivateKey.ResumeKey(originalPriv.SaveKey());

            if (originalPriv != newPriv) return false;

            var originalPub = originalPriv.GetPublicKey();
            var newPub = PublicKey.ResumeKey(originalPub.SaveKey());

            return originalPub == newPub;
        }
    }
}