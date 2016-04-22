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
                System.Console.WriteLine("FiatShamirIdentification test invalid input\n");
                return false;
            }

            uint iteration = 0;
            bool choice;
            BigInteger number;
            bool result = true;
            var generator = new RNGCryptoServiceProvider();
            var priv = PrivateKey.NewKey(generator, wordSize);
            var pub = priv.GetPublicKey();
            Verifier verifier = pub.GetVerifier();
            Proover proover = priv.GetProover(generator);

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
                System.Console.WriteLine("FiatShamirIdentification test ERROR\n");
                generator.Dispose();
                return false;
            }


            //test without key
            var genwrap = new GeneratorWrap(generator, wordSize);
            proover = new Proover(genwrap.GetBig(), genwrap.GetBig(), generator);
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
                System.Console.WriteLine("FiatShamirIdentification test ERROR\n");
                generator.Dispose();
                return false;
            }

            System.Console.WriteLine("FiatShamirIdentification test OK\n");
            generator.Dispose();
            return true;
        }


        /// <summary>
        /// Customizable version with full NewKey parameters.
        /// </summary>
        /// <param name="wordSize">number of byte of the key</param>
        /// <param name="testPrecision">percision of the test, error = 1/2^precision</param>
        /// <param name="primePrecision">percision of primality test, error = 1/2^(2*precision)</param>
        /// <param name="generator">random number generator, it is not disposed</param>
        /// <param name="threads">number of threads to use</param>
        /// <returns>result of the test</returns>
        public static bool CustomTest(uint wordSize, uint testPrecision, uint primePrecision, RandomNumberGenerator generator, ulong primeDistance=uint.MaxValue, int threads = 1)
        {
            if (wordSize < 8 || testPrecision < 1)
            {
                System.Console.WriteLine("FiatShamirIdentification test invalid input\n");
                return false;
            }

            uint iteration = 0;
            bool choice;
            BigInteger number;
            bool result = true;
            var priv = PrivateKey.NewKey(generator, wordSize, threads, primePrecision);
            var pub = priv.GetPublicKey();
            Verifier verifier = pub.GetVerifier();
            Proover proover = priv.GetProover(generator);

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
                System.Console.WriteLine("FiatShamirIdentification test ERROR\n");
                return false;
            }


            //test without key
            var genwrap = new GeneratorWrap(generator, wordSize);
            proover = new Proover(genwrap.GetBig(), genwrap.GetBig(), generator);
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
                System.Console.WriteLine("FiatShamirIdentification test ERROR\n");
                return false;
            }

            System.Console.WriteLine("FiatShamirIdentification test OK\n");
            return true;
        }

        public static bool RepresentationTest()
        {
            var originalPriv = PrivateKey.NewKey(new RNGCryptoServiceProvider());
            var newPriv = PrivateKey.ResumeKey(originalPriv.SaveKey());

            if (!PrivateKey.EqTest(originalPriv, newPriv))
            {
                System.Console.WriteLine("Representation Test ERROR: PrivateKey problem.\n");
                return false;
            }

            var originalPub = originalPriv.GetPublicKey();
            var newPub = PublicKey.ResumeKey(originalPub.SaveKey());

            if (!PublicKey.EqTest(originalPub, newPub))
            {
                System.Console.WriteLine("Representation Test ERROR: PublicKey problem.\n");
                return false;
            }

            System.Console.WriteLine("Representation Test OK.\n");
            return true;
        }
    }
}
