﻿/*
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
using System.Security.Cryptography;


namespace FiatShamirIdentification
{
    public sealed class Proover
    {
        private readonly BigInteger _key;
        private readonly BigInteger _mod;
        private BigInteger _sessionNumber;
        private readonly GeneratorWrap _generator;
        private bool _synch;


        /// <summary>
        /// </summary>
        /// <param name="privateKey">private key</param>
        /// <param name="module">module of the key</param>
        /// <param name="wordSize">key size in bytes</param>
        /// <param name="gen">random number generator, it is not disposed.</param>
        internal Proover(BigInteger privateKey, BigInteger module, RandomNumberGenerator gen, uint wordSize = 128)
        {
            _mod = module;
            _key = privateKey;
            _generator = new GeneratorWrap(gen, wordSize);
            _synch = false;
        }


        /// <summary>
        /// Start the protocol and return the init for Verifier.Step1.
        /// </summary>
        /// <returns>number to send to Verifier</returns>
        public BigInteger Step1()
        {

            _sessionNumber = _generator.GetBig()%_mod;
            _synch = true;
            while(_sessionNumber < UInt64.MaxValue) //avoid comunication of the key
                _sessionNumber = _generator.GetBig() % _mod;
            return (_sessionNumber*_sessionNumber)%_mod;

        }


        /// <summary>
        /// Take the result of Verifier.Step1() and return the proof to send to Verifier.
        /// </summary>
        /// <param name="choice">result of Verifier.Step1()</param>
        /// <exception cref="InvalidOperationException"> Proover.Step2 is called before calling Proover.Step1</exception>
        /// <returns>a number to send to Verifier</returns>
        public BigInteger Step2(bool choice)
        {
            if (_synch)
                _synch = false;
            else throw new InvalidOperationException("Called Proover.Step2 before calling Proover.Step1");
            if (choice)
                return (_sessionNumber*_key)%_mod;
            return _sessionNumber;
        }
    }
}
