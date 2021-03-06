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
//version V.2.2

using System;
using System.Numerics;

namespace FiatShamirIdentification
{
    /// <summary>
    ///     Object that checks whether an object Proover has the private key
    ///     that is associated with his public key.
    ///     Single iteration of protocol have error ratio = 1/2.
    /// </summary>
    public sealed class Verifier
    {
        private readonly Random _bitgen;
        private readonly PublicKey _key;
        private bool _choice;
        private BigInteger _sessionNumber;
        private bool _state;
        private bool _synch;


        internal Verifier(PublicKey key)
        {
            _key = key;
            _state = false;
            _bitgen = new Random();
            _synch = false;
        }


        /// <summary>
        ///     Take the result of Proover.Step1() and return a random choice to send to Proover.
        /// </summary>
        /// <param name="init">result of Proover.Step1()</param>
        /// ///
        /// <exception cref="ArgumentException"> invalid init </exception>
        /// <returns>bool to send to Proover</returns>
        public bool Step1(ref BigInteger init)
        {
            if (init < 2)
                throw new ArgumentException("init < 2");

            _sessionNumber = init;
            _choice = _bitgen.Next() % 2 == 1;
            _state = false;
            _synch = true;
            return _choice;
        }


        /// <summary>
        ///     Take the result of Proover.Step2() and return the state of identification.
        /// </summary>
        /// <param name="proof">result of Proover.Step2()</param>
        /// <exception cref="InvalidOperationException">Verifier.Step2 is called before calling Verifier.Step1</exception>
        /// <returns>true if the Proover is identified</returns>
        public bool Step2(BigInteger proof)
        {
            if (_synch)
                _synch = false;
            else throw new InvalidOperationException("Called Verifier.Step2 before calling Verifier.Step1");
            proof = proof * proof % _key.Modulus;

            BigInteger y;

            if (_choice)
                y = _sessionNumber * _key.Key % _key.Modulus;
            else y = _sessionNumber;

            _state = proof == y;

            return _state;
        }


        /// <summary>
        ///     Return the state of identification in this iteration.
        ///     Single iteration of protocol have error ratio = 1/2.
        /// </summary>
        /// <returns>true if the Proover is identified</returns>
        public bool CheckState()
        {
            return _state;
        }
    }
}