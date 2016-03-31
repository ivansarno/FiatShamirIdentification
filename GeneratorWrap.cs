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
//version V.2.0 beta

using System;
using System.Numerics;
using System.Security.Cryptography;


namespace FiatShamirIdentification
{
    internal class GeneratorWrap
    {
        private readonly RandomNumberGenerator _gen;
        private readonly byte[] _buffer;
        public uint Size { get;}

        public GeneratorWrap(RandomNumberGenerator generator, uint wordSize)
        {
            Size = wordSize;
            _gen = generator;
            _buffer = new byte[wordSize];
        }

        public BigInteger GetBig()
        {
            _gen.GetBytes(_buffer);
            _buffer[Size-1] &= 127; //forces a positive number
            return new BigInteger(_buffer);
        }

        public long GetLong()
        {
            _gen.GetBytes(_buffer, 0, 8);
            return BitConverter.ToInt64(_buffer, 0);
        }

        public int GetInt()
        {
            _gen.GetBytes(_buffer, 0, 4);
            return BitConverter.ToInt32(_buffer, 0);
        }
    }
}
