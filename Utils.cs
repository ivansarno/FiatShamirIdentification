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
    internal sealed class GeneratorWrap
    {
        private readonly byte[] _buffer;
        private readonly RandomNumberGenerator _gen;

        public GeneratorWrap(RandomNumberGenerator generator, uint wordSize)
        {
            Size = wordSize;
            _gen = generator;
            _buffer = new byte[wordSize];
        }

        public uint Size { get; }

        public BigInteger GetBig()
        {
            _gen.GetBytes(_buffer);
            _buffer[Size - 1] &= 127; //forces a positive number
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

        public ulong GetULong()
        {
            _gen.GetBytes(_buffer, 0, 8);
            return BitConverter.ToUInt64(_buffer, 0);
        }

        public uint GetUInt()
        {
            _gen.GetBytes(_buffer, 0, 4);
            return BitConverter.ToUInt32(_buffer, 0);
        }
    }

    internal static class ArrayExtension
    {
        internal static T[] Slice<T>(this T[] source, int start, int end)
        {
            var length = end - start;
            var slice = new T[length];
            Array.Copy(source, start, slice, 0, length);
            return slice;
        }

        internal static T[] Slice<T>(this T[] source, int start)
        {
            var length = source.Length - start;
            var slice = new T[length];
            Array.Copy(source, start, slice, 0, length);
            return slice;
        }

        internal static T[] Concat<T>(this T[] first, T[] second)
        {
            var length = first.Length + second.Length;
            var union = new T[length];
            Array.Copy(first, union, first.Length);
            Array.Copy(second, 0, union, first.Length, second.Length);
            return union;
        }

        internal static T[] Concat<T>(this T[] first, T[] second, T[] third)
        {
            var length = first.Length + second.Length + third.Length;
            var union = new T[length];
            Array.Copy(first, union, first.Length);
            Array.Copy(second, 0, union, first.Length, second.Length);
            Array.Copy(third, 0, union, first.Length + second.Length, third.Length);
            return union;
        }
    }
}