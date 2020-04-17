namespace OneTimePassword.Utils
{
    using OneTimePassword.Enums;
    using System;
    using System.Security.Cryptography;

    public static class Utils
	{
        /// <summary>
        /// Uses the key to get an HMAC using the specified algorithm and time step
        /// </summary>
        /// <param name="secretKey">The secret key used to compute the HMAC</param>
        /// <param name="timeStep">The time step used to compute the HMAC</param>
        /// <param name="hashMode">The HMAC algorithm to use</param>
        public static byte[] ComputeHmac(byte[]secretKey, byte[] timeStep, OtpHashModeEnum hashMode)
        {
			byte[] hashedValue = null;
			using (HMAC hmac = CreateHmacHash(hashMode))
			{
				hmac.Key = secretKey;
				hashedValue = hmac.ComputeHash(timeStep);
			}
			return hashedValue;
		}

        /// <summary>
        /// truncates a number down to the specified number of digits
        /// </summary>
        /// <param name="input">The generated otp </param>
        /// <param name="digitCount">The number of digits </param>
        public static string Digits(long input, int digitCount)
        {
            var truncatedValue = ((int)input % (int)Math.Pow(10, digitCount));
            return truncatedValue.ToString().PadLeft(digitCount, '0');
        }

        /// <summary>
        /// converts a long into a big endian byte array.
        /// </summary>
        /// <remarks>
        /// RFC 4226 specifies big endian as the method for converting the counter to data to hash.
        /// </remarks>
        public static byte[] GetBigEndianBytes(long input)
        {
            // Since .net uses little endian numbers, we need to reverse the byte order to get big endian.
            var data = BitConverter.GetBytes(input);
            Array.Reverse(data);
            return data;
        }

        /// <summary>
        /// Create an HMAC object for the specified algorithm
        /// </summary>
        private static HMAC CreateHmacHash(OtpHashModeEnum otpHashMode)
        {
            HMAC hmacAlgorithm = null;
            switch (otpHashMode)
            {
                case OtpHashModeEnum.Sha256:
                    hmacAlgorithm = new HMACSHA256();
                    break;
                case OtpHashModeEnum.Sha512:
                    hmacAlgorithm = new HMACSHA512();
                    break;
                default: //case OtpHashMode.Sha1:
                    hmacAlgorithm = new HMACSHA1();
                    break;
            }
            return hmacAlgorithm;
        }
    }
}
