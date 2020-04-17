namespace OneTimePassword.Otp
{
    using OneTimePassword.Enums;
    using System;

    public class TimeBasedOtp : ITimeBasedOtp
	{
        /// <summary>
        /// The number of ticks as Measured at Midnight Jan 1st 1970;
        /// </summary>
        private const long UnixEpochTicks = 621355968000000000L;
        /// <summary>
        /// Represents the number of ticks in 1 second.
        /// </summary>
        private const long TicksPerSecond = 10000000;

        /// <summary>
        /// Represents the time for a valid OTP. The default is 30 as recommended in the RFC.
        /// </summary>
        private readonly int step = 30;

        /// <summary>
        /// Represents the length of the generated otp code.
        /// </summary>
        private readonly int totpSize = 6;


        /// <summary>
        /// Takes a secretKey and a timestamp and then computes a TOTP(Time based one time password) value
        /// </summary>
        /// <param name="secretKey">The secretKey to use for the TOTP calculation</param>
        /// <param name="timestamp">The timestamp to use for the TOTP calculation</param>
        /// <param name="hashMode">The hash mode to use for the TOTP calculation</param>
        /// <returns>a TOTP value</returns>
        public string ComputeTotp(byte[] secretKey, DateTime timestamp, OtpHashModeEnum hashMode = OtpHashModeEnum.Sha1)
        {
            DateTime univDateTime = timestamp.ToUniversalTime();
 
            var timeStep = CalculateTimeStepFromTimestamp(univDateTime);
            return this.Compute(secretKey, timeStep, hashMode);
        }

        /// <summary>
        /// Remaining seconds for a specific timestamp
        /// </summary>
        /// <param name="timestamp">The timestamp</param>
        /// <returns>Number of remaining seconds</returns>
        public int RemainingSecondsForSpecificTime(DateTime timestamp)
        {
            timestamp = timestamp.ToUniversalTime();
            return this.step - (int)(((timestamp.Ticks - UnixEpochTicks) / TicksPerSecond) % this.step);
        }

        /// <summary>
        /// Takes a secret key, a time step and a hash mode to compute a TOTP code
        /// </summary>
        /// <param name="secretKey">The secret key</param>
        /// <param name="timeStep">The time step</param>
        /// <param name="hashMmode">The hash mode to use</param>
        /// <returns>TOTP calculated code</returns>
        private string Compute(byte[] secretKey, long timeStep, OtpHashModeEnum hashMmode)
        {
            var bigEndianTimeStep = Utils.Utils.GetBigEndianBytes(timeStep);
            var otp = this.CalculateOtp(secretKey, bigEndianTimeStep, hashMmode);
            return Utils.Utils.Digits(otp, this.totpSize);
        }

        /// <summary>
        /// Helper method that calculates OTPs
        /// </summary>
        /// <param name="secretKey">The secret key</param>
        /// <param name="data">The secret key</param>
        private long CalculateOtp(byte[] secretKey, byte[] timeStep, OtpHashModeEnum mode)
        {
            byte[] hmacComputedHash = Utils.Utils.ComputeHmac(secretKey, timeStep, mode);

            int offset = hmacComputedHash[hmacComputedHash.Length - 1] & 0x0f;

            return (hmacComputedHash[offset] & 0x7f) << 24
                | (hmacComputedHash[offset + 1] & 0xff) << 16
                | (hmacComputedHash[offset + 2] & 0xff) << 8
                | (hmacComputedHash[offset + 3] & 0xff) % 1000000;
        }

        /// <summary>
        /// Takes a timestamp and calculates a time step
        /// </summary>
        /// <param name="timestamp">The timestamp</param>
        private long CalculateTimeStepFromTimestamp(DateTime timestamp)
        {
            var window = (timestamp.Ticks - UnixEpochTicks) / (long)this.step;
            return window;
        }
    }
}
