namespace Tests.Unit
{
	using Microsoft.Extensions.DependencyInjection;
	using NUnit.Framework;
	using OneTimePassword.Enums;
	using OneTimePassword.Otp;
	using System;
	using System.Text;

	[TestFixture]
    public class TotpTests : BaseSettings
	{
		private const string HMAC_SHA1_20_bytes = "3132333435363738393031323334353637383930";
		private const string HMAC_SHA256_32_bytes = "3132333435363738393031323334353637383930" + "313233343536373839303132";
		private const string HMAC_SHA512_64_bytes = "3132333435363738393031323334353637383930" + "3132333435363738393031323334353637383930" + "3132333435363738393031323334353637383930" +
		 "31323334";

		[TestCase(HMAC_SHA1_20_bytes, OtpHashModeEnum.Sha1, 59, "265310")]
		[TestCase(HMAC_SHA256_32_bytes, OtpHashModeEnum.Sha256, 59, "368842")]
		[TestCase(HMAC_SHA512_64_bytes, OtpHashModeEnum.Sha512, 59, "182170")]
		public void ComputeTOTPTest(string secret, OtpHashModeEnum hashMode, long timestamp, string expectedOtp)
		{
			//Arrange
			var timeBasedOtpService = this.ServiceProvider.GetService<ITimeBasedOtp>();
			DateTime time = DateTimeOffset.FromUnixTimeSeconds(timestamp).DateTime;
			
			//Act
			var otp = timeBasedOtpService.ComputeTotp(Encoding.UTF8.GetBytes(secret), time, hashMode);

			//Assert
			Assert.AreEqual(otp, expectedOtp);
		}

		[Test]
		public void RemainingSecondsForSpecificTimeTest()
		{
			//Arrange
			var timeBasedOtpService = this.ServiceProvider.GetService<ITimeBasedOtp>();
			var secret = "secretKey";
			var time = DateTime.UtcNow;

			//Act
			timeBasedOtpService.ComputeTotp(Encoding.UTF8.GetBytes(secret), time);
			var remainingTime = timeBasedOtpService.RemainingSecondsForSpecificTime(DateTime.UtcNow);

			//Assert
			Assert.IsNotNull(remainingTime);
		}
	}
}