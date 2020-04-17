namespace OneTimePassword.Otp
{
	using OneTimePassword.Enums;
	using System;

	public interface ITimeBasedOtp
	{
		string ComputeTotp(byte[] secretKey, DateTime timestamp, OtpHashModeEnum hashMode = OtpHashModeEnum.Sha1);

		int RemainingSecondsForSpecificTime(DateTime timestamp);
	}
}
