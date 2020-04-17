namespace Tests.Unit
{
	using Microsoft.Extensions.DependencyInjection;
	using NUnit.Framework;
	using OneTimePassword.Otp;


	public class BaseSettings
	{
		protected ServiceProvider ServiceProvider;

		[SetUp]
		public void Setup()
		{
			var services = new ServiceCollection();
			services.AddScoped<ITimeBasedOtp, TimeBasedOtp>();
			services.BuildServiceProvider();
			ServiceProvider = services.BuildServiceProvider();
		}

		[TearDown]
		public void OneTimeTearDown()
		{
			ServiceProvider.Dispose();
		}
	}
}
