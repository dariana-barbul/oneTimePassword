namespace OneTimePassword
{
	using Microsoft.Extensions.DependencyInjection;
    using OneTimePassword.Otp;
    using System;
	using System.Text;

	class Program
	{
		static void Main(string[] args)
		{
			var serviceProvider = new ServiceCollection()
			.AddScoped<ITimeBasedOtp, TimeBasedOtp>()
			.BuildServiceProvider();

			Console.WriteLine("Please introduce user id:");
			var userId = Console.ReadLine();
			Console.WriteLine("Please insert a date time (e.g.{0}) : ", DateTime.UtcNow);
			DateTime userDateTime;
			if (DateTime.TryParse(Console.ReadLine(), out userDateTime))
			{
				var secretKey = userId + userDateTime.ToString();
				var timeBasedOtpService = serviceProvider.GetService<ITimeBasedOtp>();
				var timeBasedOtp = timeBasedOtpService.ComputeTotp(Encoding.UTF8.GetBytes(secretKey), userDateTime);
				Console.WriteLine("Your one time password is: {0}", timeBasedOtp);
			}
			else
			{
				Console.WriteLine("You have entered an incorrect value!");
			}
			Console.ReadKey();
		}
	}
}
