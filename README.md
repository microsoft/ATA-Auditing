# Introduction
Understanding Audit Policy configuration is imperative for your Domain Controllers.  This includes Advanced Threat Analytics (ATA) as well.

# Getting Started
For explicit details on using this script, please refer [here](https://aka.ms/ataauditing).

For default values (assess against v1.8, throttling with 10 concurrent processes):
    .\Measure-AtaDeployment.ps1

To configure the throttling of the processes (i.e. not being run on a DC or from a well resourced machine), use the "RunJobsThrottle" parameter.  In this example, we set this paramter to 100:
    .\Measure-AtaDeployment.ps1 -RunJobsThrottle 100

To assess against ATA's v1.7, use the "AtaVersion" Parameter, which takes a *string* value:
    .\Measure-AtaDeployment.ps1 -AtaVersion "1.7"

# Getting Help
For help please refer to the above blog.  In addition, when getting help, please include the Transcript file as illustrated in the blog post.

# Contributing
This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
