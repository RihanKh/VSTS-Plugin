#Overview

Checkmarx is a powerful single unified security solution for Static Source Code Analysis (SAST) and Open Source Analysis (OSA) designed for identifying, tracking and fixing technical and logical security flaws.

Checkmarx is integrated seamlessly into the Microsoft’s Software Development Life Cycle (SDLC), enabling
the early detection and mitigation of crucial security flaws.



#Checkmarx provides the following key benefits:

- **Scan source code**
Integrates smoothly within the SDLC to provide detailed near real- time feedback on code security state
- **Best fix location**
Highlights the best place to fix your code
- **Quick and accurate scanning**
Reduce false positives, adapt the rule set to minimize false positives, and understand the root cause
for results
- **Incremental scanning**
Just test the parts of the code that have been changed since last code check-in to reduce scanning time by
more than 80%. Enables incorporation of the security gate within your continuous integration pipeline
- **Seamless integration**
Works with all IDEs, build management servers, bug tracking tools and source repositories
- **Protect Your Full Code Portfolio (Open Source and In-house Source Code)**
Analyzing open source libraries, making sure licenses are being honored and weeding out any open source components which expose the application to known vulnerabilities,
Checkmarx Open Source solution provides complete code portfolio coverage under a single unified solution and with no extra installations or administration required.
- **Easy to initiate Open Source Analysis**
Enhancing your code portfolio risk assessment coverage is merely a few mouse clicks away. With Checkmarx’s Open Source Analysis, there is no need for additional installations or multiple management interfaces. Simply turn it on and within minutes a detailed report is generated with clear results and detailed mitigation instructions. Analysis results are designed with the developer in mind.
No time is wasted on trying to understand the required actions items to mitigate the detected security or compliance risk.


![image](images/summaryTab.PNG)



#Before You Start:

If you don't already have a Checkmarx server and require a hosted Checkmarx service, please submit the trial request registration form.
[link to Checkmarx registration page](https://info.checkmarx.com/cx-microsoft-vs-team-services)



#Checkmarx Registration:

![image](images/sample2.png)

**To complete this step:**
1.	Complete the form to request a Checkmarx trial license
2.	Activation may take a few days to set up your trial cloud account
    A Checkmarx representative will contact you with the trial license



#Getting Started with Checkmarx:

Checkmarx for Visual Studio Team Services and Team Foundation Server (2015 and greater)is simple to install and configure.
The following steps are required to get started.



#Getting Started with Checkmarx:

![image](images/sample3.png)

**To complete this step:**
1.	From the Build menu in the main screen, add Checkmarx build step
2.	Click Add to configure Checkmarx and configure the properties



#Configure Checkmarx Build Step

![image](images/config.png)

**To complete this step:**

1.	CxServer
    a.	Select a Checkmarx Endpoint from the drop-down list or click Manage to associate a new Endpoint (described in the next section).
    b.	Enter a Project Name: Either select an existing project from the list, or type in any name to create a new scan project
    c.	Preset - predefined sets of queries that you can select when Creating, Configuring and Branching Projects. Predefined presets are provided by Checkmarx and you can configure your own. You can also import and export presets.
    d.	Team – which group the project is associated
    e.	Enable the Incremental Scan checkbox if you want to reduce time between scans
    f.	Enter how often a full scan is executed between incremental scans
    g.	Folder Exclusions – comma delimited list of the folders to exclude from the scan
    h.	File Exclusions – comma delimited list of the file extensions to exclude from the scan
    i.	Synchronous Mode – enabling this option will cause the build step to wait for scan results, you can see the scan results inside the Checkmarx plug-in results window. If disabled, the results are only displayed inside the Checkmarx web-application.
    j.	Vulnerability Threshold – Available only if Synchronous mode is enabled. Set the maximum number of vulnerabilities allowable before the scan fails
2.	Control options
    a.	Enabled - Clear this check box if you want to disable a step. This is a handy option if a step is not working correctly or if you need to focus on other parts of the process.
    b.	Continue on error - If an error occurs in this step, and this check box is:
      1.	Cleared: The build fails and no subsequent steps are run.
      2.	Selected: The build will be partially successful at best, and the next step is run
      3.	Always run – control option is enabled for the rollback task, so that the script can get executed when any of the tasks in the job fail.
    c.	Scan Timeout (minutes) – enter the number of minutes to allow the scan to run before timing out.

3.  CxOSA Scan
    a.  CxOSA Folder Exclusions - comma delimited list of the folders to exclude from the scan
    b.  CxOSA Include/Exclude wildcard patterns - Comma separated list of include or exclude wildcard patterns
    c.  CxOSA Archive Extract Extensions - Comma separated list of archive wildcard patterns to include their extracted content for the scan.


#Setup New Checkmarx End-Point

![image](images/sample5.png)

**To complete this step:**
1.	Enter Connection Name – Free text, for example: Checkmarx
2.	Enter Server URL – URL is provided by Checkmarx following registration
3.	Enter Username – is provided by Checkmarx following registration
4.	Enter Password – is provided by Checkmarx following registration
5.	Click OK to continue