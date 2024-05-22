# dns-diagnostics
Tools to help diagnose issues with DNS, particularly geared around problems getting successfully set up with Sophos DNS Protection
# dnsdiag.ps1
This PowerShell script will run a series of tests to evaluate different aspects of the DNS configuration of a Windows device. It can help provide answers to many of the common detailed questions that come up when you've tried to deploy DNS Protection and it 'doesn't work'.
It writes detailed output from the tests to a file called `network_diagnostics.txt` in the current directory where you run it from.
It is mostly aimed at providing a dump of output that a human can analyze, and makes minimal efforts to interpret the results of its tests. That’s something for the future!

It runs through the following tests:

1. Test if DNS resolution is working by just issuing DNS requests using system defaults

2. 1. Resolve www.sophos.com

   2. Resolve www.google.com

1. Test if the system is set up to use DNS Protection by doing a DNS lookup for dns.access.sophos.com using system defaults

1. Test if the blockpage/welcome page is accessible by doing an HTTP request to http://dns.access.sophos.com and checking that the returned content looks like our page

1. Test if the root certificate is installed and trusted by doing an HTTPS request to https://dns.access.sophos.com

1. Checks to see if the DNS Protection server IPs are accessible

   1. Check that they appear to be accessible - Do a lookup for www.zoneedit.com (a whitelisted dynamic dns provider that should be answered for any source IP) against 193.84.4.4

   1. Check you appear to be at a recognized location by querying www.google.com against 193.84.4.4 and 193.84.5.5

   1. Checks to confirm that it is actually DNS Protection by querying dns.access.sophos.com against 193.84.4.4

1. Runs a DNS Leak Test using https://bash.ws and displays the list of DNS servers that queries are coming from. The data returned also includes the apparent source IP address, taken from the HTTPS requests to the service (not from the DNS queries)

1. Attempt to identify the public IP address using two different methods

   1. Use api.myip.com. If it fails first time (because of DNS resolution) it attempts to access the service directly using a known IP address. Note that this IP address is likely to change to this script may need updating.

   1. Using OpenDNS’s DNS echo service. Again, it first queries the OpenDNS resolver by name, which will fail if DNS resolution is not working on the device, so it falls back to querying the resolver based on a known IP address

1. Test DNS query latency by sending 10 requests and calculating the average round-trip time. This is always interesting information to get, and the comparison may tell us something about how their system DNS is set up. For example, very low latency times (<10ms) will often point to the fact that they have a local DNS resolver:

   1. First by querying 193.84.4.4 directly

   1. Secondly by using the system DNS resolver settings

After the tests, it runs a couple more diagnostic commands

- Outputs a prioritized list of interfaces together with their DNS settings, to help check if the device is configured correctly or if Windows may be directing queries to other services

- Output from ipconfig /all - because it can be quite useful

Finally it prints a brief summary of the test results, for tests that have a pass/fail outcome.

### Enabling the script

Note that Windows defaults now prevent running of Powershell scripts unless the are signed by a trusted code signing certificate. This is enforced with Execution Policies. You can change this policy using the Set-ExecutionPolicy cmdlet. You can change this policy for a User, for the whole device, and the policy can be set using Active Directory GPOs.

It’s probably not a good idea to enable it at the User or Device level, unless you remember to change it back.

To enable all scripts to be run just for the lifetime of your current PowerShell window, run this command:

```
PS C:\> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted
```