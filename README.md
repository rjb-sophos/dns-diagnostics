# dns-diagnostics
Tools to help diagnose issues with DNS, particularly geared around problems getting successfully set up with Sophos DNS Protection
# dnsdiag.ps1
This PowerShell script will run a series of tests to evaluate different aspects of the DNS configuration of a Windows device. It can help provide answers to many of the common detailed questions that come up when you've tried to deploy DNS Protection and it 'doesn't work'.
It writes detailed output from the tests to a file called `network_diagnostics.txt` in the current directory where you run it from.
It is mostly aimed at providing a dump of output that a human can analyze, and makes minimal efforts to interpret the results of its tests. That’s something for the future!
## Usage
   `.\dnsdiag.ps1 [-no_open] [-skip_leaktest] [-skip_regions] [-outputFile "[Filename]"] [-tenant_id <UUID>] `

      -no_open       Do not open the output file in Notepad at the end
      -skip_leaktest Don't run the full DNS Leak Test
      -skip_regions  Don't run the region-by-region latency checks
      -no_html       Don't output the blockpage HTML in the results
      -outputFile    Write output to a different file instead of `network_diagnostics.txt`. A blank
                     value ("") will write all output to the console (ugh!).
      -tenant_id     Provide your Sophos Central account ID (a uuid in the form  
                     00000000-0000-0000-0000-000000000000) for extra checks

## Description

The script runs through the following tests:

1. Test if DNS resolution is working by just issuing DNS requests using system defaults

   1. Resolve www.sophos.com

   1. Resolve www.google.com

1. Test if the system is set up to use DNS Protection by doing a DNS lookup for dns.access.sophos.com using system defaults

1. Test if the blockpage/welcome page is accessible by doing an HTTP request to http://dns.access.sophos.com and checking that the returned content looks like our page

1. Test if the root certificate is installed and trusted by doing an HTTPS request to https://dns.access.sophos.com

1. Checks to see if the DNS Protection server IPs are accessible

   1. Check that they appear to be accessible - Do a lookup for www.zoneedit.com (a whitelisted dynamic dns provider that should be answered for any source IP) against 193.84.4.4

   1. Check you appear to be at a recognized location by querying www.google.com against 193.84.4.4 and 193.84.5.5

   1. Checks to confirm that it is actually DNS Protection by querying dns.access.sophos.com against 193.84.4.4

   1. Uses special TXT probe queries supported by DNS Protection to confirm the source IP that DNS Protection sees, and whether your IP is a known 'Location' in an account

   1. If you provide your Sophos Central unique account ID at the command line, it will repeat the test to confirm that the IP address is actually registered to a location in your account. 

1. Runs a DNS Leak Test using https://bash.ws and displays the list of DNS servers that queries are coming from. The data returned also includes the apparent source IP address, taken from the HTTPS requests to the service (not from the DNS queries)

1. Attempt to identify the public IP address using two different methods

   1. Use api.myip.com. If it fails first time (because of DNS resolution) it attempts to access the service directly using a known IP address. Note that this IP address is likely to change to this script may need updating.

   1. Using OpenDNS’s DNS echo service. Again, it first queries the OpenDNS resolver by name, which will fail if DNS resolution is not working on the device, so it falls back to querying the resolver based on a known IP address

1. Test DNS query latency by sending 10 requests and calculating the average round-trip time. This is always interesting information to get, and the comparison may tell us something about how their system DNS is set up. For example, very low latency times (<10ms) will often point to the fact that they have a local DNS resolver:

   1. First by querying 193.84.4.4 directly

   1. Secondly by using the system DNS resolver settings

   1. Finally by querying the region-specific POPs directly (to retrieve per-region latency numbers)

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
# dlt.pl

This tool is designed to run at the command line of a Sophos Firewall and makes use of Perl modules specific to the Firewall. It provides a way to do a DNS leak test directly from the Firewall itself, instead of just running a Leak Test web page on a browser inside the network. Running the test on the Firewall allows you to rule out possible issues on the internal network and focus on whether DNS traffic is being diverted downstream from your Firewall by your ISP or a network gateway device outside of the Firewall.

## Usage
   `perl dlt.pl [-s <ip address>]`

      -s <ip address>   Just run a single leak test against the DNS server at this ip address, using UDP port 53


With no command line arguments, it starts by doing the diagnostic DNS queries that will only be answered by DNS Protection, and that can confirm if your Firewall's IP address is known and is a registered Location in DNS Protection for your Central account.

It then performs leak tests using 5 DNS resolver addresses:

1. The Firewall's built-in DNS server, which forwards queries to the configured servers and falls back to recursive resolution if that fails

1. DNS Protection on 193.84.4.4 using UDP

1. DNS Proteciton on 193.84.5.5 using UDP

1. DNS Protection on 193.84.4.4 using TCP - sometimes when DNS is being diverted, only UDP traffic is affected.

1. Google DNS on 8.8.8.8 using UDP - if traffic to DNS Protection is being diverted, it might be interesting to see if that's happening for Google DNS as well.
