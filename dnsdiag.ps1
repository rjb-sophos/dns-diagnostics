# dnsdiag.ps1
#
# Script for collecting a range of information to help diagnose
# DNS setup issues related to Sophos DNS Protection
#
# Creates/overwrites output into $outputFile - opens the output in Notepad
#
# Make $outputFile an empty string to output all detail to the console
#
# To allow permission to run this script, run the following command first:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted
# This allows running of scripts in the current PS console until it's closed

$knownIP_resolver3_opendns="208.67.222.220"
$knownIP_api_myip="172.67.75.163"
$outputFile = "network_diagnostics.txt"

if( $outputFile -ne "") {
    Write-Host "Test output will be written to $outputFile"
    try {
        Remove-Item $outputFile -ErrorAction Stop
    }
    catch {
    }
}

function Write-Result {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
                   ValueFromPipeline)]
        $Output
    )
    PROCESS {
        if($outputFile -eq "") {
            $Output | Out-Host
         } else { 
            if(($Output.GetType().Name -eq "String") -and ($Output.StartsWith("Test"))) {
                $Output | Out-Host
            }
            $Output | Out-File -Append $outputFile
        }
    }
}
function Test-DNSLatency {
    param(
        [string]$testname="www.sophos.com",
        [int]$turns=10,
        [string]$res="193.84.4.4",
        [string]$type="A"
    )
    $t=@()
    $params=@{
        Name=$testname
        Type="A"
        ErrorAction="Stop"
        Server=$res
        }
    if($res -eq "") {
        Write-Result "Testing system default resolver, requesting $type record for $testname"
        $params.Remove('Server')
    } else {
        Write-Result "Testing resolver at $res, requesting $type record for $testname"
    }
    for ($i=0;$i -lt $turns+1; $i++) {
        try {
            $t1=(Measure-Command {
                Resolve-DnsName @params
            }).TotalMilliseconds
            if ($i -gt 0) {
                $t+=$t1
                Write-Result "Turn $($i) : $($t[-1])ms"
            } else {
                Write-Result "Priming query : $($t1)ms"
            }
            Start-Sleep -Milliseconds 200
        }
        catch {
            Write-Result "DNS resolution error:"
            write-Result ( $_ | Format-Table|Out-String)
            $i=$turns+1
        }
    }
    if($t.length -eq $turns) {
        $tt=($t | measure -Average)
        Write-Result "Average=$($tt.Average)ms"
    } else {
        Write-Result "DNS latency test incomplete"
    } 
}
# Error handler
function Invoke-ErrorHandler {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffzzz"
    Write-Result "[${timestamp}]: $Message"
    Write-Error "[${timestamp}]: $Message" -ErrorAction Stop
}
# Help print a server line based on what info is present, pass a line (arg $1)
function Format-ServerInfo {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Line
    )
    $parts = $Line -split "\|"
    $ip = $parts[0].Trim()
    $country = $parts[2].Trim()
    $asn = $parts[3].Trim()
    $msg = ""
    if ([string]::IsNullOrEmpty($ip)) {
        return "NO IP"
    } else {
        try {
           $hostname=(Resolve-DnsName $ip -ErrorAction Stop).NameHost
        }
        catch {
            $hostname="reverse lookup failed"
        }
       if([string]::IsNullOrEmpty($hostname)) {
           $msg="$ip | reverse lookup failed "
       } else {
           $msg="$ip | $hostname " 
       }
       if ([string]::IsNullOrEmpty($country) -and [string]::IsNullOrEmpty($asn) ) {
           return $msg
       }
       elseif ([string]::IsNullOrEmpty($country) -or [string]::IsNullOrEmpty($asn)) {
            return "$msg | ${country}${asn}"
        }
        else {
            return "$msg | $country | $asn"
        }
    }
}

Function Test-DnsLeaks {
    # Check for all mandatory tools
    #Test-AvailableCommand -Commands "Cut", "Echo", "Select-String", "Head", "New-TemporaryFile", "Test-Connection", "ForEach-Object", "Replace"
    # Leaktest site
    $transport = "https://"
    $domain = "bash.ws"
    # Start test
    # Generate random id between 1000000-9999999
    $id = [int](Get-Random -Minimum 1000000 -Maximum 9999999)
    Write-Result "DNS leak test: Checking for network connection using id $id..."
    # Prep for download and get a header
    $results = New-TemporaryFile
    $link = "$transport$domain"
    
    # Check internet connection
    try {
        Invoke-WebRequest -Uri $link -UseBasicParsing -OutFile $results.FullName -ErrorAction Stop 
    }
    catch {
        Invoke-ErrorHandler -Message "Error, timeout while testing internet connection"
    }
    
    # Test header
    $headerContent = Get-Content -Path $results.FullName -Raw
    if ($headerContent -match "200 OK" -or $headerContent -match "DNS leak test") {
        Write-Result "DNS leak test: Connected to internet, sending DNS probes..."
    }
    else {
        Invoke-ErrorHandler -Message "Error, failed to connect to testing domain: ${transport}${domain}"
    }
    
    # Send 10 pings with your id
    for ($i = 1; $i -le 10; $i++) {
        Test-Connection -ComputerName "${i}.${id}.${domain}" -Count 1 -ErrorAction SilentlyContinue | Out-Null
    }
    # Save results to a file
    $results.Delete()
    $link = "${transport}${domain}/dnsleak/test/${id}?txt"
    try {
        Invoke-WebRequest -Uri $link -UseBasicParsing -OutFile $results.FullName -ErrorAction Stop
    }
    catch {
        Invoke-ErrorHandler -Message "Error, failed to download results of DNS Leak test"
    }
    # Unpack the text file and print the servers
    Write-Result "DNS leak test Results`n====================="
    Get-Content -Path $results.FullName | ForEach-Object {
        $line=$_
        $cols=($line -split "\|")
        switch ($cols[4]) {
            "ip" {
                Write-Result "Your IP: "
                Format-ServerInfo -Line $line | Write-Result
                Write-Result "`nYour DNS Server(s):"
            }
            "conclusion" {
# Ignore their conclusion as it's not really relevant to this test
 #               Write-Result "`nConclusion: $($cols[0])"
            }
            "dns" {
                Format-ServerInfo -Line $line | Write-Result
            }
            default {
                Write-Error "Error encountered for line: $line"
            }
        }
    }
    # Delete temp file
    $results.Delete()
}

$notTested="Not tested"
$success="Success"
$failed="Failed"
$redirect="Redirected"

$collectResults=@{
    systemDNS=$notTested
    systemUsingDNSProt=$notTested
    gotDNSProtWelcomePage=$notTested
    gotDNSProtWelcomePageHTTPS=$notTested
    reachDNSProt4=$notTested
    reachDNSProt5=$notTested
    accessDNSProt=$notTested
    queryRedirection=$notTested
}

# Tests start here
Write-Result "Test starting - DNS Diagnostics at $(Get-Date -Format "yyyy-MM-dd hh:mm:ss K")`n"

# Test General DNS resolution
Write-Result "Test 1a: Testing if system DNS resolution is working - resolving www.sophos.com..."
try {
    $dns = Resolve-DnsName -Name "www.sophos.com" -Erroraction Stop | Write-Result
}
catch {
    Write-Result "Error resolving www.sophos.com - device DNS may not be configured correctly at all" 
    write-Result ( $_ | Format-Table|Out-String)
    $collectResults['systemDNS']=$failed
}
# Test general DNS resolution
Write-Result "Test 1b: Testing resolution of www.google.com..."
try {
    Resolve-DnsName -Name "www.google.com" -ErrorAction Stop | Write-Result
    $collectResults['systemDNS']=$success
}
catch {
    Write-Result "Error resolving www.google.com:"
    write-Result ( $_ | Format-Table|Out-String)
    $collectResults['systemDNS']=$failed
}
Write-Result "End of test 1`n------" 

Write-Result "Test 2: Testing if you're using DNS Protection by resolving dns.access.sophos.com..."
if($collectResults['systemDNS'] -eq $success) {
    try {
        $dns = Resolve-DnsName -Name "dns.access.sophos.com" -Erroraction Stop 
        $dns | Write-Result
        if( ($dns.Length -gt 0) -and
           ($dns[0].Name -eq "dns.access.sophos.com") -and 
           ($dns[0].Type -eq 'A') ) {
            Write-Result "Successful, as far as I can tell"
            $collectResults['systemUsingDNSProt']=$success
        } else {
            Write-Result "Unexpected result - should have received an A record"
            $collectResults['systemUsingDNSProt']=$redirect
        }
    }
    catch {
        Write-Result "Error resolving dns.access.sophos.com - device DNS configuration is not using DNS Protection"
        Write-Result ( $_ | Format-Table|Out-String)
        $collectResults['systemUsingDNSProt']=$failed
    }
} else {
    Write-Result "System DNS not working - skipping this test"
}
Write-Result "End of test 2`n------"

# Test access to the blockpage service
Write-Result "Test 3: Checking blockpage service..."
if($collectResults['systemDNS'] -eq $success) {
    if($collectResults['systemUsingDNSProt'] -eq $success) {
        try {
            $blockpageResponse = Invoke-WebRequest -Uri "http://dns.access.sophos.com" -ErrorAction Stop
            Write-Result "Blockpage content:"
            Write-Result $blockpageResponse.RawContent
            if ($blockpageResponse.RawContent -like "*Welcome to Sophos DNS Protection*") {
                Write-Result "Blockpage service accessible" 
                $collectResults['gotDNSProtWelcomePage']=$success
            } else {
                Write-Result "Blockpage content not recognized"
                $collectResults['gotDNSProtWelcomePage']=$failed
            }
        }
        catch {
            Write-Result "Error accessing blockpage service"
            Write-Result ( $_ | Format-Table|Out-String)
            $collectResults['gotDNSProtWelcomePage']=$failed
        }
    } else {
        Write-Result "System DNS is not being handled by DNS Protection - skipping this test"
    }
} else {
    Write-Result "System DNS not working - skipping this test"
}
Write-Result "End of test 3`n------" 

# Test HTTPS access to the blockpage service
Write-Result "Test 4: Checking blockpage service over HTTPS..."
if($collectResults['systemDNS'] -eq $success) {
    if($collectResults['systemUsingDNSProt'] -eq $success) {
        try {
            $blockpageResponse = Invoke-WebRequest -Uri "https://dns.access.sophos.com" -ErrorAction Stop
            # No need to output the page content again - we're really looking for cert errors
            if ($blockpageResponse.RawContent -like "*Welcome to Sophos DNS Protection*") {
                Write-Result "HTTPS blockpage service accessible"
                $collectResults['gotDNSProtWelcomePageHTTPS']=$success
            } else {
                Write-Result "HTTPS blockpage content not recognized" 
                Write-Result "Blockpage content:" 
                Write-Result $blockpageResponse.RawContent 
                $collectResults['gotDNSProtWelcomePageHTTPS']=$failed
            }
        }
        catch {
            Write-Result "Error accessing HTTPS blockpage service - have you installed the DNS Protection root certificate?"
            Write-Result ( $_ | Format-Table|Out-String)
            $collectResults['gotDNSProtWelcomePageHTTPS']=$failed
        }
    } else {
        Write-Result "System DNS is not being handled by DNS Protection - skipping this test"
    }
} else {
    Write-Result "System DNS not working - skipping this test"
}
Write-Result "End of test 4`n------"
# Test access to the DNS Protection servers
Write-Result "Test 5a: Checking that direct queries appear to reach DNS Protection servers..."
try {
    $dnsProtectionResponse = Resolve-DnsName -Name "www.zoneedit.com" -Server 193.84.5.5 -ErrorAction Stop
    Write-Result ($dnsProtectionResponse | Format-Table | Out-String) 
    if ($dnsProtectionResponse[0].Name -eq "www.zoneedit.com") {
        Write-Result "Access to DNS Protection server 193.84.5.5 successful"
        $collectResults['reachDNSProt5']=$success
    } else {
        Write-Result "Access to DNS Protection server 193.84.5.5 failed"
        $collectResults['reachDNSProt5']=$failed
    }
}
catch {
    Write-Result "Error accessing DNS Protection servers"
    write-Result ( $_ | Format-Table|Out-String)
    $collectResults['reachDNSProt5']=$failed
}
try {
    $dnsProtectionResponse = Resolve-DnsName -Name "www.zoneedit.com" -Server 193.84.4.4 -ErrorAction Stop
    Write-Result ($dnsProtectionResponse | Format-Table | Out-String) 
    if ($dnsProtectionResponse[0].Name -eq "www.zoneedit.com") {
        Write-Result "Access to DNS Protection server 193.84.4.4 successful"
        $collectResults['reachDNSProt4']=$success
    } else {
        Write-Result "Access to DNS Protection server 193.84.4.4 failed"
        $collectResults['reachDNSProt4']=$failed
    }
}
catch {
    Write-Result "Error accessing DNS Protection servers"
    write-Result ( $_ | Format-Table|Out-String)
    $collectResults['reachDNSProt4']=$failed
}
# Test access to the DNS Protection servers
Write-Result "Test 5b: Checking access to DNS Protection servers from this location..."
try {    
    $dnsProtectionResponse = Resolve-DnsName "www.google.com" -Server 193.84.5.5 -ErrorAction Stop
    Write-Result ($dnsProtectionResponse | Format-Table | Out-String) 
    if ($dnsProtectionResponse[0].Name -eq "www.google.com") {
        Write-Result "Use of DNS Protection from this location appears to be allowed" 
        $collectResults['accessDNSProt']=$success
    } else {
        Write-Result "Use of DNS Protection from this location appears to be allowed" 
        $collectResults['accessDNSProt']=$failed
    }
}
catch {
    Write-Result "Error accessing DNS Protection server at 193.84.5.5" 
    Write-Result ( $_ | Format-Table|Out-String) 
    $collectResults['accessDNSProt']=$failed
}
# Test if the device is actually talking to the DNS Protection servers
Write-Result "Test 5c: Checking that queries to DNS Protection aren't getting redirected..." 
try {
    $dns = Resolve-DnsName -Name "dns.access.sophos.com" -Server "193.84.5.5" -ErrorAction Stop
    Write-Result ($dns | Format-Table | Out-String) 
    # TODO: Check the actual IP if possible
    if( ($dns.Length -gt 0) -and
        ($dns[0].Name -eq "dns.access.sophos.com") -and 
        ($dns[0].Type -eq 'A') ) {
        Write-Result "Queries to DNS Protection are not being redirected" 
        $collectResults['queryRedirection']=$success
    } else {
        Write-Result "Queries to DNS Protection might be redirected" 
        $collectResults['queryRedirection']=$redirect
    }
}
catch {
    Write-Result "Error checking queries to DNS Protection are redirected" 
    Write-Result ( $_ | Format-Table|Out-String) 
    $collectResults['queryRedirection']=$failed
}
Write-Result "End of test 5`n------" 
Write-Result "Test 6: Running a DNS Leak Test using https://bash.ws" 
if($collectResults['systemDNS'] -eq $success) {
    Test-DnsLeaks
} else {
    Write-Result "    Looks like the system DNS is not working. Skipping."
}
Write-Result "End of test 6`n------" 
Write-Result "Test 7a: Checking the apparent source IP address for this location via HTTPS..."
try {
    Invoke-WebRequest -Uri https://api.myip.com -ErrorAction Stop | Write-Result
    }
catch {
    Write-Result "Error checking the apparent source IP via HTTPS" 
    Write-Result ( $_ | Format-Table|Out-String) 
    Write-Result "Trying again with a known IP address $knownIP_api_myip for the service..." 
    Invoke-WebRequest -Uri "https://$knownIP_api_myip/" -Headers @{Host='api.myip.com'} | Write-Result
}

Write-Result "Test 7b: Checking the apparent source IP address via DNS..." 
try {
    Resolve-DnsName -Name myip.opendns.com -Server resolver3.opendns.com -ErrorAction Stop | Write-Result
}
catch {
    Write-Result "Error checking the apparent source IP via DNS"
    write-Result ( $_ | Format-Table|Out-String)
    Write-Result "Trying again with a known resolver IP $knownIP_resolver3_opendns..."
    Resolve-DnsName -Name myip.opendns.com -Server $knownIP_resolver3_opendns | Write-Result
}
Write-Result "End of test 7`n------"

Write-Result "Test 8: Checking DNS query latency"

Write-Result "`nCheck latency to Sophos DNS Protection"
if($collectResults['accessDNSProt'] -eq $success) {
    Test-DNSLatency -testname www.google.com -res 193.84.4.4
} else {
    Write-Result "`nSophos DNS Protection access test failed - skipping"
}

Write-Result "`nCheck latency using system DNS settings"
if($collectResults['systemDNS'] -eq $success) {
    Test-DNSLatency -testname www.sophos.com -res ''
} else {
    Write-Result "`nSystem DNS access test failed - skipping"
}

$region_hostnames = @{
    "PROD0" = "af45696a9d98ae9b5.awsglobalaccelerator.com"
    "PROD1" = "af39f12a3abbc288b.awsglobalaccelerator.com"
    "PROD2" = "a96ba037364f66208.awsglobalaccelerator.com"
    "PROD3" = "a55ca1360a42b9e25.awsglobalaccelerator.com"
    "PROD4" = "a66562e2168e6f91e.awsglobalaccelerator.com"
    "PROD5" = "acec48d591c5f7b0c.awsglobalaccelerator.com"
    "PROD6" = "a28fbfe39bd2d0a91.awsglobalaccelerator.com"
    "PROD7" = "a5cd470aace53e730.awsglobalaccelerator.com"
}

if($collectResults['accessDNSProt'] -eq $success) {
    $region_hostnames.getEnumerator() | Sort-Object -property:Key | ForEach {
        Write-Result "`nCheck latency to Sophos DNS Protection ($($_.key))"
        $ips = Resolve-DnsName -Name $_.value -Type A -Server "193.84.4.4" -DnsOnly -ErrorAction Stop | Select-Object -Property IPAddress
        Test-DNSLatency -testname www.example.com -res $ips[0].IPAddress
    }
} else {
    Write-Result "`nSophos DNS Protection access test failed - skipping"
}

Write-Result "End of test 8`n------"

# Get the device's DNS settings
Write-Result "`nRetrieving the device's DNS settings..."
$i = 0
Get-NetIPInterface | Select-Object -Property ifIndex, AddressFamily, InterfaceMetric | Sort-Object -Property InterfaceMetric | ForEach-Object {
    $i = $i + 1
    $a = $_
    $b = (Get-DnsClientServerAddress -AddressFamily $a.AddressFamily -InterfaceIndex $a.ifIndex)
    $im = $a.InterfaceMetric
    Write-Result "Priority $i (Metric $im):" 
    Write-Output $b | Out-String | Write-Result
}
# Get information about the network interfaces
Write-Result "`nRetrieving information about the network interfaces..." 
ipconfig /all | Write-Result
Write-Result "Summary of test results`n======================="

#Output the test result summary
Write-Result ( $collectResults | Format-Table | Out-String)

#End of tests
Write-Result "Test finished - DNS Diagnostics at $(Get-Date -Format "yyyy-MM-dd hh:mm:ss K")"

if($outputFile -ne "") {
    Write-Result "Test output has been written to $outputFile" 
    notepad $outputFile
} 
