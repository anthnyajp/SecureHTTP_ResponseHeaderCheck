CLS

# Need to ADD or Fix
    # Check for Insecure Redirect
     # Checking each response cookie for secure & https

#-------------
# Script to loop over a list of URLs and export security response headers to csv.
#   INPUT: A txt file with one URL per line
#   
#   OUTPUT: A CSV file with columns for:
#               - RequestURI = the URI from than line in input file
#               - StatusCode = response status code (blank if error code!)
#               - Error = Error message
#
<#
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


#>

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$Date= ((Get-Date).ToString("yyyyMMdd_HHmmss"))

# Update paths to import file and export directory if needed
#$linksFilePath = "C:\Downloads\WebURLs.txt"
#$outCSVPath = "C:\Downloads\URL_Header_Checker_Export_"+$Date+".csv"
$linksFilePath = "$PSScriptRoot\WebURLs.txt"
$outCSVPath = "$PSScriptRoot\URL_Header_Checker_Export_"+$Date+".csv"

get-content $linksFilePath |
 Foreach { $uril = $_; try 
    { 
        Invoke-WebRequest -Uri $uril -Method GET -UseBasicParsing -MaximumRedirection 10 -ErrorAction SilentlyContinue 

    } 
        catch [System.Net.WebException]
        { 
            New-Object -TypeName psobject -Property @{ Error = $_ } 
               
        } 

    } |
    
 Select @{Name="RequestURI";Expression={$uril}},StatusCode, StatusDescription , Error , @{Name="ProtocolVersion";Expression={$_.BaseResponse.ProtocolVersion}} , @{Name="Final_URL";Expression={$_.BaseResponse.ResponseUri.AbsoluteUri}},@{Name="Server";Expression={$_.Headers["Server"]}}, @{Name="Content-Type";Expression={$_.Headers["Content-Type"]}} ,  @{Name="CSP";Expression={$_.Headers["Content-Security-Policy"]}}  ,@{Name="X-Content-Type-Options";Expression={$_.Headers["X-Content-Type-Options"]}} , @{Name="Strict-Transport-Security 31536000";Expression={$_.Headers["Strict-Transport-Security"]}} ,  @{Name="Cache-Control";Expression={$_.Headers["Cache-Control"]}} ,  @{Name="Expires";Expression={$_.Headers["Expires"]}} , @{Name="Set-Cookie";Expression={$_.Headers["Set-Cookie"]}} ,@{Name="X-XSS-Protection";Expression={$_.Headers["X-XSS-Protection"]}} ,  @{Name="X-Frame-Options";Expression={$_.Headers["X-Frame-Options"]}} , @{Name="Access-Control-Allow-Origin";Expression={$_.Headers["Access-Control-Allow-Origin"]}} , @{Name="Referrer-Policy";Expression={$_.Headers["Referrer-Policy"]}} , @{Name="Permission-Policy";Expression={$_.Headers["Permission-Policy"]}} , @{Name="Clear-Site-Data";Expression={$_.Headers["Clear-Site-Data"]}} , @{Name="Feature-Policy";Expression={$_.Headers["Feature-Policy"]}} , @{Name="Expect-CT";Expression={$_.Headers["Expect-CT"]}} , @{Name="X-Permitted-Cross-Domain-Policies";Expression={$_.Headers["X-Permitted-Cross-Domain-Policies"]}} , @{Name="Cross-Origin-Embedder-Policy";Expression={$_.Headers["Cross-Origin-Embedder-Policy"]}} , @{Name="Cross-Origin-Opener-Policy";Expression={$_.Headers["Cross-Origin-Opener-Policy"]}} , @{Name="Cross-Origin-Resource-Policy";Expression={$_.Headers["Cross-Origin-Resource-Policy"]}} , @{Name="Links";Expression={[string]$_.links.href -like "http:*"}}|

 Export-Csv $outCSVPath -NoTypeInformation
