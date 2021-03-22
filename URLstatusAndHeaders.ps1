#-------------
# Script to loop over a list of URLs, make a HTTP HEAD request and check for (first) 200 response
#   INPUT: A txt file with one URL per line
#   
#   OUTPUT: A CSV file with columns for:
#               - RequestURI = the URI from than line in input file
#               - StatusCode = response status code (blank if error code!)
#               - Error = Error message (for 404 or 500 errors)
#

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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$Date= ((Get-Date).ToString("yyyyMMdd_HHmmss"))

$linksFilePath = "C:\Downloads\WebURLs.txt"
$outCSVPath = "C:\Downloads\URL_Header_Checker_Export_"+$Date+".csv"

get-content $linksFilePath |
 Foreach { $uril = $_; try 
    { 
        Invoke-WebRequest -Uri $uril -Method GET -MaximumRedirection 10 -ErrorAction SilentlyContinue -UseBasicParsing
        #$Final = [System.Net.HttpWebRequest]::Create($uril).GetResponse().ResponseUri.AbsoluteUri
        #$Redirect = IF ($uril -eq $Final) {$Final} 
           # Else{Get-UrlRedirection -Enumerate $uril}
    } 
        catch 
        { 
            New-Object -TypeName psobject -Property @{ Error = $_ } 
        } 
    } |
 Select @{Name="RequestURI";Expression={$uril}}, StatusCode, @{Name="Location";Expression={$Location}}, Error , @{Name="Server";Expression={$_.Headers["Server"]}} , @{Name="CSP";Expression={$_.Headers["Content-Security-Policy"]}}  ,@{Name="X-Content-Type-Options";Expression={$_.Headers["X-Content-Type-Options"]}} , @{Name="Strict-Transport-Security";Expression={$_.Headers["Strict-Transport-Security"]}} , @{Name="Cache-Control";Expression={$_.Headers["Cache-Control"]}} , @{Name="Set-Cookie";Expression={$_.Headers["Set-Cookie"]}} , @{Name="Expires";Expression={$_.Headers["Expires"]}} , @{Name="X-XSS-Protection";Expression={$_.Headers["X-XSS-Protection"]}} , @{Name="X-Frame-Options";Expression={$_.Headers["X-Frame-Options"]}} , @{Name="Referrer-Policy";Expression={$_.Headers["Referrer-Policy"]}} , @{Name="Clear-Site-Data";Expression={$_.Headers["Clear-Site-Data"]}} , @{Name="Feature-Policy";Expression={$_.Headers["Feature-Policy"]}} , @{Name="Expect-CT";Expression={$_.Headers["Expect-CT"]}} , @{Name="X-Permitted-Cross-Domain-Policies";Expression={$_.Headers["X-Permitted-Cross-Domain-Policies"]}} , @{Name="Cross-Origin-Embedder-Policy";Expression={$_.Headers["Cross-Origin-Embedder-Policy"]}} , @{Name="Cross-Origin-Opener-Policy";Expression={$_.Headers["Cross-Origin-Opener-Policy"]}} , @{Name="Cross-Origin-Resource-Policy";Expression={$_.Headers["Cross-Origin-Resource-Policy"]}}|
 Export-Csv $outCSVPath


 ## --- URL Redirections FUNCTION -- ####

  
<#  ## Currently Not working ##

Function Get-UrlRedirection {
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory, ValueFromPipeline)] [Uri] $Url,
    [switch] $Enumerate,
    [int] $MaxRedirections = 10 # Use same default as [System.Net.HttpWebRequest]
  )

  process {
    try {

      if ($Enumerate) { # Enumerate the whole redirection chain, from input URL to ultimate target,
                        # assuming the max. count of redirects is not exceeded.
        # We must walk the chain of redirections one by one.
        # If we disallow redirections, .GetResponse() fails and we must examine
        # the exception's .Response object to get the redirect target.
        $nextUrl = $Url
        $urls = @( $nextUrl.AbsoluteUri ) # Start with the input Uri
        $ultimateFound = $false
        # Note: We add an extra loop iteration so we can determine whether
        #       the ultimate target URL was reached or not.
        foreach($i in 1..$($MaxRedirections+1)) {
          Write-Verbose "Examining: $nextUrl"
          $request = [System.Net.HttpWebRequest]::Create($nextUrl)
          $request.AllowAutoRedirect = $False
          try {
            $response = $request.GetResponse()
            # Note: In .NET *Core* the .GetResponse() for a redirected resource
            #       with .AllowAutoRedirect -eq $False throws an *exception*.
            #       We only get here on *Windows*, with the full .NET Framework.
            #       We either have the ultimate target URL, or a redirection
            #       whose target URL is reflected in .Headers['Location']
            #       !! Syntax `.Headers.Location` does NOT work.
            $nextUrlStr = $response.Headers['Location']
            $response.Close()
            # If the ultimate target URL was reached (it was already
            # recorded in the previous iteration), and if so, simply exit the loop.
            if (-not $nextUrlStr) {
              $ultimateFound = $true
              break
            }
          } catch [System.Net.WebException] {
            # The presence of a 'Location' header implies that the
            # exception must have been triggered by a HTTP redirection 
            # status code (3xx). 
            # $_.Exception.Response.StatusCode contains the specific code
            # (as an enumeration value that can be case to [int]), if needed.
            # !! Syntax `.Headers.Location` does NOT work.
            $nextUrlStr = try { $_.Exception.Response.Headers['Location'] } catch {}
            # Not being able to get a target URL implies that an unexpected
            # error ocurred: re-throw it.
            if (-not $nextUrlStr) { Throw }
          }
          Write-Verbose "Raw target: $nextUrlStr"
          if ($nextUrlStr -match '^https?:') { # absolute URL
            $nextUrl = $prevUrl = [Uri] $nextUrlStr
          } else { # URL without scheme and server component
            $nextUrl = $prevUrl = [Uri] ($prevUrl.Scheme + '://' + $prevUrl.Authority + $nextUrlStr)
          }
          if ($i -le $MaxRedirections) { $urls += $nextUrl.AbsoluteUri }          
        }
        # Output the array of URLs (chain of redirections) as a *single* object.
        Write-Output -NoEnumerate $urls
        if (-not $ultimateFound) { Write-Warning "Enumeration of $Url redirections ended before reaching the ultimate target." }

      } else { # Resolve just to the ultimate target,
                # assuming the max. count of redirects is not exceeded.

                # Note that .AllowAutoRedirect defaults to $True.
        # This will fail, if there are more redirections than the specified 
        # or default maximum.
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.timeout = 120000; # 2minutes
        if ($PSBoundParameters.ContainsKey('MaxRedirections')) {
          $request.MaximumAutomaticRedirections = $MaxRedirections
        }
        $response = $request.GetResponse()
        # Output the ultimate target URL.
        # If no redirection was involved, this is the same as the input URL.
        $response.ResponseUri.AbsoluteUri
        $response.Close()

       }

      } catch {
        Write-Error $_ # Report the exception as a non-terminating error.
    }
  } # process

}
#>
