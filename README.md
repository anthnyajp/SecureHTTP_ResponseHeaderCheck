# SecureHTTP_ResponseHeaderCheck
PowerShell script that will take a list of URL's as import and export csv with secure headers if found. Also includes redirects.

To run: 
Copy file "WebURLs.txt" to "C:\Downloads\"
Run PowerShell scirpt "URLstatusAndHeaders.ps1"
Check output CSV file at: C:\Downloads\TestURLexport2.csv


**Currently getting error with Get-UrlRedirection. 

Error = Get-UrlRedirection : Exception calling "GetResponse" with "0" argument(s): "The operation has timed out"
