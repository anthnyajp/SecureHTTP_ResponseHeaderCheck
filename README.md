# SecureHTTP_ResponseHeaderCheck
PowerShell script that will take a list of URL's as import and export csv with secure headers if found. Also includes redirects.

To run: 
- Copy file "WebURLs.txt" to "C:\Downloads\" (Update file with your list of URL's)
- Run PowerShell script "URLstatusAndHeaders.ps1"
- Check output CSV file at: C:\Downloads\URL_Header_Checker_Export_"+$Date+".csv
