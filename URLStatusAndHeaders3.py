import csv
import requests
import urllib3
import datetime
from urllib.parse import urlparse
import ssl
import socket
import time

count = 0
startTime = datetime.datetime.now()

# Disable SSL certificate verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Open the input and output files
date = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
input_file_path = "/home/anthonyp/Documents/Scripts/Python/URLStatusAndHeaders/WebURLs.txt"
output_file_path = "/home/anthonyp/Documents/Scripts/Python/URLStatusAndHeaders/URL_Header_Checker_Export_" + date + ".csv"

# Write column headers in CSV
with open(input_file_path, "r") as input_file, open(output_file_path, "w", newline="") as output_file:
    csv_writer = csv.writer(output_file)
    csv_writer.writerow(["ID","URL","Initial Full Host" , "Status Code", "Status Description", "Final URL", "Final Full Host" ,"Same?" ,"Redirect", "scheme" ,"hostname" , "port" , "http_version", "Server", "Content Type", "Content Length",  "Content-Security-Policy","X-Content-Type-Options", "Strict-Transport-Security", "Cache-Control", "Expires", "Set-Cookie","X-XSS-Protection", "X-Frame-Options",  "access_control_allow_origin", "referrer_policy", "permissions_policy", "clear_site_data", "feature_policy", "expect_ct", "x_permitted_cross_domain_policies", "cross_origin_embedder_policy", "cross_origin_opener_policy", "cross_origin_resource_policy", "x_powered_by", "ProtocolVersion", "Insecure Redirects", "HTTP Links"])
  
    # Iterate through the input file
    for url in input_file:
        # Clean up the URL
        url = url.strip()
        
        try:
            # Clear variables
            statuscode = ""
            status_description = ""
            history = ""
            server = ""
            content_type = ""
            content_length = ""
            final_url = ""
            csp = ""
            x_content_type_options = ""
            strict_transport_security = ""
            cache_control = ""
            expires = ""
            set_cookie = ""
            x_xss_protection = ""
            x_frame_options = ""
            access_control_allow_origin = ""
            referrer_policy = ""
            permissions_policy = ""
            clear_site_data = ""
            feature_policy = ""
            expect_ct = ""
            x_permitted_cross_domain_policies = ""
            cross_origin_embedder_policy = ""
            cross_origin_opener_policy = ""
            cross_origin_resource_policy = ""
            x_powered_by = ""
            protocol_version = ""
            insecure_redirects = ""
            http_links = ""
            parsed_uri = ""
            scheme = ""
            hostname = ""
            port = ""
            http_version = ""
            Fullhostname = ""
            e = ""
            stripped_url = ""
            parsed_url = ""
            #ssl_context = ""
            insecure_redirects = ""
            http_links = ""
            parsed_uriInitial = ""
            scheme1 = ""
            hostname1 = ""
            Fullhostname1 = ""
            port1 = ""
            same = ""
            
            #get URL hostname and referrer to send in request header
            parsed_url = urlparse(url)
            stripped_url = parsed_url.netloc
            referrer = parsed_url.scheme + "://" + parsed_url.netloc
            
            #Set request headers 
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Encoding":"gzip, deflate, br",
                "Cache-Control":"no-cache",
                "Accept-Language":"en-US,en;q=0.9",
                "Connection":"keep-alive",
                "Pragma":"no-cache",
                "Sec-Ch-Ua-Platform":"Windows",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua":'"Google Chrome";v="113","Chromium";v="113","Not:A-Brand";v="24"',
                "Sec-Fetch-Dest":"document",
                "Sec-Fetch-Mode":"navigate",
                "Sec-Fetch-Site":"none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
                "Referer": referrer,
                "host": stripped_url
                }
            
            # Make a GET request to the URL with SSL validation disabled
            response = requests.get(url, verify=False, allow_redirects=True,headers = headers ,timeout=20)#stream=True
                        
            # Get the status code and response headers
            url =url
            statuscode = response.status_code
            status_description = response.reason
            history = response.history
            server = response.headers.get('Server', "Missing")
            content_type = response.headers.get('Content-Type', "Missing")
            content_length = response.headers.get('Content-Length', "Missing")
            final_url = response.url
            csp = response.headers.get('Content-Security-Policy', "Missing")
            x_content_type_options = response.headers.get('X-Content-Type-Options', "Missing")
            strict_transport_security = response.headers.get('Strict-Transport-Security', "Missing")
            cache_control = response.headers.get('Cache-Control', "Missing")
            expires = response.headers.get('Expires', "OK")
            set_cookie = response.headers.get('Set-Cookie', "OK")
            x_xss_protection = response.headers.get('X-XSS-Protection', "OK")
            x_frame_options = response.headers.get('X-Frame-Options', "Missing")
            access_control_allow_origin = response.headers.get('Access-Control-Allow-Origin', "Missing")
            referrer_policy = response.headers.get('Referrer-Policy', "Missing")
            permissions_policy = response.headers.get('Permissions-Policy', "Missing")
            clear_site_data = response.headers.get('Clear-Site-Data', "Missing")
            feature_policy = response.headers.get('Feature-Policy', "Missing")
            expect_ct = response.headers.get('Expect-CT', "Missing")
            x_permitted_cross_domain_policies = response.headers.get('X-Permitted-Cross-Domain-Policies', "Missing")
            cross_origin_embedder_policy = response.headers.get('Cross-Origin-Embedder-Policy', "Missing")
            cross_origin_opener_policy = response.headers.get('Cross-Origin-Opener-Policy', "Missing")
            cross_origin_resource_policy = response.headers.get('Cross-Origin-Resource-Policy', "Missing")
            x_powered_by = response.headers.get('X-Powered-By', "Missing")
            protocol_version = response.headers.get('ProtocolVersion', "Missing")
            insecure_redirects = False
            http_links = False
            
            #Parse the final URL string
            parsed_uri = urlparse(final_url, scheme='', allow_fragments=True)
            scheme = parsed_uri.scheme
            hostname = parsed_uri.hostname
            Fullhostname = parsed_uri.scheme + "://" + parsed_uri.hostname
            port = parsed_uri.port
            
            #Parse initial URL string
            parsed_uriInitial = urlparse(url, scheme='', allow_fragments=True)
            scheme1 = parsed_uriInitial.scheme
            hostname1 = parsed_uriInitial.hostname
            Fullhostname1 = parsed_uriInitial.scheme + "://" + parsed_uriInitial.hostname
            port1 = parsed_uriInitial.port
            
            http_version = response.raw.version
            #ssl_context = ssl.TLSVersion.name

            #Check if the inital host name is the same as the final host name
            if Fullhostname1 == Fullhostname:
                same = "True"
            else:
                same = "False"
                          

            # Check for insecure redirects
            for resp in response.history:
                if resp.is_redirect and not resp.url.startswith('https:'):
                    insecure_redirects = True
                    break

            # Check for HTTP links in the final URL
            if final_url.startswith('http'):
                response = requests.get(final_url, verify=False)
                if 'http:' in response.text:
                    http_links = True
                        
            # Write the results to the output file
            count = count + 1
            csv_writer.writerow([count,url,Fullhostname1, statuscode, status_description, final_url,Fullhostname,same,history,scheme , hostname , port , http_version, server, content_type, content_length, csp, x_content_type_options, strict_transport_security, cache_control, expires, set_cookie, x_xss_protection, x_frame_options, access_control_allow_origin, referrer_policy, permissions_policy, clear_site_data, feature_policy, expect_ct, x_permitted_cross_domain_policies, cross_origin_embedder_policy, cross_origin_opener_policy, cross_origin_resource_policy, x_powered_by, protocol_version, insecure_redirects, http_links])
                        
            print(count)       
        except Exception as e:
            count = count + 1
            # If there is an error, write the URL and error message to the output file
            csv_writer.writerow([count,url,"N/A",str(e), "N/A","N/A","N/A", "N/A","N/A", "N/A", "N/A","N/A","N/A", "N/A", "N/A", "N/A","N/A", "N/A", "N/A", "N/A","N/A", "N/A", "N/A", "N/A","N/A","N/A", "N/A", "N/A", "N/A","N/A", "N/A", "N/A", "N/A","N/A", "N/A", "N/A", "N/A","N/A"])
                       
            print(count,' Exception')
            
print("Complete.. ",count," records checked.")
print("It took this long to complete: ",datetime.datetime.now() - startTime)
