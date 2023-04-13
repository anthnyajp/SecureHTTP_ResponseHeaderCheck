import csv
import requests
import urllib3
import datetime

# Disable SSL certificate verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Open the input and output files
date = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
input_file_path = "WebURLs.txt"
output_file_path = "URL_Header_Checker_Export_" + date + ".csv"

with open(input_file_path, "r") as input_file, open(output_file_path, "w", newline="") as output_file:
    csv_writer = csv.writer(output_file)
    csv_writer.writerow(["URL", "Status Code", "Status Description", "Server", "Content Type", "Content Length", "Final URL", "Content-Security-Policy","X-Content-Type-Options", "Strict-Transport-Security", "Cache-Control", "Expires", "Set-Cookie","X-XSS-Protection", "X-Frame-Options",  "access_control_allow_origin", "referrer_policy", "permissions_policy", "clear_site_data", "feature_policy", "expect_ct", "x_permitted_cross_domain_policies", "cross_origin_embedder_policy", "cross_origin_opener_policy", "cross_origin_resource_policy", "x_powered_by", "ProtocolVersion", "links"])
  
    # Iterate through the input file
    for url in input_file:
        # Clean up the URL
        url = url.strip()
        
        try:
            # Make a GET request to the URL with SSL validation disabled
            response = requests.get(url, verify=False)
            
            # Get the status code and response headers
            url =url
            status_code = response.status_code
            status_description = response.reason
            server = response.headers.get('Server', '')
            content_type = response.headers.get('Content-Type', '')
            content_length = response.headers.get('Content-Length', '')
            final_url = response.url
            csp = response.headers.get('Content-Security-Policy', '')
            x_content_type_options = response.headers.get('X-Content-Type-Options', '')
            strict_transport_security = response.headers.get('Strict-Transport-Security', '')
            cache_control = response.headers.get('Cache-Control', '')
            expires = response.headers.get('Expires', '')
            set_cookie = response.headers.get('Set-Cookie', '')
            x_xss_protection = response.headers.get('X-XSS-Protection', '')
            x_frame_options = response.headers.get('X-Frame-Options', '')
            access_control_allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
            referrer_policy = response.headers.get('Referrer-Policy', '')
            permissions_policy = response.headers.get('Permissions-Policy', '')
            clear_site_data = response.headers.get('Clear-Site-Data', '')
            feature_policy = response.headers.get('Feature-Policy', '')
            expect_ct = response.headers.get('Expect-CT', '')
            x_permitted_cross_domain_policies = response.headers.get('X-Permitted-Cross-Domain-Policies', '')
            cross_origin_embedder_policy = response.headers.get('Cross-Origin-Embedder-Policy', '')
            cross_origin_opener_policy = response.headers.get('Cross-Origin-Opener-Policy', '')
            cross_origin_resource_policy = response.headers.get('Cross-Origin-Resource-Policy', '')
            x_powered_by = response.headers.get('X-Powered-By', '')
            protocol_version = response.headers.get('ProtocolVersion', "")
            links = response.headers.get('Links', '')
                        
            # Write the results to the output file
            csv_writer.writerow([url, status_code, status_description, server, content_type, content_length, final_url, csp, x_content_type_options, strict_transport_security, cache_control, expires, set_cookie, x_xss_protection, x_frame_options, access_control_allow_origin, referrer_policy, permissions_policy, clear_site_data, feature_policy, expect_ct, x_permitted_cross_domain_policies, cross_origin_embedder_policy, cross_origin_opener_policy, cross_origin_resource_policy, x_powered_by, protocol_version, links])
                   
        except Exception as e:
            # If there is an error, write the URL and error message to the output file
            csv_writer.writerow([url, str(e), '','', '', '', '','', '', '', '','', '', '', '','', '', '', '','', '', '', '','', '', '', '',''])