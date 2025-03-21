# OCTI-vuln2ioc
This python script leverages OpenCTI to collect IOC related to threats targeting specific CVE

# Usage
OPENCTI_URL: edit here the url of your OpenCTI tenant

OPENCTI_TOKEN: edit here the API token of the OpenCTI tenant, actions will be done on behalf of the user, you may want to use a service account

target_label: edit here the list of the labels attached to the vulnerabilities that you want to track (label must exist)

ioc_label: edit here the label that will be applied to the indicator that indicates a threat that targets your vulnerabilities (label must exist)

# Expected Output
The IoC that indicate threats targetting vulnerabilities that have a specific label, will be tagged with the "ioc_label"
You can use this ioc_label as a filter option to push the IoC to detection/block lists
