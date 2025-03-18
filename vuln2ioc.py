from pycti import OpenCTIApiClient
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
OPENCTI_URL = 'https://xyz.filigran.io/graphql'
OPENCTI_TOKEN = 'XYZ-1234-ABCD-AZERTY'
opencti_client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN, ssl_verify=False)

target_label = ["tenable", "windows"]
ioc_label = ["vuln2ioc"]

list_label = opencti_client.label.list(
    filters= {
		  "mode": "and",
			 "filters": [
		    { "key" : "value",
		      "values": target_label
		    }
		  ],
		  "filterGroups": [],
	  },
)

list_label_q= []
for j, item_label in enumerate(list_label, start=1):
#    print(item_label["id"])
    list_label_q.append(item_label["id"])    

ioc_label_id = opencti_client.label.list(
    filters= {
		  "mode": "and",
			 "filters": [
		    { "key" : "value",
		      "values": ioc_label
		    }
		  ],
		  "filterGroups": [],
	  },
)


CVE_with_tag = opencti_client.vulnerability.list(
    filters= {
    "mode": "and",
    "filters": [
      {
        "key": "entity_type",
        "values": [
          "Vulnerability"
        ],
        "operator": "eq",
        "mode": "or"
      }
    ],
    "filterGroups": [
      {
        "mode": "and",
        "filters": [
          {
            "key": "objectLabel",
            "values": list_label_q,
            "operator": "eq",
            "mode": "or"
          }
        ],
        "filterGroups": []
      }
    ]
  }
)
list_cve = []
for i, item_CVE in enumerate(CVE_with_tag, start=1):
    list_cve.append(item_CVE["id"])
#    print(item_CVE["name"])

threats_with_cve = opencti_client.stix_domain_object.list( 
  filters= {
    "mode": "and",
    "filters": [
      {
        "key": "entity_type",
        "values": [
          "malware", 
          "threat-actor",
          "threat-actor-group",
          "intrusion-set",
          "campaign"
        ],
        "operator": "eq",
        "mode": "or"
      },
      {
        "key": "regardingOf",
        "values": [
          {
            "key": "relationship_type",
            "values": [
              "targets",
              "exploits"
            ]
          },
          {
            "key": "id",
            "values": list_cve
          }
        ],
        "operator": "eq",
        "mode": "or"
      }
    ],
    "filterGroups": []
  }
)

list_threats = []
for j, item_threat in enumerate(threats_with_cve, start=1):
    list_threats.append(item_threat["id"])
#    print(item_threat["name"])


ioc_with_CVE = opencti_client.indicator.list(filters={
    "mode": "and",
    "filters": [
      {
        "key": "revoked",
        "values": [
          "false"
        ],
        "operator": "eq",
        "mode": "or"
      },
      {
        "key": "regardingOf",
        "values": [
          {
            "key": "relationship_type",
            "values": [
              "indicates"
            ]
          },
          {
            "key": "id",
            "values": list_threats
          }
        ],
        "operator": "eq",
        "mode": "or"
      }
    ],
    "filterGroups": []
})
for k, item_ioc in enumerate(ioc_with_CVE, start=1):
    opencti_client.stix_domain_object.add_label(id=item_ioc["id"],label_id=ioc_label_id[0]["id"])
#    print(item_ioc["name"])
