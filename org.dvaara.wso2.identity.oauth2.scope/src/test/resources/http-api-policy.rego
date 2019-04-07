package httpapi.authz

subordinates = {"alice": [], "charlie": [], "bob": ["alice"], "betty": ["charlie"]}

# HTTP API request
import input as http_api
# http_api = {
#   "spiffe_id": "spiffe://example.org/front-end2",
#   "path": ["finance", "salary", "alice"],
#   "scope": clearance2,
#   "user": "alice",
#   "method": "GET"
#   "user_agent": "cURL/1.0"
#   "remote_addr": "127.0.0.1"
#   "iat":2019-02-10 12:27:27.196
# }

default allow = false

# Allow users to get their own salaries.

deny {
  http_api.method = "DELETE"
}

allow {
  http_api.method = "GET"
  http_api.path = ["finance", "salary", username]
  username = http_api.user
}

# Allow managers to get their subordinates' salaries.
allow {
  http_api.method = "GET"
  http_api.path = ["finance", "salary", username]
  http_api.scope = "clearance2"
}

# Allow managers to edit their subordinates' salaries only if the request came from a workload with SPIFFE ID "spiffe://example.org/workload-1"
allow {
  http_api.method = "POST"
  subordinates[http_api.user][_] = username
  http_api.path = ["finance", "salary", username]
  http_api.remote_addr = "127.0.0.1"
  http_api.spiffe_id = "spiffe://example.org/workload-1"
}
