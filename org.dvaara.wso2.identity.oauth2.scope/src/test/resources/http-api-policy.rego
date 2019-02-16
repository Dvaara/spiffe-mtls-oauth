package httpapi.authz

# HTTP API request
import input as http_api
# http_api = {
#   "spiffe-id": "spiffe://example.org/front-end2",
#   "path": ["finance", "salary", "alice"],
#   "user": "alice",
#   "method": "GET"
#   "user_agent": "cURL/1.0"
#   "remote_addr": "127.0.0.1"
#   "iat":2019-02-10 12:27:27.196
# }

default allow = false

# Allow users to get their own salaries.

allow {
  http_api.method = "GET"
}

allow {
  http_api.method = "GET"
  http_api.path = ["finance", "salary", username]
  username = http_api.user
}

allow {
  http_api.method = "GET"
  http_api.path = ["finance2", "salary", username]
  username = http_api.user
}

# Allow managers to get their subordinates' salaries.
allow {
  http_api.method = "GET"
  http_api.path = ["finance", "salary", username]
}

# Allow managers to edit their subordinates' salaries only if the request came from user agent cURL and address 127.0.0.1.
allow {
  http_api.method = "POST"
  http_api.path = ["finance", "salary", username]
  http_api.remote_addr = "127.0.0.1"
  http_api.user_agent = "curl/7.47.0"
}