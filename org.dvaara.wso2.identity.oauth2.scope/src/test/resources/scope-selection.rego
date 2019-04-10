package opa.spiffe

allowed_scopes[s] {
      allow[_].id = s;
      allow[i].scopes = allowed
}

allow  = [
  {
    "id": "spiffe://example.org/wso2-is",
    "scopes": ["clearance3"]
  },
  {
    "id": "spiffe://example.org/workload1",
    "scopes": ["clearance2"]
  },
  {
    "id": "spiffe://example.org/front-end2",
    "scopes": ["clearance1", "clearance2"]
  }
]

{
  "scopes": [
    {
      "id": "spiffe://example.org/wso2-is",
      "scopes": ["clearance3"]
    },
    {
      "id": "spiffe://example.org/workload1",
      "scopes": ["clearance2"]
    },
    {
      "id": "spiffe://example.org/front-end2",
      "scopes": ["clearance1", "clearance2"]
    }
  ]
}