#!/bin/bash

projectName="cr0hn/vulnerable-node"
analyzerName="JavaScript%20Analyzer"
branchName="master"

# Load environment variables from cicd.env file
. ./cicd.env
email=${EMAIL}
password=${PASSWORD}
domain=${DOMAIN}

# AUTHENTICATE
curl -X 'POST' \
    'https://'$domain'/api/auth/authenticate' \
    --insecure \
    -s \
    -H 'accept: application/json' \
    -H 'Content-Type: application/json' \
    -d '{
  "email": "'$email'",
  "password": "'$password'"
}' >./auth_tokens.json

# Extract the tokens and expiration times
token=$(jq -r '.data.token' ./auth_tokens.json)
refresh_token=$(jq -r '.data.refresh_token' ./auth_tokens.json)
token_expiry=$(jq -r '.data.token_expiry' ./auth_tokens.json)
refresh_token_expiry=$(jq -r '.data.refresh_token_expiry' ./auth_tokens.json)

# Clean up the temporary file
rm ./auth_tokens.json

# RETRIEVE USER
curl -X 'GET' \
    'https://'$domain'/api/auth/user' \
    --insecure \
    -s \
    -H 'accept: application/json' \
    -H "Authorization: Bearer $token" >response.json

userId=$(jq -r '.data.id' ./response.json)
userFirstName=$(jq -r '.data.first_name' ./response.json)
userLastName=$(jq -r '.data.last_name' ./response.json)

echo "You are connected with: $userFirstName $userLastName ($userId)"

# RETRIEVE USER'S ORGANIZATIONS
curl -X 'GET' \
    'https://'$domain'/api/org' \
    --insecure \
    -s \
    -H 'accept: application/json' \
    -H "Authorization: Bearer $token" >response.json

organizationID=$(jq -r '.data[0].organization.id' ./response.json)
echo $organizationID

# RETRIEVE ORGANIZATIONS'S PROJECTS
curl -X 'GET' \
    "https://$domain/api/org/$organizationID/projects?search_key=$projectName" \
    --insecure \
    -s \
    -H 'accept: application/json' \
    -H "Authorization: Bearer $token" >response.json

projectID=$(jq -r '.data[0].id' ./response.json)
echo $projectID

# RETRIEVE ANALYZER
curl -X 'GET' \
    "https://$domain/api/org/$organizationID/analyzers/name?analyzer_name=$analyzerName" \
    --insecure \
    -s \
    -H 'accept: application/json' \
    -H "Authorization: Bearer $token" >response.json

analyzerID=$(jq -r '.data.id' ./response.json)
echo $analyzerID

# RETRIEVE ANALYZER
curl -X 'POST' \
    "https://$domain/api/org/$organizationID/projects/$projectID/analyses" \
    --insecure \
    -s \
    -H 'accept: application/json' \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $token" \
-d '{
    "analyzer_id": "'$analyzerID'",
    "branch": "'$branchName'",
    "config": {
        "js-sbom": {
            "branch": "'$branchName'",
            "project": "'$organizationID'/projects/'$projectID'/'$branchName'"
        },
        "js-license": {
            "licensePolicy": [
                ""
            ]
        }
    }
}' >response.json

status=$(jq -r '.status' ./response.json)
echo $status

# Clean up the temporary file
rm ./response.json
