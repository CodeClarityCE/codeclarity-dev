#!/bin/bash

projectName="cr0hn/vulnerable-node"
analyzerName="JavaScript%20Analyzer"
branchName="master"

# Load environment variables from cicd.env file
. ./cicd.env
email=${EMAIL}
password=${PASSWORD}
domain=${DOMAIN}

# AUTHENTICATE: the API sets the sign-in as cookies, which curl keeps in a cookie jar.
jar=$(mktemp)
trap 'rm -f "$jar"' EXIT
curl -X 'POST' \
    'https://'$domain'/api/auth/authenticate' \
    -s \
    -c "$jar" \
    -H 'accept: application/json' \
    -H 'Content-Type: application/json' \
    -d '{
  "email": "'$email'",
  "password": "'$password'"
}' >/dev/null

# RETRIEVE USER
curl -X 'GET' \
    'https://'$domain'/api/auth/user' \
    -s \
    -H 'accept: application/json' \
    -b "$jar" -H 'X-CodeClarity-CSRF: 1' >response.json

userId=$(jq -r '.data.id' ./response.json)
userFirstName=$(jq -r '.data.first_name' ./response.json)
userLastName=$(jq -r '.data.last_name' ./response.json)

echo "You are connected with: $userFirstName $userLastName ($userId)"

# RETRIEVE USER'S ORGANIZATIONS
curl -X 'GET' \
    'https://'$domain'/api/org' \
    -s \
    -H 'accept: application/json' \
    -b "$jar" -H 'X-CodeClarity-CSRF: 1' >response.json

organizationID=$(jq -r '.data[0].organization.id' ./response.json)
echo $organizationID

# RETRIEVE ORGANIZATIONS'S PROJECTS
curl -X 'GET' \
    "https://$domain/api/org/$organizationID/projects?search_key=$projectName" \
    -s \
    -H 'accept: application/json' \
    -b "$jar" -H 'X-CodeClarity-CSRF: 1' >response.json

projectID=$(jq -r '.data[0].id' ./response.json)
echo $projectID

# RETRIEVE ANALYZER
curl -X 'GET' \
    "https://$domain/api/org/$organizationID/analyzers/name?analyzer_name=$analyzerName" \
    -s \
    -H 'accept: application/json' \
    -b "$jar" -H 'X-CodeClarity-CSRF: 1' >response.json

analyzerID=$(jq -r '.data.id' ./response.json)
echo $analyzerID

# CREATE ANALYSIS
curl -X 'POST' \
    "https://$domain/api/org/$organizationID/projects/$projectID/analyses" \
    -s \
    -H 'accept: application/json' \
    -H 'Content-Type: application/json' \
    -b "$jar" -H 'X-CodeClarity-CSRF: 1' \
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
