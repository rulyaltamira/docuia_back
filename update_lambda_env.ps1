# Update Lambda environment variables
$envVars = @{
    "Variables" = @{
        "TENANTS_TABLE" = "docpilot-newsystem-v2-tenants-dev"
        "USERS_TABLE" = "docpilot-newsystem-v2-users-dev"
        "CONTRACTS_TABLE" = "docpilot-newsystem-v2-contracts-dev"
        "ALERTS_TABLE" = "docpilot-newsystem-v2-alerts-dev"
        "ALERT_RULES_TABLE" = "docpilot-newsystem-v2-alert-rules-dev" 
        "ALERT_PREFERENCES_TABLE" = "docpilot-newsystem-v2-alert-preferences-dev"
        "MAIN_BUCKET" = "docpilot-newsystem-v2-main-dev"
        "SES_BUCKET" = "docpilot-newsystem-v2-ses-dev"
        "USER_POOL_ID" = "eu-west-1_U76ZEVpde"
        "DEBUG" = "true"
    }
}

# Convert to JSON
$envJson = ConvertTo-Json -InputObject $envVars -Compress

# Write the JSON to a file
Set-Content -Path env.json -Value $envJson

# Update the Lambda function
Write-Host "Updating Lambda function environment variables..."
aws lambda update-function-configuration --function-name docpilot-newsystem-v2-dev-tenantOnboarding --environment file://env.json 