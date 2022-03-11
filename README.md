# zeek_to_wildfire
Send Extracted Files from Zeek to Palo Alto  WildFire Sandbox (Private Cloud) and get Notice

## Description

This Zeek script detects the filetypes that Palo Alto WildFire Sandbox(Private Cloud) can analyse and check the HASH if it malicious or benign
If the hash value doesn't exists in WildFire's Database it automatically submits the file to the sandbox for analysis and re-checks for the verdict

If any malicious file found it creates a Zeek Notice Log.

## Installation
Just load the script in your `local.zeek` and change the configuration values for your Wildfire IP and your API-KEY 

```
# Load the script to Zeek
@load <path-to-script>/wildfire.zeek

#change the configuration values
redef WildFireSandbox::API_KEY = "your-wildfire-api-key";
redef WildFireSandbox::WILDFIRE_SERVER = "https://your-wildfire-ip";
```

Optionally you can change the followings
```
# If you dont want to check the validity of the wildfire certificate - (value: bool)
redef WildFireSandbox::VERIFY_TLS = F;

# This value says to Zeek in which interval will recheck the hash if the verdict was
# Pending (Wildfire code: -100) or after file submission (Wildfire code: -102) - (value: interval)
redef WildFireSandbox::sleep_interval = 2min;
```


