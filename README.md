# zeek_to_wildfire
Send Extracted Files from Zeek to Palo Alto  WildFire Sandbox (Private Cloud) and get Notice

## Description

This Zeek script detects the filetypes that Palo Alto WildFire Sandbox(Private Cloud) can analyse and check the HASH if it malicious or benign
If the hash value doesn't exists in WildFire's Database it automatically submits the file to the sandbox for analysis and re-checks for the verdict

If any malicious file found it creates a Zeek Notice Log.

## How it works

- Zeek creates SHA256 File hash and extracts the files that are supported from PA Wildfire.
- Send the hash to WildFire and gets the verdict. If it is malicious it creates a notice
- If the hash it is not known to wildfire, Zeek submits the file to Wildfire.
- Check every 2 min (in case of Pending state), for verdict.
- If verdict is malicious then it creates a notice.

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
# If you dont want to check the validity of the wildfire certificate - (value: bool) (default: T)
redef WildFireSandbox::VERIFY_TLS = F;

# This value says to Zeek in which interval will recheck the hash if the verdict was
# Pending (Wildfire code: -100) or after file submission (Wildfire code: -102) - (value: interval) (default: 30sec)
redef WildFireSandbox::sleep_interval = 2min;
# Change Max retries of recheck (value: count) (default: 10)
redef WildFireSandbox::max_count = 10;
```


