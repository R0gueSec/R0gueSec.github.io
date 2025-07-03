# Scenario 3: Potential Impossible Travel

# Part 1: Create Alert Rule (Potential Impossible Travel)

## KQL Query to Detect Impossible Travel

```powershell
// Locate Instances of Potential Impossible Travel
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed

```

## MITRE ATT&CK TTPs:

```powershell
The Impossible Travel KQL query is best aligned with:

T1078 – Valid Accounts (most directly),

T1550 – Alternate Authentication Material, and

T1090 – Proxy (as a technique to obscure true origin).

These mappings are useful for:

Tagging incidents in Sentinel with ATT&CK IDs,

Automating response workflows (e.g., disable account, trigger MFA),

Reporting and compliance (e.g., MITRE-aligned dashboards).

Let me know if you'd like a Markdown or JSON version to include in your IR notes.
```

![image](/assets/img/bluelabs/potential-impossible-travel/image.png)

![image](/assets/img/bluelabs/potential-impossible-travel/image1.png)

![image](/assets/img/bluelabs/potential-impossible-travel/image2.png)

![image](/assets/img/bluelabs/potential-impossible-travel/image3.png)

The Detection Rule is Triggered

![image](/assets/img/bluelabs/potential-impossible-travel/image4.png)

![image](/assets/img/bluelabs/potential-impossible-travel/image5.png)

![image](/assets/img/bluelabs/potential-impossible-travel/image6.png)

![image](/assets/img/bluelabs/potential-impossible-travel/image7.png)

![image](/assets/img/bluelabs/potential-impossible-travel/image8.png)

Entities:

```powershell
Entities (9)
 9f70b6b2ead907b656636d76ba0e504891f1d33097ba8d30cf1f955ab91f00d3@roguecorp.com
 162e30755bc9a3e7dde8edf2a52dfa9340fbaa344c6758d2ecb5ae7836d3dadd@roguecorp.com
 a9d973022d30582f4e23c56d3352b4722011bcb45fb5c7445ac6ae0002542086@roguecorp.com
 06d32e153b231f2f9f2e0a499827f300aafa1b5096815a5837b32f34d6f267df@roguecorp.com
 47e6322353e0e93adfcb5a7dcb9966df7ab17529a7e33267ebb5e469fa555254@roguecorp.com
 9c9ecf443bab503c2016bba334a806279b07532911585da6a5b76432bb6877df@roguecorp.com
 431810045c6e1a565df4a5992d2743312a030b2a6465647eb081ffc8d2bb9a15@roguecorp.com
 05052212485141aa60d9344755217508aa48c758dff6d0061c43cb6366ac7fb9@roguecorp.com
 eeb5d3da95689a0b777d86e0de3b2249137f3e56797825349376f183a79bd7c7@roguecorp.com

```

The KQL Query finds one of the nine entities is the biggest repeat offender:

```powershell
// Locate Instances of Potential Impossible Travel
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

![image](/assets/img/bluelabs/potential-impossible-travel/image9.png)

This KQL Query finds out which locations the most offending entity has logged in from since the last 7 days:

```powershell
let TimePeriodThreshold = timespan(7d);
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == "eeb5d3da95689a0b777d86e0de3b2249137f3e56797825349376f183a79bd7c7@roguecorp.com"
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
```

![image](/assets/img/bluelabs/potential-impossible-travel/image10.png)

I make a KQL Query to search for signin locations of the past 7 days of all the top 9 entities:

```powershell
let TimePeriodThreshold = timespan(7d);
let TargetUsers = dynamic([
  "9f70b6b2ead907b656636d76ba0e504891f1d33097ba8d30cf1f955ab91f00d3@roguecorp.com",
  "162e30755bc9a3e7dde8edf2a52dfa9340fbaa344c6758d2ecb5ae7836d3dadd@roguecorp.com",
  "a9d973022d30582f4e23c56d3352b4722011bcb45fb5c7445ac6ae0002542086@roguecorp.com",
  "06d32e153b231f2f9f2e0a499827f300aafa1b5096815a5837b32f34d6f267df@roguecorp.com",
  "47e6322353e0e93adfcb5a7dcb9966df7ab17529a7e33267ebb5e469fa555254@roguecorp.com",
  "9c9ecf443bab503c2016bba334a806279b07532911585da6a5b76432bb6877df@roguecorp.com",
  "431810045c6e1a565df4a5992d2743312a030b2a6465647eb081ffc8d2bb9a15@roguecorp.com",
  "05052212485141aa60d9344755217508aa48c758dff6d0061c43cb6366ac7fb9@roguecorp.com",
  "eeb5d3da95689a0b777d86e0de3b2249137f3e56797825349376f183a79bd7c7@roguecorp.com"
]);
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName in (TargetUsers)
| extend City = tostring(parse_json(LocationDetails).city),
         State = tostring(parse_json(LocationDetails).state),
         Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project TimeGenerated, UserPrincipalName, UserId, City, State, Country
| order by UserPrincipalName, TimeGenerated desc
```

![image](/assets/img/bluelabs/potential-impossible-travel/image11.png)

 User “[9c9ecf443bab503c2016bba334a806279b07532911585da6a5b76432bb6877df@roguecorp.com](mailto:9c9ecf443bab503c2016bba334a806279b07532911585da6a5b76432bb6877df@roguecorp.com)” logged in from Diamond Bar, California at 6/28/2025, 2:39:33.104 AM and then logged in again from Trenton, New Jersey at 6/28/2025, 4:17:38.575 AM. 

That is a distance of 2,713 miles.

![image](/assets/img/bluelabs/potential-impossible-travel/image12.png)

# Containment, Eradication, and Recovery

We can disable the user’s account:

![image](/assets/img/bluelabs/potential-impossible-travel/image13.png)

Perhaps the user is using a VPN. 

We may inspect the user’s data AzureActivity log to see if any suspicious activity is found. The user’s VM will also be inspected for unusual activity. 

The case was elevated to Tier II and management will discuss with the user if the user has done anything that would explain the impossible travel.

# Post-Incident Activities

We can create a geo-fencing activity within Azure that prevents logins outside of certain regions.

I updated the Activity Log:

![image](/assets/img/bluelabs/potential-impossible-travel/image14.png)

![image](/assets/img/bluelabs/potential-impossible-travel/image15.png)

```powershell
True Positive - Suspicious Activity

We will investigate the user's activities further. The user's management team will discuss with the user about the impossible travel and report the user's response to us. We may disable the user's account if need be. 
```
