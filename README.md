# central-tools

Small tools to handle Central sessions/data structures.
Edit `central_config.py` and specify the cluster name and username to access.


## centralsession.py

This is the main class required by most of the scripts in this repository.
It manages Central UI/API sessions and API tokens.

It has following advantages to [pycentral](https://github.com/aruba/pycentral) SDK.

1. You do not need to specify Access Token/Client ID/Client Secret etc to access Central API.
   The main class CentralSession will take care of it automatically.
2. pycentral does not support generating token if company SSO is used because Central's oauth API does not support SSO.
   This library can generate tokens even with company domain account. 
3. This library provides I/F to access Central NMS Application, as well as Central API.
   NMS app provides more comprehensive view of customer's network.
4. This library provides an interface compatible with pycentral. You can use this class interchangeably with pycentral.
5. pycentral creates token cache file per customer ID/client ID. This library stores tokens to single file.

If directly called it will test an API and return the result.

#### Syntax
```
  centralsession.py [--debug|--info]
```

### How to use CentralSession class
You can create Central session either of below:

1. Create a configuration file named 'central_config.py' and call create_session_from_config()
2. Call the constructor of CentralSession class

Example for 1:
```
#  Save this as central_config.py
#  Only 'instance' and 'username' are mandatory. Other parameters can be blank or omitted.
instance = 'apac-1'
username = 'ksasaki@arubanetworks.com'
password = 'aruba12345'     # optional
customer_id = 'a93e95c9a2434f9ea0c5c0359db91f73'    # optional
app_name = 'api-test-script'    # optional
```
How to use:
```
    import centralsession

    central = centralsession.create_session_from_config()
    resp = central.apiGet(
        endpoint="/configuration/v2/groups",
        params={
            "limit": 20,
            "offset": 0
        })
    print(resp.text)
```

Example for 2:
```
    import centralsession

    central = centralsession.CentralSession("apac-1", "ksasaki@arubanetworks.com", password="aruba12345")
    resp = central.apiGet(
        endpoint="/configuration/v2/groups",
        params={
            "limit": 20,
            "offset": 0
        })
    print(resp.text)
```

#### Interfaces
```
    central.apiGet(endpoint, *args, **kwargs):
```
Send GET request to Central API.

```
    central.apiPost(endpoint, *args, **kwargs):
```
Send POST request to Central API.

```
    central.apiReq(method, endpoint, *args, **kwargs):
```
Send arbitrary request to Central API.

```
    central.nmsGet(endpoint, *args, **kwargs):
```
Send GET request to Central NMS app.

```
    central.nmsPost(endpoint, *args, **kwargs):
```
Send POST request to Central NMS app.

```
    central.command(self, apiMethod, apiPath, apiData={}, apiParams={},
                headers={}, files={}, retry_api_call=True):
```
This interface provides the same syntax as pycentral.

#### Run pycentral samples
Just replace the constructor calls in pycentral sample scripts as below.

```
    from pycentral.base import ArubaCentralBase
    central = ArubaCentralBase(central_info=central_info,
                           ssl_verify=ssl_verify)
```
Replace above lines with below:
```
    from centralsession import create_session_from_config 
    central = create_session_from_config()
```
and put your Central username and instance name to `central_config.py`
