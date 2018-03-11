# MvcAuthentication
Custom authentication policy for Mvc. The authentication action is registered as a mvc authorization filter, which would be executed immediately after the route system determines which controller and action to proceed.

The execution priority can be referred [here](https://docs.microsoft.com/en-us/aspnet/core/mvc/controllers/filters).

## Configuration
Add json section to your configuration for CAS usage:
```json
{
    "cas": {
        "redirectUrl": "",
        "validateUrl": "",
        "sessionName": "CAS_LOGIN"
    }
}
```

## Usage
The authentication service can be used in two ways:
1) add `AuthenticationRequired` attribute to your action or controller.
2) acquire the `IAuthenticationService` by DI and perform authentication actions.

`AuthenticationTest` provides samples about the detail.