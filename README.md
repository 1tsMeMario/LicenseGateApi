# License Gate Api Wrapper for C++

## Installation
Build project using VS 2022. first time building you will have error building the loader. simply move the .lib into the loader folder and include in project.

To install LicenseGate Wrapper, simply include the library.h header and static lib in your project

## Dependencies

- Nlohmann Json
- LibCurl
- OpenSSL

## Example Usages

```c++
#include <LicenseGate.hpp>
#include <XorStr.hpp>
#include <iostream>

int main() {
    // Example usage of LicenseGate class
    std::string userId = xorstr_(""); // Replace with actual user ID
    std::string licenseKey = xorstr_(""); // Replace with actual license key
    std::string scope = xorstr_(""); // Optional: Replace with actual scope
    std::string metadata = xorstr_(""); // Optional: Replace with actual metadata

    std::string publicRsaKey;
    publicRsaKey += xorstr_("-----BEGIN PUBLIC KEY-----\n");
    publicRsaKey += xorstr_("MIIBIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIBCgKCAgEAy1nD2QpN/zjv7dbG1HId\n");
    publicRsaKey += xorstr_("9h2UZUfjWq5+6ZPVtOGrnixLkHo8E/YG1cWEqlvs1QeXEYPfekBGD+5ZejV5CJrN\n");
    publicRsaKey += xorstr_("BuZkCdN5Q3oI2StUbF1KK2DVEUarZ69Tg6rbLkzQ8gLXI22dGaM3uyTLQ8BVS4uA\n");
    publicRsaKey += xorstr_("VZcgJJ0XaQWm4rKwWlGHkPVYhO+YW2AXwxHhJJZhcjxXPge/zfnJ2UYBJG1yFgm6\n");
    publicRsaKey += xorstr_("CUkctCCOkFV3KKmjkKHdMfUP2wXONOGJ2L77cMm9tONfCjMZqWNY0TpHlzrPq3vg\n");
    publicRsaKey += xorstr_("IUsPFG/VntHlUkd+UBHtxOzpFfwll8X1qpdNv2uecPX5nDykGZgKRx5J3T+wa3He\n");
    publicRsaKey += xorstr_("vQF0qgNTAtxBOHgTbHaGrZTJt0CrfwOsBZ7F1RrCvI9tslvsV4URurZdX1Z8Eqnp\n");
    publicRsaKey += xorstr_("ZoLzPgpdXodGhdZcgDNtdlMX65kTxOzN6FsPN5MtnbkeFoLXwvCHKwIDAQAB\n");
    publicRsaKey += xorstr_("-----END PUBLIC KEY-----\n");



    // Initialize LicenseGate with userId and optional public RSA key
    LicenseGate licenseGate(userId, publicRsaKey);

    // Optional: Set additional parameters
    licenseGate.setValidationServer("https://api.licensegate.io");
    licenseGate.enableChallenges(); // If you want to enable challenges
    licenseGate.enableDebug(); // If you want debug information

    // Verify the license
    LicenseGate::ValidationType result = licenseGate.verify(licenseKey, scope, metadata);

    // Handle the result
    switch (result) {
    case LicenseGate::ValidationType::VALID:
        std::cout << xorstr_("License is valid.") << std::endl;
        break;
    case LicenseGate::ValidationType::NOT_FOUND:
        licenseGate.exitApplication(xorstr_("License not found."));
        break;
    case LicenseGate::ValidationType::NOT_ACTIVE:
        licenseGate.exitApplication(xorstr_("License not active."));
        break;
    case LicenseGate::ValidationType::EXPIRED:
        licenseGate.exitApplication(xorstr_("License expired."));
        break;
    case LicenseGate::ValidationType::LICENSE_SCOPE_FAILED:
        licenseGate.exitApplication(xorstr_("License scope failed."));
        break;
    case LicenseGate::ValidationType::IP_LIMIT_EXCEEDED:
        licenseGate.exitApplication(xorstr_("IP limit exceeded."));
        break;
    case LicenseGate::ValidationType::RATE_LIMIT_EXCEEDED:
        licenseGate.exitApplication(xorstr_("Rate limit exceeded."));
        break;
    case LicenseGate::ValidationType::FAILED_CHALLENGE:
        licenseGate.exitApplication(xorstr_("Failed challenge."));
        break;
    case LicenseGate::ValidationType::SERVER_ERROR:
        licenseGate.exitApplication(xorstr_("Server error."));
        break;
    case LicenseGate::ValidationType::CONNECTION_ERROR:
        licenseGate.exitApplication(xorstr_("Connection error."));
        break;
    default:
        licenseGate.exitApplication(xorstr_("Unknown validation result."));
        break;
    }

    return 0;
}

```
