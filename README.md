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
#include "library.h"

int main() {
    // Example usage of LicenseGate class
    std::string userId = "";
    // You can set this to an empty string if you're not using challenges
    std::string publicRsaKey = "";

    // Create an instance of LicenseGate
    LicenseGate licenseGate(userId, publicRsaKey);

    // Optionally enable debugging
    licenseGate.debug();

    // Optionally enable RSA Challenges
    licenseGate.useChallenges();

    // Verify a license key
    std::string licenseKey = "";
    std::string scope = "";
    std::string metadata = "";

    // Call the verify method to validate the license key
    ValidationType validationResult = licenseGate.verify(licenseKey, scope, metadata);

    // Handle the result
    switch (validationResult) {
    case ValidationType::VALID:
        std::cout << "License is valid." << std::endl;
        break;
    case ValidationType::NOT_FOUND:
        std::cout << "License not found." << std::endl;
        break;
    case ValidationType::EXPIRED:
        std::cout << "License has expired." << std::endl;
        break;
        // Add other cases as needed...
    default:
        std::cout << "License validation failed with error." << std::endl;
        break;
    }

    system("pause");
    return 0;
}
```

## ToDo

- Fix RSA Challenges as they dont work properly.
- Add other api functions.
- Make certian functions private to the end user.
