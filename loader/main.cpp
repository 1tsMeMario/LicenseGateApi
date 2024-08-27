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
