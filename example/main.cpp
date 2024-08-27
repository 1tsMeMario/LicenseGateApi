#include <LicenseGate.hpp>
#include <XorStr.hpp>
#include <iostream>

int main() {
    // Example usage of LicenseGate class
    std::string userId = xorstr_("a1d77"); // Replace with actual user ID
    std::string licenseKey = xorstr_("d395fd0d-73bb-4dfd-b480-ad6cff1dc69d"); // Replace with actual license key
    std::string scope = xorstr_(""); // Optional: Replace with actual scope
    std::string metadata = xorstr_(""); // Optional: Replace with actual metadata

    std::string publicRsaKey; // Optional: Replace with actual metadata
    publicRsaKey += xorstr_("-----BEGIN PUBLIC KEY-----\n");
    publicRsaKey += xorstr_("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn2oUURYHrzS7sV1OuNhl\n");
    publicRsaKey += xorstr_("3VfWLjt1n4MfI8YI3JjdodwADY8lMz7wA7HmBH1uju5t9ELch1N44yNvYAaVeI5d\n");
    publicRsaKey += xorstr_("ayRRzewxoYxV7uv01j3VYacjg46mxzdLAuWDLqB2m8ilWbmW2LNCxNQVK34Z4oNO\n");
    publicRsaKey += xorstr_("//h4bFcslr/przr7xVhvq7VJAbrM3ykMLPArE0+1E6Z0Xy3gP120fBb+lCpoIJDF\n");
    publicRsaKey += xorstr_("8LIpDrCVymH70+zvvq1OnEKFtnCihNFIzN9DF4GA6slJbewfld0l7DayA14ioYGY\n");
    publicRsaKey += xorstr_("Q6emHKVrbSTJYvZkD9RcaE6e5dA2h1g53XYVVc6Rl82jtTcADMDILfhSelLaKZ2S\n");
    publicRsaKey += xorstr_("ZwIDAQAB\n");
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
