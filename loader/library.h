#ifndef LICENSEGATE_H
#define LICENSEGATE_H

#define OPENSSL_SUPPRESS_DEPRECATED  // Suppress OpenSSL deprecation warnings

#include <iostream>
#include <string>
#include <map>
#include <curl/curl.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Enum for the various validation states
enum class ValidationType {
    VALID,
    NOT_FOUND,
    NOT_ACTIVE,
    EXPIRED,
    LICENSE_SCOPE_FAILED,
    IP_LIMIT_EXCEEDED,
    RATE_LIMIT_EXCEEDED,
    FAILED_CHALLENGE,
    SERVER_ERROR,
    CONNECTION_ERROR
};

// LicenseGate class definition
class LicenseGate {
private:
    static constexpr const char* DEFAULT_SERVER = "https://api.licensegate.io";

    std::string userId;
    std::string publicRsaKey;
    std::string validationServer = DEFAULT_SERVER;
    bool useChallenge = false;
    bool debugMode = false;

public:
    LicenseGate(const std::string& userId, const std::string& publicRsaKey = "");

    LicenseGate& setPublicRsaKey(const std::string& publicRsaKey);
    LicenseGate& setValidationServer(const std::string& validationServer);
    LicenseGate& useChallenges();
    LicenseGate& debug();

    ValidationType verify(const std::string& licenseKey, const std::string& scope = "", const std::string& metadata = "");
    bool verifySimple(const std::string& licenseKey, const std::string& scope = "", const std::string& metadata = "");

private:
    std::string buildUrl(const std::string& licenseKey, const std::string& scope, const std::string& metadata, const std::string& challenge);
    json requestServer(const std::string& url);
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp);
    std::string urlEncode(const std::string& value);
    std::string base64Decode(const std::string& encoded);
    bool verifyChallenge(const std::string& challenge, const std::string& signedChallengeBase64);
    ValidationType mapValidationResult(const std::string& result);
};

#endif // LICENSEGATE_H
