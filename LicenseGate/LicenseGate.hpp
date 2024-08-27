#ifndef LICENSE_GATE_H
#define LICENSE_GATE_H

#include <iostream>
#include <string>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <ctime>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <vector>

using json = nlohmann::json;

class LicenseGate {
private:
    static constexpr const char* DEFAULT_SERVER = "https://api.licensegate.io";
    std::string userId;
    std::string publicRsaKey;
    std::string validationServer = DEFAULT_SERVER;
    bool useChallenges = false;
    bool debug = false;

public:
    LicenseGate(std::string userId);
    LicenseGate(std::string userId, std::string publicRsaKey);

    LicenseGate& setPublicRsaKey(const std::string& publicKey);
    LicenseGate& setValidationServer(const std::string& server);
    LicenseGate& enableChallenges();
    LicenseGate& enableDebug();

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

    int NOT_FOUND = 1;
    int NOT_ACTIVE = 2;
    int EXPIRED = 3;
    int LICENSE_SCOPE_FAILED = 4;
    int IP_LIMIT_EXCEEDED = 5;
    int RATE_LIMIT_EXCEEDED = 6;
    int FAILED_CHALLENGE = 7;
    int SERVER_ERROR = 8;
    int CONNECTION_ERROR = 0;

    ValidationType verify(const std::string& licenseKey);
    ValidationType verify(const std::string& licenseKey, const std::string& scope);
    ValidationType verify(const std::string& licenseKey, const std::string& scope, const std::string& metadata);

    bool verifySimple(const std::string& licenseKey);
    bool verifySimple(const std::string& licenseKey, const std::string& scope);
    bool verifySimple(const std::string& licenseKey, const std::string& scope, const std::string& metadata);

    void exitApplication(const std::string& exitMessage);

private:
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* response);
    std::string buildUrl(const std::string& licenseKey, const std::string& scope, const std::string& metadata, const std::string& challenge);
    json requestServer(const std::string& urlStr);
    bool verifyChallenge(const std::string& challenge, const std::string& signedChallengeBase64);
    ValidationType getValidationType(const std::string& result);
    std::vector<unsigned char> base64_decode(const std::string& input);
};

#endif // LICENSE_GATE_H
