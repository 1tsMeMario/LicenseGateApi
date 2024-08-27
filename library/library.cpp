#include "library.h"

// Constructor
LicenseGate::LicenseGate(const std::string& userId, const std::string& publicRsaKey)
    : userId(userId), publicRsaKey(publicRsaKey) {
    if (!publicRsaKey.empty()) {
        useChallenge = true;
    }
}

LicenseGate& LicenseGate::setPublicRsaKey(const std::string& publicRsaKey) {
    this->publicRsaKey = publicRsaKey;
    return *this;
}

LicenseGate& LicenseGate::setValidationServer(const std::string& validationServer) {
    this->validationServer = validationServer;
    return *this;
}

LicenseGate& LicenseGate::useChallenges() {
    this->useChallenge = true;
    return *this;
}

LicenseGate& LicenseGate::debug() {
    this->debugMode = true;
    return *this;
}

ValidationType LicenseGate::verify(const std::string& licenseKey, const std::string& scope, const std::string& metadata) {
    try {
        std::string challenge = useChallenge ? std::to_string(time(nullptr)) : "";
        std::string url = buildUrl(licenseKey, scope, metadata, challenge);

        // Request server and get JSON response
        json response = requestServer(url);

        // Check if there is an error in the response
        if (response.contains("error") && response["error"].get<bool>()) {
            if (debugMode) std::cout << "Error: " << response["error"].get<std::string>() << std::endl;
            return ValidationType::SERVER_ERROR;
        }

        // Check if the validation failed
        if (response.contains("valid") && !response["valid"].get<bool>()) {
            return mapValidationResult(response["result"].get<std::string>());
        }

        // Handle challenge verification if applicable
        if (useChallenge && response.contains("signedChallenge")) {
            std::string signedChallenge = response["signedChallenge"].get<std::string>();
            if (!verifyChallenge(challenge, signedChallenge)) {
                if (debugMode) std::cout << "Error: Challenge verification failed" << std::endl;
                return ValidationType::FAILED_CHALLENGE;
            }
        }

        return mapValidationResult(response["result"].get<std::string>());
    }
    catch (...) {
        if (debugMode) std::cerr << "Connection Error" << std::endl;
        return ValidationType::CONNECTION_ERROR;
    }
}

bool LicenseGate::verifySimple(const std::string& licenseKey, const std::string& scope, const std::string& metadata) {
    return verify(licenseKey, scope, metadata) == ValidationType::VALID;
}

std::string LicenseGate::buildUrl(const std::string& licenseKey, const std::string& scope, const std::string& metadata, const std::string& challenge) {
    std::string url = validationServer + "/license/" + userId + "/" + licenseKey + "/verify";

    // Construct query parameters for metadata, scope, and challenge
    if (!metadata.empty()) {
        url += "?metadata=" + urlEncode(metadata);
    }

    if (!scope.empty()) {
        if (url.find("?") == std::string::npos) {
            url += "?scope=" + urlEncode(scope);
        }
        else {
            url += "&scope=" + urlEncode(scope);
        }
    }

    if (useChallenge && !challenge.empty()) {
        if (url.find("?") == std::string::npos) {
            url += "?challenge=" + urlEncode(challenge);
        }
        else {
            url += "&challenge=" + urlEncode(challenge);
        }
    }

    return url;
}

json LicenseGate::requestServer(const std::string& url) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        // Parse the JSON response from the server
        if (res == CURLE_OK) {
            return json::parse(readBuffer);
        }
        else {
            throw std::runtime_error("Failed to connect to server");
        }
    }

    return {};
}

size_t LicenseGate::WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t totalSize = size * nmemb;
    userp->append((char*)contents, totalSize);
    return totalSize;
}

std::string LicenseGate::urlEncode(const std::string& value) {
    CURL* curl = curl_easy_init();
    char* output = curl_easy_escape(curl, value.c_str(), value.length());
    std::string encoded(output);
    curl_free(output);
    curl_easy_cleanup(curl);
    return encoded;
}

std::string LicenseGate::base64Decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.data(), encoded.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // Do not add a newline

    char buffer[1024];
    std::string decoded;
    int decodedLength = 0;

    while ((decodedLength = BIO_read(bio, buffer, sizeof(buffer))) > 0) {
        decoded.append(buffer, decodedLength);
    }

    BIO_free_all(bio);
    return decoded;
}

bool LicenseGate::verifyChallenge(const std::string& challenge, const std::string& signedChallengeBase64) {
    try {
        // Decode the base64-encoded signed challenge
        std::string decodedSignature = base64Decode(signedChallengeBase64);

        // Load RSA public key from the PEM format string
        BIO* bio = BIO_new_mem_buf(publicRsaKey.data(), publicRsaKey.size());
        RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);

        if (!rsa) {
            throw std::runtime_error("Failed to load public key");
        }

        // Verify the RSA signature using SHA256
        bool result = RSA_verify(NID_sha256,
            reinterpret_cast<const unsigned char*>(challenge.data()), challenge.size(),
            reinterpret_cast<const unsigned char*>(decodedSignature.data()), decodedSignature.size(), rsa);

        RSA_free(rsa);
        return result;
    }
    catch (...) {
        if (debugMode) std::cerr << "Challenge verification failed" << std::endl;
        return false;
    }
}

ValidationType LicenseGate::mapValidationResult(const std::string& result) {
    if (result == "VALID") return ValidationType::VALID;
    if (result == "NOT_FOUND") return ValidationType::NOT_FOUND;
    if (result == "NOT_ACTIVE") return ValidationType::NOT_ACTIVE;
    if (result == "EXPIRED") return ValidationType::EXPIRED;
    if (result == "LICENSE_SCOPE_FAILED") return ValidationType::LICENSE_SCOPE_FAILED;
    if (result == "IP_LIMIT_EXCEEDED") return ValidationType::IP_LIMIT_EXCEEDED;
    if (result == "RATE_LIMIT_EXCEEDED") return ValidationType::RATE_LIMIT_EXCEEDED;
    if (result == "FAILED_CHALLENGE") return ValidationType::FAILED_CHALLENGE;
    return ValidationType::SERVER_ERROR;
}
