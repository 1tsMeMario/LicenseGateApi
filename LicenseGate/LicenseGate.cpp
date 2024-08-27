#include "LicenseGate.hpp"
#include "XorStr.hpp"

LicenseGate::LicenseGate(std::string userId) : userId(std::move(userId)) {}

LicenseGate::LicenseGate(std::string userId, std::string publicRsaKey)
    : userId(std::move(userId)), publicRsaKey(std::move(publicRsaKey)), useChallenges(true) {}

LicenseGate& LicenseGate::setPublicRsaKey(const std::string& publicKey) {
    publicRsaKey = publicKey;
    return *this;
}

LicenseGate& LicenseGate::setValidationServer(const std::string& server) {
    validationServer = server;
    return *this;
}

LicenseGate& LicenseGate::enableChallenges() {
    useChallenges = true;
    return *this;
}

LicenseGate& LicenseGate::enableDebug() {
    debug = true;
    return *this;
}

LicenseGate::ValidationType LicenseGate::verify(const std::string& licenseKey) {
    return verify(licenseKey, "", "");
}

LicenseGate::ValidationType LicenseGate::verify(const std::string& licenseKey, const std::string& scope) {
    return verify(licenseKey, scope, "");
}

LicenseGate::ValidationType LicenseGate::verify(const std::string& licenseKey, const std::string& scope, const std::string& metadata) {
    try {
        std::string challenge = useChallenges ? std::to_string(std::time(nullptr)) : "";
        json response = requestServer(buildUrl(licenseKey, scope, metadata, challenge));

        if (response.contains(xorstr_("error")) || !response.contains(xorstr_("result"))) {
            if (debug) std::cout << xorstr_("Error: ") << response[xorstr_("error")] << std::endl;
            return ValidationType::SERVER_ERROR;
        }

        if (response.contains(xorstr_("valid")) && !response[xorstr_("valid")].get<bool>()) {
            ValidationType result = getValidationType(response[xorstr_("result")].get<std::string>());
            return result != ValidationType::VALID ? result : ValidationType::SERVER_ERROR;
        }

        if (useChallenges && !verifyChallenge(challenge, response[xorstr_("signedChallenge")].get<std::string>())) {
            if (debug) std::cout << xorstr_("Error: Challenge verification failed") << std::endl;
            return ValidationType::FAILED_CHALLENGE;
        }

        return getValidationType(response[xorstr_("result")].get<std::string>());
    }
    catch (...) {
        return ValidationType::CONNECTION_ERROR;
    }
}

bool LicenseGate::verifySimple(const std::string& licenseKey) {
    return verify(licenseKey) == ValidationType::VALID;
}

bool LicenseGate::verifySimple(const std::string& licenseKey, const std::string& scope) {
    return verify(licenseKey, scope) == ValidationType::VALID;
}

bool LicenseGate::verifySimple(const std::string& licenseKey, const std::string& scope, const std::string& metadata) {
    return verify(licenseKey, scope, metadata) == ValidationType::VALID;
}

std::string sanitizeExitMessage(const std::string& message) {
    std::string sanitizedMessage;
    // Copy only alphanumeric characters and spaces to sanitizedMessage
    std::copy_if(message.begin(), message.end(), std::back_inserter(sanitizedMessage), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || std::isspace(static_cast<unsigned char>(c));
        });
    return sanitizedMessage;
}

void LicenseGate::exitApplication(const std::string& exitMessage)
{
    system(("start cmd /C \"color 4 && title Error && echo " + sanitizeExitMessage(exitMessage) + " && timeout /t 5 > NUL\"").c_str());
    exit(0);
}

size_t LicenseGate::WriteCallback(void* contents, size_t size, size_t nmemb, std::string* response) {
    size_t totalSize = size * nmemb;
    response->append((char*)contents, totalSize);
    return totalSize;
}

std::string LicenseGate::buildUrl(const std::string& licenseKey, const std::string& scope, const std::string& metadata, const std::string& challenge) {
    std::string queryString;

    CURL* curl = curl_easy_init();
    if (curl) {
        if (!metadata.empty()) {
            char* encodedMetadata = curl_easy_escape(curl, metadata.c_str(), metadata.size());
            queryString += xorstr_("?metadata=") + std::string(encodedMetadata);
            curl_free(encodedMetadata);
        }
        if (!scope.empty()) {
            char* encodedScope = curl_easy_escape(curl, scope.c_str(), scope.size());
            queryString += (queryString.empty() ? xorstr_("?") : xorstr_("&")) + std::string(xorstr_("scope=")) + std::string(encodedScope);
            curl_free(encodedScope);
        }
        if (useChallenges && !challenge.empty()) {
            char* encodedChallenge = curl_easy_escape(curl, challenge.c_str(), challenge.size());
            queryString += (queryString.empty() ? xorstr_("?") : xorstr_("&")) + std::string(xorstr_("challenge=")) + std::string(encodedChallenge);
            curl_free(encodedChallenge);
        }

        curl_easy_cleanup(curl);
    }

    return validationServer + xorstr_("/license/") + userId + xorstr_("/") + licenseKey + xorstr_("/verify") + queryString;
}

json LicenseGate::requestServer(const std::string& urlStr) {
    CURL* curl;
    CURLcode res;
    std::string responseStr;

    curl = curl_easy_init();
    if (!curl) throw std::runtime_error(xorstr_("Failed to initialize CURL"));

    curl_easy_setopt(curl, CURLOPT_URL, urlStr.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseStr);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) throw std::runtime_error(xorstr_("Failed to perform HTTP request"));

    if (debug) std::cout << xorstr_("Response: ") << responseStr << std::endl;

    return json::parse(responseStr);
}

bool LicenseGate::verifyChallenge(const std::string& challenge, const std::string& signedChallengeBase64) {
    std::vector<unsigned char> signedChallenge = base64_decode(signedChallengeBase64);

    BIO* bio = BIO_new_mem_buf((void*)publicRsaKey.c_str(), -1);
    EVP_PKEY* evp_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!evp_key) {
        if (debug) std::cerr << xorstr_("Error reading public key: ") << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        if (debug) std::cerr << xorstr_("Error creating EVP_MD_CTX: ") << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_free(evp_key);
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, evp_key) <= 0) {
        if (debug) std::cerr << xorstr_("Error initializing DigestVerify: ") << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(evp_key);
        return false;
    }

    int result = EVP_DigestVerify(ctx, signedChallenge.data(), signedChallenge.size(),
        (const unsigned char*)challenge.c_str(), challenge.size());

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(evp_key);

    if (result == 1) {
        if (debug) std::cout << xorstr_("Signature verification succeeded!") << std::endl;
        return true;
    }
    else {
        if (debug) std::cerr << "Signature verification failed: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }
}

LicenseGate::ValidationType LicenseGate::getValidationType(const std::string& result) {
    if (result == xorstr_("VALID")) return ValidationType::VALID;
    else if (result == xorstr_("NOT_FOUND")) return ValidationType::NOT_FOUND;
    else if (result == xorstr_("NOT_ACTIVE")) return ValidationType::NOT_ACTIVE;
    return ValidationType::SERVER_ERROR;
}

std::vector<unsigned char> LicenseGate::base64_decode(const std::string& encoded) {
    BIO* bio, * b64;
    size_t decodeLen = (encoded.size() * 3) / 4;
    std::vector<unsigned char> decoded(decodeLen);

    bio = BIO_new_mem_buf(encoded.data(), -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    decodeLen = BIO_read(bio, decoded.data(), encoded.size());
    decoded.resize(decodeLen);

    BIO_free_all(bio);
    return decoded;
}
