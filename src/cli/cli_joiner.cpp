/*
 *  Copyright (c) 2019, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file implements a simple CLI for the Joiner role.
 */

#include "cli_joiner.hpp"

#include <inttypes.h>

#include "cli/cli.hpp"
#include "utils/parse_cmdline.hpp"

#if OPENTHREAD_CONFIG_JOINER_ENABLE

namespace ot {
namespace Cli {

constexpr Joiner::Command Joiner::sCommands[];

otError Joiner::ProcessDiscerner(uint8_t aArgsLength, char *aArgs[])
{
    otError error = OT_ERROR_NONE;

    if (aArgsLength == 2)
    {
        otJoinerDiscerner discerner;

        memset(&discerner, 0, sizeof(discerner));
        if (strcmp(aArgs[1], "clear") == 0)
        {
            SuccessOrExit(error = otJoinerSetDiscerner(mInterpreter.mInstance, nullptr));
        }
        else
        {
            VerifyOrExit(OT_ERROR_NONE == Interpreter::ParseJoinerDiscerner(aArgs[1], discerner),
                         error = OT_ERROR_INVALID_ARGS);
            SuccessOrExit(error = otJoinerSetDiscerner(mInterpreter.mInstance, &discerner));
        }
    }
    else if (aArgsLength == 1)
    {
        const otJoinerDiscerner *discerner = otJoinerGetDiscerner(mInterpreter.mInstance);

        VerifyOrExit(discerner != nullptr, error = OT_ERROR_NOT_FOUND);

        mInterpreter.OutputLine("0x%llx/%u", static_cast<unsigned long long>(discerner->mValue), discerner->mLength);
    }
    else
    {
        error = OT_ERROR_INVALID_ARGS;
    }

exit:
    return error;
}

otError Joiner::ProcessHelp(uint8_t aArgsLength, char *aArgs[])
{
    OT_UNUSED_VARIABLE(aArgsLength);
    OT_UNUSED_VARIABLE(aArgs);

    for (const Command &command : sCommands)
    {
        mInterpreter.OutputLine(command.mName);
    }

    return OT_ERROR_NONE;
}

otError Joiner::ProcessId(uint8_t aArgsLength, char *aArgs[])
{
    OT_UNUSED_VARIABLE(aArgsLength);
    OT_UNUSED_VARIABLE(aArgs);

    mInterpreter.OutputExtAddress(*otJoinerGetId(mInterpreter.mInstance));
    mInterpreter.OutputLine("");

    return OT_ERROR_NONE;
}

otError Joiner::ProcessStart(uint8_t aArgsLength, char *aArgs[])
{
    otError     error;
    const char *provisioningUrl = nullptr;

    VerifyOrExit(aArgsLength > 1, error = OT_ERROR_INVALID_ARGS);

    if (aArgsLength > 2)
    {
        provisioningUrl = aArgs[2];
    }

    error = otJoinerStart(mInterpreter.mInstance, aArgs[1], provisioningUrl, PACKAGE_NAME,
                          OPENTHREAD_CONFIG_PLATFORM_INFO, PACKAGE_VERSION, nullptr, &Joiner::HandleCallback, this);

exit:
    return error;
}

#include <openthread/crypto.h>

#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ctr_drbg.h>

#include <stdio.h>

#define TIMEOUT_INTERVAL                   120000

/**
 * CoAP transport configuration.
 * Must be configured by the user.
 */
#define GCP_COAP_SECURE_ENABLED               1
#define GCP_COAP_SECURE_PSK_SECRET            "blah"
#define GCP_COAP_SECURE_PSK_IDENTITY          "test"

/**
 * Google Cloud Platform CoAP server parameters.
 */
#define GCP_COAP_IOT_CORE_SERVER_PORT         5683
#define GCP_COAP_IOT_CORE_SERVER_SECURE_PORT  5684

/**
 * Google Cloud Platform project configuration.
 * Must be configured by the user.
 */
#define GCP_COAP_IOT_CORE_SERVER_ADDRESS      "64:ff9b::23ee:2ab0"
#define GCP_COAP_IOT_CORE_PATH                "gcp"
#define GCP_COAP_IOT_CORE_PROJECT_ID          "project-id"
#define GCP_COAP_IOT_CORE_REGISTRY_ID         "registry-id"
#define GCP_COAP_IOT_CORE_REGION              "us-central1"
#define GCP_COAP_IOT_CORE_PUBLISH             "publishEvent"
#define GCP_COAP_IOT_CORE_CONFIG              "config"

/**
 * Google Cloud Platform device configuration.
 * Must be configured by the user.
 */
#define GCP_COAP_IOT_CORE_DEVICE_ID          "example"
#define GCP_COAP_IOT_CORE_DEVICE_KEY         "-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIEnJqMGMS4hWOMQxzx3xyZQTFgm1gNT9Q6DKsX2y8T7uoAoGCCqGSM49\n\
AwEHoUQDQgAEd3Jlb4FLOZJ51eHxeB+sbwmaPFyhsONTUYNLCLZeC1clkM2vj3aT\n\
YbzzSs/BHl4HToQmvd4Evm5lOUVElhfeRQ==\n\
-----END EC PRIVATE KEY-----"

/**
 * The JSON representation of the header with ES256 algorithm.
 */
#define JWT_HEADER_TYPE_ES256 \
    "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"

/**
 * The maximum size of the JWT signature.
 */
#define JWT_SIGNATURE_SIZE 64

/**
 * The size of key length for ES256.
 */
#define JWT_KEY_LENGTH_ES256 32

/**
 * The JWT delimeter used to separete header, claim and signature.
 *
 */
#define JWT_DELIMETER '.'

#define BUFFER_LENGTH 512

static otError base64_url_encode(uint8_t *p_output, uint16_t *p_output_len, const uint8_t *p_buff, uint16_t length)
{
    otError error = OT_ERROR_NONE;
    int     result;
    size_t  encoded_len = 0;

    result = mbedtls_base64_encode(p_output, *p_output_len, &encoded_len, p_buff, length);

    if (result != 0)
    {
        /////LOG_INF("MBEDTLS b64 encode: %d", result);
        return OT_ERROR_NO_BUFS;
    }

    // JWT uses URI as defined in RFC4648, while mbedtls as is in RFC1421.
    for (uint32_t index = 0; index < encoded_len; index++)
    {
        if (p_output[index] == '+')
        {
            p_output[index] = '-';
        }
        else if (p_output[index] == '/')
        {
            p_output[index] = '_';
        }
        else if (p_output[index] == '=')
        {
            p_output[index] = 0;
            encoded_len  = index;
            break;
        }
    }

    *p_output_len = encoded_len;

    return error;
}

static otError jwt_create(uint8_t       * p_output,
                          uint16_t      * p_output_len,
                          const uint8_t * p_claims,
                          uint16_t        claims_len,
                          const uint8_t * p_private_key,
                          uint16_t        private_key_len)
{
    otError                error = OT_ERROR_NONE;
    uint8_t                hash[32];
    uint8_t                signature[JWT_SIGNATURE_SIZE];
    uint16_t               signature_size    = JWT_SIGNATURE_SIZE;
    uint16_t               output_max_length = *p_output_len;
    uint16_t               length;

    // Encode JWT Header using Base64 URL.
    length = output_max_length;

    error = base64_url_encode(p_output, &length, (const uint8_t *)JWT_HEADER_TYPE_ES256,
                              strlen(JWT_HEADER_TYPE_ES256));
    if (error != OT_ERROR_NONE) {
      /////LOG_INF("jwt header b64 url encode fail: %d, len: %d:%d", error, length, output_max_length);
      return error;
    }

    *p_output_len = length;

    // Append delimiter.
    p_output[*p_output_len] = JWT_DELIMETER;
    *p_output_len += 1;

    // Encode JWT Claim using Base64 URL.
    length = output_max_length - *p_output_len;

    error = base64_url_encode(p_output + *p_output_len, &length, p_claims, claims_len);
    if (error != OT_ERROR_NONE) {
      ///LOG_INF("jwt claim b64 url encode fail");
      return error;
    }

    *p_output_len += length;

    // Create SHA256 Hash from encoded JWT Header and JWT Claim.
    int err = mbedtls_sha256_ret(p_output, *p_output_len, hash, 0);
    if (err != 0) {
      ///LOG_INF("jwt sha256 hash fail encode fail");
      return error;
    }

    // Append delimiter.
    p_output[*p_output_len] = JWT_DELIMETER;
    *p_output_len += 1;

    // Create ECDSA Sign.
    error = otCryptoEcdsaSign(signature, &signature_size, hash, sizeof(hash), p_private_key, private_key_len);
    if (error != OT_ERROR_NONE) {
      ///LOG_INF("jwt ecdsa sign fail");
      return error;
    }

    // Encode JWT Sign using Base64 URL.
    length = output_max_length - *p_output_len;

    error = base64_url_encode(p_output + *p_output_len, &length, signature, signature_size);
    if (error != OT_ERROR_NONE) {
      ///LOG_INF("jwt sign b64 encode fail");
      return error;
    }
    *p_output_len += length;

    return error;
}

otError coap_header_proxy_uri_append(const char * p_action, uint64_t unix_time)
{
    otError error = OT_ERROR_NONE;
    char    jwt[BUFFER_LENGTH];
    char    claims[BUFFER_LENGTH];

    memset(jwt, 0, sizeof(jwt));
    memset(claims, 0, sizeof(claims));

    uint16_t offset = snprintf(jwt, sizeof(jwt), "%s/%s/%s/%s/%s?jwt=",
                               GCP_COAP_IOT_CORE_PROJECT_ID, GCP_COAP_IOT_CORE_REGION,
                               GCP_COAP_IOT_CORE_REGISTRY_ID, GCP_COAP_IOT_CORE_DEVICE_ID,
                               p_action);

    uint16_t output_len = sizeof(jwt) - offset;

    uint64_t timeout = unix_time + (TIMEOUT_INTERVAL/1000) * 2;

    uint16_t length = snprintf(claims, sizeof(claims), "{\"iat\":%lu,\"exp\":%lu,\"aud\":\"%s\"}",
                               (uint32_t)(unix_time), (uint32_t)(timeout), GCP_COAP_IOT_CORE_PROJECT_ID);
    if (length <= 0) {
      ///LOG_INF("json sprintf failed");
      return OT_ERROR_FAILED;
    }

    // strlen for device key +1 for null byte
    error = jwt_create((uint8_t *)&jwt[offset], &output_len, (const uint8_t *)claims, strlen(claims),
                               (const uint8_t *)GCP_COAP_IOT_CORE_DEVICE_KEY, strlen(GCP_COAP_IOT_CORE_DEVICE_KEY) + 1);
    //if (error != OT_ERROR_NONE) {
      ///LOG_INF("jwt create failed: %d", error);
      //return;
    //}
    return error;
}

otError Joiner::ProcessStop(uint8_t aArgsLength, char *aArgs[])
{
    otError error = OT_ERROR_NONE;
    OT_UNUSED_VARIABLE(aArgsLength);
    OT_UNUSED_VARIABLE(aArgs);

    //otJoinerStop(mInterpreter.mInstance);
    const char *action = "abc";
	error = coap_header_proxy_uri_append(action, 123456789);

    return error;
}

otError Joiner::Process(uint8_t aArgsLength, char *aArgs[])
{
    otError        error = OT_ERROR_INVALID_COMMAND;
    const Command *command;

    VerifyOrExit(aArgsLength != 0, IgnoreError(ProcessHelp(0, nullptr)));

    command = Utils::LookupTable::Find(aArgs[0], sCommands);
    VerifyOrExit(command != nullptr);

    error = (this->*command->mHandler)(aArgsLength, aArgs);

exit:
    return error;
}

void Joiner::HandleCallback(otError aError, void *aContext)
{
    static_cast<Joiner *>(aContext)->HandleCallback(aError);
}

void Joiner::HandleCallback(otError aError)
{
    switch (aError)
    {
    case OT_ERROR_NONE:
        mInterpreter.OutputLine("Join success");
        break;

    default:
        mInterpreter.OutputLine("Join failed [%s]", otThreadErrorToString(aError));
        break;
    }
}

} // namespace Cli
} // namespace ot

#endif // OPENTHREAD_CONFIG_JOINER_ENABLE
