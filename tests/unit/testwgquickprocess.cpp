/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "testwgquickprocess.h"
#include "../../src/wgquickprocess.h"

#include "helper.h"

const QString privateKey = "94gVOw6mDbX7KKBC8Pyr6q5PwaaX/nM0MDspJFVqthtf=";
const QString deviceIpv4Address= "10.2.33.4/32";
const QString deviceIpv6Address= "2001:db8::2:1/128";
const QString serverIpv4Gateway= "10.2.0.1";
const QString serverIpv6Gateway= "::1/128";
const QString serverPublicKey= "83fVOw6mDbX7KKBC8Pyr6q5PwaaX/nM0MDspJFVqtgrj=";
const QString serverIpv4AddrIn= "10.2.33.4/32";
const QString serverIpv6AddrIn= "2001:db8:a0b:12f0::1";
const QString allowedIPAddressRanges= "0.0.0.0/0, ::0/0";
int serverPort = 4444;
bool ipv6Enabled = true;


void TestWgQuickProcess::validateTrue() {
    QVERIFY2(
        WgQuickProcess::validateWgArgs(privateKey, deviceIpv4Address, deviceIpv6Address,
        serverIpv4Gateway, serverIpv6Gateway, serverPublicKey, serverIpv4AddrIn, serverIpv6AddrIn, 
        allowedIPAddressRanges, serverPort, ipv6Enabled),
        "Valid arguments did not pass validation."
    );
}

void TestWgQuickProcess::validateFalse() { 
    const QString invalidAllowedIPAddressRanges = "0.0.0.0/0, \n ::0/0";
    QVERIFY2(
        !WgQuickProcess::validateWgArgs(privateKey, deviceIpv4Address, deviceIpv6Address,
        serverIpv4Gateway, serverIpv6Gateway, serverPublicKey, serverIpv4AddrIn, serverIpv6AddrIn, 
        invalidAllowedIPAddressRanges, serverPort, ipv6Enabled),
        "invalid allowed ip address ranges unexpectedly passed validation."
    );
    // TODO - We could validate all arguments
    // However, we may get rid of the conf file all together so not doing it for now.
}