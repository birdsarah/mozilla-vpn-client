/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nos_wgquickprocess.h"
#include "logger.h"

#include <QCoreApplication>
#include <QTemporaryDir>
#include <QProcess>

namespace {
  Logger logger(LOG_LINUX, "NosWgQuickProcess");
}

// static
bool NosWgQuickProcess::run(
  Daemon::Op op, const QString& privateKey, const QString& deviceIpv4Address,
  const QString& deviceIpv6Address, const QString& serverIpv4Gateway,
  const QString& serverIpv6Gateway, const QString& serverPublicKey,
  const QString& serverIpv4AddrIn, const QString& serverIpv6AddrIn,
  const QString& allowedIPAddressRanges, int serverPort, bool ipv6Enabled) {
  
  logger.log() << "SAB - 4";

  Q_UNUSED(serverIpv6AddrIn);

  /* THIS SECTION JUST MAKES THE CONFIGURATION FILE */

  QByteArray content;
  content.append("[Interface]\nPrivateKey = ");
  content.append(privateKey.toUtf8());
  content.append("\nAddress = ");
  content.append(deviceIpv4Address.toUtf8());

  if (ipv6Enabled) {
    content.append(", ");
    content.append(deviceIpv6Address.toUtf8());
  }

  content.append("\nDNS = ");
  content.append(serverIpv4Gateway.toUtf8());

  if (ipv6Enabled) {
    content.append(", ");
    content.append(serverIpv6Gateway.toUtf8());
  }

  content.append("\n\n[Peer]\nPublicKey = ");
  content.append(serverPublicKey.toUtf8());
  content.append("\nEndpoint = ");
  content.append(serverIpv4AddrIn.toUtf8());
  content.append(QString(":%1").arg(serverPort).toUtf8());

  /*
  # In theory, we should use the ipv6 endpoint, but wireguard doesn't seem
  # to be happy if there are 2 endpoints.
  if (ipv6Enabled) {
      content.append("\nEndpoint = [");
      content.append(serverIpv6AddrIn);
      content.append(QString("]:%1").arg(serverPort));
  }
  */

  content.append(
      QString("\nAllowedIPs = %1\n").arg(allowedIPAddressRanges).toUtf8());

  QTemporaryDir tmpDir;
  if (!tmpDir.isValid()) {
    qWarning("Cannot create a temporary directory");
    return false;
  }

  QDir dir(tmpDir.path());
  QFile file(dir.filePath(QString("%1.conf").arg(WG_INTERFACE)));
  if (!file.open(QIODevice::ReadWrite)) {
    qWarning("Unable to create a file in the temporary folder");
    return false;
  }

  qint64 written = file.write(content);
  if (written != content.length()) {
    qWarning("Unable to write the whole configuration file");
    return false;
  }

  file.close();




  /* ARE WE UP or DOWN? */

  QStringList arguments;
  arguments.append(op == Daemon::Up ? "up" : "down");
  arguments.append(file.fileName());

  /* RUN PLEASE and then clean-up */

  QString app = "wg-quick";
  logger.log() << "Start:" << app << " - arguments:" << arguments;

  QProcess wgQuickProcess;
  wgQuickProcess.start(app, arguments);

  if (!wgQuickProcess.waitForFinished(-1)) {
    logger.log() << "Error occurred:" << wgQuickProcess.errorString();
    return false;
  }

  logger.log() << "Execution finished" << wgQuickProcess.exitCode();

  logger.log() << "wg-quick stdout:" << Qt::endl
               << qUtf8Printable(wgQuickProcess.readAllStandardOutput())
               << Qt::endl;
  logger.log() << "wg-quick stderr:" << Qt::endl
               << qUtf8Printable(wgQuickProcess.readAllStandardError())
               << Qt::endl;

  return wgQuickProcess.exitCode() == 0;



logger.log() << content;
logger.log() << arguments;



/* PSEUDO CODE */

/* Output from wg-quick stdout
[#] ip link add moz0 type wireguard                                                                                                                                                             
[#] wg setconf moz0 /dev/fd/63                                                                                                                                                                  
[#] ip -4 address add 10.65.40.242/32 dev moz0                                                                                                                                                  
[#] ip -6 address add fc00:bbbb:bbbb:bb01::2:28f1/128 dev moz0                                                                                                                                  
[#] ip link set mtu 1420 up dev moz0                                                                                                                                                            
[#] resolvconf -a tun.moz0 -m 0 -x                                                        
[#] wg set moz0 fwmark 51820                                                              
[#] ip -6 route add ::/0 dev moz0 table 51820        
[#] ip -6 rule add not fwmark 51820 table 51820                                                 
[#] ip -6 rule add table main suppress_prefixlength 0
[#] ip6tables-restore -n                                                                  
[#] ip -4 route add 0.0.0.0/0 dev moz0 table 51820   
[#] ip -4 rule add not fwmark 51820 table 51820 
[#] ip -4 rule add table main suppress_prefixlength 0                                           
[#] sysctl -q net.ipv4.conf.all.src_valid_mark=1   
[#] iptables-restore -n  
*/


// 1. Does moz0 interface already exist. If yes, return. If no, setup.

// 2. add_if `sudo ip link add moz0 type wireguard`  (to delete `sudo ip link delete moz0 type wireguard`)

// 2a. In othercases, fallback to wireguard-go

// 3. set_config `wg setconf moz0 wireguard.conf` - feed in the wireguard config file, which looks like some of this:

/*
[Interface]                                                                                                                       
PrivateKey = qXenc8rn09CYrDBHWHisJsrA2LPC/dsuX2gmfYdCELQ=                                                                                                                                       
Address = 10.65.40.242/32, fc00:bbbb:bbbb:bb01::2:28f1/128                                                                                                                                      
DNS = 10.64.0.1, fc00:bbbb:bbbb:bb01::1                                                                                                                                                         

[Peer]                                          
PublicKey = RwgvGZvXpMbLW8efqCkIWKDoQnm8j/QVytGZNhl3l04=                                        
Endpoint = 198.54.131.146:20697                 
AllowedIPs = 0.0.0.0/0, ::0/0                   
*/
// need to pick out the bits we actually need, not sure what it is yet

// OR https://www.wireguard.com/quickstart/
// wg set moz00 listen-port 51820 private-key /path/to/private-key peer ABCDEF... allowed-ips 192.168.88.0/24 endpoint 209.202.254.14:8172

// 4. For each of the Address: 
// ip $proto address add "$1" dev moz0
// $proto is -4 or -6
// $1 is the address

// 5. Set MTU `ip link set mtu "$MTU" up dev moz0`
// There's logic in the script to pick a default MTU if one isn't provided - seems to be 1420

// 6. Set DNS
// resolvconf -a "$(resolvconf_iface_prefix)$INTERFACE" -m 0 -x (resolvconf -a tun.moz0 -m 0 -x)

// 7. Add routes
// This seems pretty complicated part of updating iptables
/*
[#] wg set moz0 fwmark 51820                                                              
[#] ip -6 route add ::/0 dev moz0 table 51820        
[#] ip -6 rule add not fwmark 51820 table 51820                                                 
[#] ip -6 rule add table main suppress_prefixlength 0
[#] ip6tables-restore -n                                                                  
[#] ip -4 route add 0.0.0.0/0 dev moz0 table 51820   
[#] ip -4 rule add not fwmark 51820 table 51820 
[#] ip -4 rule add table main suppress_prefixlength 0                                           
[#] sysctl -q net.ipv4.conf.all.src_valid_mark=1   
[#] iptables-restore -n  
*/



/* On down

[#] ip -4 rule delete table 51820
[#] ip -4 rule delete table main suppress_prefixlength 0
[#] ip -6 rule delete table 51820
[#] ip -6 rule delete table main suppress_prefixlength 0
[#] ip link delete dev moz0
[#] resolvconf -d tun.moz0 -f
[#] iptables-restore -n
[#] ip6tables-restore -n

*/

  return true;  
}
