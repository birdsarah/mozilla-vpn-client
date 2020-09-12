import QtQuick 2.0
import Mozilla.VPN 1.0

import "../themes/themes.js" as Theme

// VPNStabilityLabelAction
ParallelAnimation {
    property var connectionStatus: VPNConnectionHealth.stability
    property bool isConnectionUnstable: connectionStatus === VPNConnectionHealth.Unstable

    PropertyAction {
        target: stabilityLabel
        property: "text"
        value: isConnectionUnstable ? qsTr("Unstable") : qsTr("No Signal")
    }
    PropertyAction {
        target: warningIcon
        property: "source"
        value: isConnectionUnstable ? "../resources/warning-orange.svg" : "../resources/warning.svg"
    }
    PropertyAction {
        target: stabilityLabel
        property: "color"
        value: isConnectionUnstable ? Theme.orange : Theme.red
    }
}