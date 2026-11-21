import QtQuick
import Quickshell
import Quickshell.Io

Item {
    id: root
    implicitWidth: pill.implicitWidth
    implicitHeight: parent ? parent.height : 28

    signal summonOverlay()

    Rectangle {
        id: pill
        anchors.centerIn: parent
        implicitWidth: row.implicitWidth + 16
        height: 22
        radius: 6
        color: mouseArea.containsMouse ? "#2e3440" : "transparent"

        Row {
            id: row
            anchors.centerIn: parent
            spacing: 6

            Text {
                text: "◎"
                color: "#7aa2f7"
                font.pixelSize: 13
                anchors.verticalCenter: parent.verticalCenter
            }

            Text {
                text: "Peek"
                color: "#c0caf5"
                font.pixelSize: 12
                font.weight: Font.Medium
                anchors.verticalCenter: parent.verticalCenter
            }
        }

        MouseArea {
            id: mouseArea
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
                root.summonOverlay()
                summonProc.running = true
            }
        }
    }

    Process {
        id: summonProc
        command: ["omarchy-shell", "shell", "summon", "sonlc.omapeek"]
    }
}
