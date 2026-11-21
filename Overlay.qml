import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io

Item {
    id: root
    anchors.fill: parent
    focus: true

    property string pluginDir: Qt.resolvedUrl(".").toString().replace("file://", "")
    property string targetPath: ""
    property var inspectData: null
    property string errorText: ""
    property bool showSafetyDetails: true

    signal closeRequested()

    // Theme tokens (Omarchy Quattro defaults — Tokyo Night palette)
    readonly property color bgScrim: "#aa0b0e14"
    readonly property color bgSurface: "#1a1b26"
    readonly property color bgElevated: "#24283b"
    readonly property color borderSubtle: "#3b4261"
    readonly property color textPrimary: "#c0caf5"
    readonly property color textMuted: "#7982a9"
    readonly property color accentColor: "#7aa2f7"
    readonly property color safeColor: "#9ece6a"
    readonly property color cautionColor: "#e0af68"
    readonly property color dangerColor: "#f7768e"

    function safetyColor(verdict) {
        if (verdict === "danger") return dangerColor
        if (verdict === "caution") return cautionColor
        return safeColor
    }

    function loadFile(path) {
        targetPath = path
        errorText = ""
        inspectData = null
        inspectProc.command = [pluginDir + "/bin/omapeek-inspect", path]
        inspectProc.running = true
    }

    Component.onCompleted: {
        readTargetProc.running = true
    }

    Keys.onPressed: (event) => {
        if (event.key === Qt.Key_Escape || event.key === Qt.Key_Space) {
            closeRequested()
            event.accepted = true
        } else if (event.key === Qt.Key_S) {
            showSafetyDetails = !showSafetyDetails
            event.accepted = true
        }
    }

    Process {
        id: readTargetProc
        command: ["sh", "-c", "cat \"${XDG_RUNTIME_DIR:-/tmp}/omapeek/target\" 2>/dev/null || wl-paste -n 2>/dev/null || true"]
        stdout: SplitParser {
            onRead: (line) => {
                const p = line.trim()
                if (p.length > 0) root.loadFile(p)
            }
        }
    }

    Process {
        id: inspectProc
        property string buffer: ""
        onStarted: buffer = ""
        stdout: SplitParser {
            splitMarker: ""
            onRead: (chunk) => { inspectProc.buffer += chunk }
        }
        onExited: (exitCode) => {
            if (exitCode === 0) {
                try {
                    root.inspectData = JSON.parse(inspectProc.buffer)
                } catch (e) {
                    root.errorText = "Failed to parse inspector output: " + e
                }
            } else {
                root.errorText = "Unable to inspect file: " + root.targetPath
            }
        }
    }

    Process {
        id: openDefaultProc
        command: ["xdg-open", root.targetPath]
    }

    // Dimmed backdrop
    Rectangle {
        anchors.fill: parent
        color: root.bgScrim

        MouseArea {
            anchors.fill: parent
            onClicked: root.closeRequested()
        }
    }

    // Centered Quick Look Modal
    Rectangle {
        id: modal
        width: Math.min(parent.width * 0.78, 980)
        height: Math.min(parent.height * 0.82, 720)
        anchors.centerIn: parent
        radius: 14
        color: root.bgSurface
        border.color: root.borderSubtle
        border.width: 1
        clip: true

        MouseArea { anchors.fill: parent } // block backdrop click-through

        ColumnLayout {
            anchors.fill: parent
            spacing: 0

            // Header bar
            Rectangle {
                Layout.fillWidth: true
                height: 52
                color: root.bgElevated

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 18
                    anchors.rightMargin: 18
                    spacing: 12

                    Text {
                        text: root.inspectData ? root.inspectData.meta.name : "OmaPeek"
                        color: root.textPrimary
                        font.pixelSize: 15
                        font.weight: Font.DemiBold
                        elide: Text.ElideMiddle
                        Layout.fillWidth: true
                    }

                    Text {
                        visible: root.inspectData !== null
                        text: root.inspectData
                              ? (root.inspectData.meta.size_human + " · " + root.inspectData.kind.toUpperCase())
                              : ""
                        color: root.textMuted
                        font.pixelSize: 12
                    }

                    // Safety badge pill
                    Rectangle {
                        visible: root.inspectData !== null
                        radius: 6
                        height: 26
                        implicitWidth: badgeText.implicitWidth + 18
                        color: Qt.rgba(
                            root.safetyColor(root.inspectData ? root.inspectData.safety.verdict : "safe").r,
                            root.safetyColor(root.inspectData ? root.inspectData.safety.verdict : "safe").g,
                            root.safetyColor(root.inspectData ? root.inspectData.safety.verdict : "safe").b,
                            0.18
                        )
                        border.color: root.safetyColor(root.inspectData ? root.inspectData.safety.verdict : "safe")
                        border.width: 1

                        Text {
                            id: badgeText
                            anchors.centerIn: parent
                            text: root.inspectData
                                  ? (root.inspectData.safety.verdict.toUpperCase() + " (" + root.inspectData.safety.score + "/100)")
                                  : ""
                            color: root.safetyColor(root.inspectData ? root.inspectData.safety.verdict : "safe")
                            font.pixelSize: 11
                            font.weight: Font.Bold
                        }

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: root.showSafetyDetails = !root.showSafetyDetails
                        }
                    }
                }
            }

            // Safety findings banner (auto-expanded when caution/danger)
            Rectangle {
                visible: root.inspectData !== null && root.showSafetyDetails && root.inspectData.safety.findings.length > 0
                Layout.fillWidth: true
                implicitHeight: findingsCol.implicitHeight + 20
                color: "#1f1c28"

                ColumnLayout {
                    id: findingsCol
                    anchors.fill: parent
                    anchors.margins: 12
                    spacing: 6

                    Repeater {
                        model: root.inspectData ? root.inspectData.safety.findings : []
                        delegate: RowLayout {
                            Layout.fillWidth: true
                            spacing: 8
                            Text {
                                text: "[" + modelData.severity.toUpperCase() + "]"
                                color: modelData.severity === "high" ? root.dangerColor
                                     : modelData.severity === "medium" ? root.cautionColor
                                     : root.accentColor
                                font.pixelSize: 11
                                font.weight: Font.Bold
                            }
                            Text {
                                text: modelData.title + " — " + modelData.detail
                                color: root.textPrimary
                                font.pixelSize: 12
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }
                    }
                }
            }

            // Main Preview Content Area
            Item {
                Layout.fillWidth: true
                Layout.fillHeight: true

                // Error state
                Text {
                    visible: root.errorText.length > 0
                    anchors.centerIn: parent
                    text: root.errorText
                    color: root.dangerColor
                    font.pixelSize: 14
                }

                // Image preview
                Image {
                    visible: root.inspectData && root.inspectData.kind === "image"
                    anchors.fill: parent
                    anchors.margins: 20
                    source: visible ? ("file://" + root.inspectData.meta.path) : ""
                    fillMode: Image.PreserveAspectFit
                    asynchronous: true
                }

                // Code / Markdown preview
                ScrollView {
                    visible: root.inspectData && (root.inspectData.kind === "code" || root.inspectData.kind === "markdown")
                    anchors.fill: parent
                    anchors.margins: 16
                    clip: true

                    TextArea {
                        readOnly: true
                        text: visible ? root.inspectData.preview.content : ""
                        color: root.textPrimary
                        font.family: "JetBrains Mono, monospace"
                        font.pixelSize: 13
                        background: null
                        wrapMode: TextArea.NoWrap
                    }
                }

                // Archive / ZIP preview
                ListView {
                    visible: root.inspectData && root.inspectData.kind === "archive"
                    anchors.fill: parent
                    anchors.margins: 16
                    clip: true
                    spacing: 4
                    model: visible ? root.inspectData.preview.entries : []

                    delegate: Rectangle {
                        width: ListView.view.width
                        height: 30
                        radius: 6
                        color: modelData.flags.length > 0 ? "#2e1f27" : root.bgElevated

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 12
                            anchors.rightMargin: 12
                            spacing: 10

                            Text {
                                text: (modelData.is_dir ? "📁 " : "📄 ") + modelData.name
                                color: modelData.flags.length > 0 ? root.dangerColor : root.textPrimary
                                font.family: "JetBrains Mono, monospace"
                                font.pixelSize: 12
                                Layout.fillWidth: true
                                elide: Text.ElideMiddle
                            }

                            Text {
                                visible: modelData.flags.length > 0
                                text: modelData.flags.join(", ").toUpperCase()
                                color: root.dangerColor
                                font.pixelSize: 10
                                font.weight: Font.Bold
                            }

                            Text {
                                text: modelData.size + " B"
                                color: root.textMuted
                                font.pixelSize: 11
                            }
                        }
                    }
                }

                // PDF preview (Page-1 thumbnail via pdftoppm/qlmanage when available, else metadata card)
                ColumnLayout {
                    visible: root.inspectData && root.inspectData.kind === "pdf"
                    anchors.fill: parent
                    anchors.margins: 16
                    spacing: 10

                    Image {
                        visible: root.inspectData && root.inspectData.kind === "pdf" && root.inspectData.preview.thumbnail
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        source: visible ? ("file://" + root.inspectData.preview.thumbnail) : ""
                        fillMode: Image.PreserveAspectFit
                        asynchronous: true
                    }

                    Text {
                        text: "PDF Document (v" + (root.inspectData ? root.inspectData.preview.version : "") + ")"
                        color: root.textPrimary
                        font.pixelSize: 15
                        font.weight: Font.DemiBold
                        Layout.alignment: Qt.AlignHCenter
                    }
                    Text {
                        text: root.inspectData ? (root.inspectData.preview.page_count + " page(s) · SHA-256: " + root.inspectData.meta.sha256.slice(0, 16) + "…") : ""
                        color: root.textMuted
                        font.pixelSize: 12
                        Layout.alignment: Qt.AlignHCenter
                    }
                }

                // Audio / Video metadata preview
                ColumnLayout {
                    visible: root.inspectData && (root.inspectData.kind === "audio" || root.inspectData.kind === "video")
                    anchors.centerIn: parent
                    spacing: 8

                    Text {
                        text: root.inspectData && root.inspectData.kind === "video" ? "🎬 Video Media" : "🎵 Audio Media"
                        color: root.accentColor
                        font.pixelSize: 18
                        font.weight: Font.DemiBold
                        Layout.alignment: Qt.AlignHCenter
                    }
                    Text {
                        text: {
                            if (!root.inspectData || !root.inspectData.preview) return ""
                            const p = root.inspectData.preview
                            const parts = []
                            if (p.codec) parts.push(p.codec)
                            if (p.duration_secs !== null && p.duration_secs !== undefined) parts.push(p.duration_secs + "s")
                            if (p.width && p.height) parts.push(p.width + "×" + p.height)
                            if (p.sample_rate) parts.push((p.sample_rate / 1000).toFixed(1) + " kHz")
                            if (p.channels) parts.push(p.channels + " ch")
                            if (p.bitrate_kbps) parts.push(p.bitrate_kbps + " kbps")
                            return parts.join(" · ")
                        }
                        color: root.textPrimary
                        font.family: "JetBrains Mono, monospace"
                        font.pixelSize: 13
                        Layout.alignment: Qt.AlignHCenter
                    }
                }
            }

            // Bottom Action Bar
            Rectangle {
                Layout.fillWidth: true
                height: 44
                color: root.bgElevated

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 18
                    anchors.rightMargin: 18
                    spacing: 14

                    Text {
                        text: "Space / Esc: Close   ·   S: Toggle Safety Report"
                        color: root.textMuted
                        font.pixelSize: 11
                        Layout.fillWidth: true
                    }

                    Button {
                        text: "Open Default"
                        onClicked: openDefaultProc.running = true
                    }
                }
            }
        }
    }
}
