import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Ui

Item {
    id: root
    property var shell: null
    property var manifest: null
    property bool opened: false

    property string pluginDir: Qt.resolvedUrl(".").toString().replace("file://", "")
    property string targetPath: ""
    property var inspectData: null
    property string errorText: ""
    property bool showSafetyDetails: true
    property bool quarantinedDone: false
    property string statusText: ""
    property bool statusIsError: false

    function setStatus(msg, isErr) {
        root.statusText = msg
        root.statusIsError = isErr
        statusClearTimer.restart()
    }

    function open(payload) {
        root.quarantinedDone = false
        root.statusText = ""
        footerBar.confirmUnsafeOpen = false
        root.opened = true
        if (payload && payload.length > 0) {
            root.loadFile(payload)
        } else {
            readTargetProc.running = true
        }
    }

    function close() {
        root.opened = false
        footerBar.confirmUnsafeOpen = false
    }

    function dismiss() {
        root.close()
    }

    function toggle() {
        if (root.opened) root.dismiss()
        else root.open("")
    }

    function triggerOpenDefault() {
        if (!root.targetPath) return
        const isDanger = root.inspectData && root.inspectData.safety.verdict === "danger"
        if (isDanger && !footerBar.confirmUnsafeOpen) {
            footerBar.confirmUnsafeOpen = true
            root.setStatus("Click again or press O to confirm unsafe open", true)
            return
        }
        footerBar.confirmUnsafeOpen = false
        openDefaultProc.command = ["xdg-open", root.targetPath]
        openDefaultProc.running = true
        root.setStatus("Opening with default app…", false)
    }

    function triggerSandboxOpen() {
        if (!root.targetPath) return
        quarantineOpenProc.command = [root.pluginDir + "bin/omapeek-quarantine", "open", root.targetPath]
        quarantineOpenProc.running = true
        root.setStatus("Launching isolated bwrap sandbox…", false)
    }

    function triggerQuarantine() {
        if (!root.targetPath) return
        quarantineVaultProc.command = [root.pluginDir + "bin/omapeek-quarantine", "vault", root.targetPath]
        quarantineVaultProc.running = true
        root.setStatus("Moving to quarantine vault…", false)
    }

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
        quarantinedDone = false
        statusText = ""
        footerBar.confirmUnsafeOpen = false
        inspectProc.command = [
            "sh", "-c",
            "if [ -x \"$1/bin/omapeek-inspect\" ]; then exec \"$1/bin/omapeek-inspect\" \"$2\"; else exec python3 \"$1/bin/omapeek-inspect.py\" \"$2\"; fi",
            "omapeek", pluginDir, path
        ]
        inspectProc.running = true
    }

    Component.onCompleted: {
        readTargetProc.running = true
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
        onExited: (code) => {
            if (code === 0) {
                root.close()
            } else {
                root.setStatus("No default app registered for this file (exit " + code + ")", true)
            }
        }
    }

    Process {
        id: quarantineOpenProc
        onExited: (code) => {
            if (code === 0) {
                root.setStatus("Opened in isolated bwrap sandbox", false)
            } else {
                root.setStatus("Sandbox open failed (exit " + code + ")", true)
            }
        }
    }

    Process {
        id: quarantineVaultProc
        onExited: (code) => {
            if (code === 0) {
                root.quarantinedDone = true
                root.setStatus("Moved to ~/.local/share/omapeek/quarantine/", false)
                closeTimer.start()
            } else {
                root.setStatus("Quarantine failed (exit " + code + ")", true)
            }
        }
    }

    Timer {
        id: closeTimer
        interval: 900
        onTriggered: {
            root.quarantinedDone = false
            root.close()
        }
    }

    Timer {
        id: statusClearTimer
        interval: 3500
        onTriggered: root.statusText = ""
    }

    OverlayWindow {
        id: panel
        shown: root.opened
        WlrLayershell.namespace: "omarchy-omapeek"

        Item {
            anchors.fill: parent
            focus: root.opened

            Keys.onPressed: (event) => {
                if (event.key === Qt.Key_Escape || event.key === Qt.Key_Space) {
                    root.close()
                    event.accepted = true
                } else if (event.key === Qt.Key_S) {
                    root.showSafetyDetails = !root.showSafetyDetails
                    event.accepted = true
                } else if (event.key === Qt.Key_O) {
                    root.triggerOpenDefault()
                    event.accepted = true
                }
            }

            // Dimmed backdrop
            Rectangle {
                anchors.fill: parent
                color: root.bgScrim

                MouseArea {
                    anchors.fill: parent
                    onClicked: root.close()
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
                    visible: root.errorText.length > 0 && root.inspectData === null
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

                // Code / Markdown preview (pure QtQuick Flickable + TextEdit)
                Flickable {
                    visible: root.inspectData && (root.inspectData.kind === "code" || root.inspectData.kind === "markdown")
                    anchors.fill: parent
                    anchors.margins: 16
                    clip: true
                    contentWidth: codeText.paintedWidth
                    contentHeight: codeText.paintedHeight

                    TextEdit {
                        id: codeText
                        readOnly: true
                        selectByMouse: true
                        text: visible ? root.inspectData.preview.content : ""
                        color: root.textPrimary
                        font.family: "JetBrains Mono, monospace"
                        font.pixelSize: 13
                    }
                }

                // Archive / ZIP / Directory Audit preview
                ListView {
                    visible: root.inspectData && (root.inspectData.kind === "archive" || root.inspectData.kind === "directory")
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
                id: footerBar
                Layout.fillWidth: true
                height: 44
                color: root.bgElevated

                property bool confirmUnsafeOpen: false

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 18
                    anchors.rightMargin: 18
                    spacing: 10

                    Text {
                        text: root.statusText.length > 0
                              ? root.statusText
                              : "Space/Esc: Close  ·  S: Safety  ·  O: Open"
                        color: root.statusText.length > 0
                               ? (root.statusIsError ? root.dangerColor : root.safeColor)
                               : root.textMuted
                        font.pixelSize: 11
                        elide: Text.ElideRight
                        Layout.fillWidth: true
                    }

                    Rectangle {
                        visible: root.inspectData && root.inspectData.safety.verdict !== "safe"
                        height: 28
                        implicitWidth: sbText.implicitWidth + 20
                        radius: 6
                        color: sbMouse.pressed ? "#343b58" : (sbMouse.containsMouse ? "#2d334d" : root.bgSurface)
                        border.color: sbMouse.containsMouse ? root.accentColor : root.borderSubtle
                        Text { id: sbText; anchors.centerIn: parent; text: "🛡 Sandbox Open"; color: root.textPrimary; font.pixelSize: 12 }
                        MouseArea {
                            id: sbMouse
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: root.triggerSandboxOpen()
                        }
                    }

                    Rectangle {
                        visible: root.inspectData && root.inspectData.safety.verdict !== "safe"
                        height: 28
                        implicitWidth: qText.implicitWidth + 20
                        radius: 6
                        color: root.quarantinedDone ? "#1f3326"
                             : (qMouse.pressed ? "#343b58" : (qMouse.containsMouse ? "#2d334d" : root.bgSurface))
                        border.color: root.quarantinedDone ? root.safeColor
                                    : (qMouse.containsMouse ? root.cautionColor : root.borderSubtle)
                        Text {
                            id: qText
                            anchors.centerIn: parent
                            text: root.quarantinedDone ? "✓ Quarantined!" : "🔒 Quarantine"
                            color: root.quarantinedDone ? root.safeColor : root.textPrimary
                            font.pixelSize: 12
                        }
                        MouseArea {
                            id: qMouse
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: root.triggerQuarantine()
                        }
                    }

                    Rectangle {
                        readonly property bool isDanger: root.inspectData && root.inspectData.safety.verdict === "danger"
                        height: 28
                        implicitWidth: openText.implicitWidth + 20
                        radius: 6
                        color: isDanger
                               ? (openMouse.pressed ? "#522434" : (openMouse.containsMouse ? "#47212f" : "#3a1d28"))
                               : (openMouse.pressed ? "#343b58" : (openMouse.containsMouse ? "#2d334d" : root.bgSurface))
                        border.color: isDanger ? root.dangerColor
                                    : (openMouse.containsMouse ? root.accentColor : root.borderSubtle)
                        Text {
                            id: openText
                            anchors.centerIn: parent
                            text: parent.isDanger
                                  ? (footerBar.confirmUnsafeOpen ? "Click Again to Confirm" : "⚠ Open Anyway (Unsafe)")
                                  : "Open Default"
                            color: parent.isDanger ? root.dangerColor : root.textPrimary
                            font.pixelSize: 12
                        }
                        MouseArea {
                            id: openMouse
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: root.triggerOpenDefault()
                        }
                    }
                }
            }
        }
        }
        }
    }
}
