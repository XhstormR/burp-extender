package burp

import java.awt.Color
import java.awt.GridLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JFormattedTextField
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.SwingUtilities

class ConfigurableSettings {

    private val settings = mutableMapOf<String, String>()
    private val defaultSettings = mutableMapOf<String, String>()
    private val callbackSettings = mutableMapOf<String, MutableList<(String) -> Unit>>()
    private val settingDescriptions = mutableMapOf<String, String>()

    companion object {
        const val PROFILE_PATH_KEY = "profile path"
        const val LOG_DEBUG_ENABLE_KEY = "enable debug log"
        const val ISSUE_REPORT_URL_KEY = "issue report url"
        const val ISSUE_REPORT_ENABLE_KEY = "enable issue report"
    }

    init {
        register(PROFILE_PATH_KEY, "", PROFILE_PATH_KEY)
        register(LOG_DEBUG_ENABLE_KEY, false, LOG_DEBUG_ENABLE_KEY)
        register(ISSUE_REPORT_URL_KEY, "https://httpbin.org/anything", ISSUE_REPORT_URL_KEY)
        register(ISSUE_REPORT_ENABLE_KEY, false, ISSUE_REPORT_ENABLE_KEY)
    }

    fun register(key: String, value: Any) =
        register(key, value, null)

    fun register(key: String, value: Any, description: String?) {
        if (settings[key] != null) return

        val newValue = value.toString()
        val oldValue = BurpUtil.callbacks.loadExtensionSetting(key)
        update(key, oldValue ?: newValue)

        defaultSettings[key] = newValue

        if (description != null) settingDescriptions[key] = description
    }

    fun register(key: String, value: (String) -> Unit) {
        callbackSettings.computeIfAbsent(key) { mutableListOf() }.add(value)
    }

    fun update(key: String, value: String) {
        settings[key] = value
        callbackSettings[key]?.forEach { it(value) }
        BurpUtil.callbacks.saveExtensionSetting(key, value)
    }

    private fun resetAll() {
        for (key in settings.keys) {
            update(key, defaultSettings[key].toString())
        }
    }

    fun getString(key: String) = settings[key] ?: defaultSettings[key].toString()

    fun getInt(key: String) = settings[key]?.toInt() ?: defaultSettings[key]?.toInt() ?: 0

    fun getBoolean(key: String) = settings[key]?.toBoolean() ?: defaultSettings[key]?.toBoolean() ?: false

    private fun getValue(key: String): Any {
        val value = getString(key)
        var result: Any = value
        return when {
            runCatching { result = value.toInt() }.isSuccess -> result
            runCatching { result = value.toBooleanStrict() }.isSuccess -> result
            else -> value
        }
    }

    fun showSettings() {
        showSettings(settings.keys)
    }

    fun showSettings(settingsToShow: Collection<String>) {
        val panel = JPanel()
        panel.layout = GridLayout(0, 6)
        panel.setSize(800, 800)

        val configured = mutableMapOf<String, Any>()
        for (key in settingsToShow) {
            val value = getValue(key)
            val label = JLabel("\n$key: ").apply {
                toolTipText = settingDescriptions.getOrDefault(key, "No description available")
                if (settings[key] != defaultSettings[key]) foreground = Color.magenta
            }
            val box = when (value) {
                is Boolean -> JCheckBox().apply { isSelected = value }
                is Int -> JFormattedTextField().apply { text = value.toString() }
                else -> JTextField(value.toString(), value.toString().length).apply { columns = 1 }
            }
            panel.add(label)
            panel.add(box)
            configured[key] = box
        }
        panel.add(JLabel(""))
        panel.add(JLabel(""))
        val buttonResetSettings = JButton("Reset Settings").apply {
            addActionListener { e ->
                resetAll()
                val comp = e.source as JComponent
                val win = SwingUtilities.getWindowAncestor(comp)
                win.dispose()
            }
        }
        panel.add(buttonResetSettings)
        val result = JOptionPane.showConfirmDialog(
            BurpUtil.getBurpFrame(),
            panel,
            "${BurpExtender.EXTENSION_NAME} Settings",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE
        )
        if (result == JOptionPane.OK_OPTION) {
            for (key in configured.keys) {
                val newValue = configured[key].let {
                    when (it) {
                        is JCheckBox -> it.isSelected
                        is JFormattedTextField -> it.text.toInt()
                        is JTextField -> it.text
                        else -> error("Unknown type")
                    }
                }.toString()
                if (newValue != settings[key]) {
                    update(key, newValue)
                }
            }
        }
    }
}
