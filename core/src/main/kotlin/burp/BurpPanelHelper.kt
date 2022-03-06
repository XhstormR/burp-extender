package burp

import burp.model.Profile
import burp.model.ProfileTableModel
import burp.model.ProfileType
import burp.scanner.ActiveScanner
import burp.scanner.PassiveScanner
import com.typesafe.config.ConfigFactory
import kotlinx.serialization.hocon.Hocon
import kotlinx.serialization.hocon.decodeFromConfig
import java.io.File
import javax.swing.JFileChooser

class BurpPanelHelper(
    override val burpExtender: IBurpExtenderCallbacks,
) : BurpPanel(), BurpLogger {

    var activeScanners = listOf<ActiveScanner>()
    var passiveScanners = listOf<PassiveScanner>()

    private val profileTableModel = ProfileTableModel()

    init {
        profileTable.model = profileTableModel

        reloadButton.addActionListener { loadProfilePath() }
        directoryButton.addActionListener { selectProfilePath() }
        directoryField.document.addUndoableEditListener { loadProfilePath() }

        burpExtender.loadExtensionSetting(PROFILE_PATH_KEY)
            ?.let { updateProfilePath(it) }
    }

    private fun selectProfilePath() {
        val fileChooser = JFileChooser()
            .apply { fileSelectionMode = JFileChooser.DIRECTORIES_ONLY }

        val userSelection = fileChooser.showOpenDialog(`$$$getRootComponent$$$`())
        if (userSelection != JFileChooser.APPROVE_OPTION) return

        updateProfilePath(fileChooser.selectedFile.absolutePath)
    }

    private fun loadProfilePath() {
        println(directoryField.text)

        val profiles = File(directoryField.text)
            .walk()
            .filter { it.extension == "conf" }
            .map { ConfigFactory.parseFile(it) }
            .map { Hocon.decodeFromConfig<Profile>(it) }
            .toList()
        profiles.forEach(::println)

        profileTableModel.setData(profiles)
        updateScanner(profiles)
        updateProfileWidth(ProfileTableModel.PROFILE_COLUMWIDTHS)
    }

    private fun updateScanner(profiles: List<Profile>) {
        profiles
            .filter { it.enabled }
            .groupBy { it.type }
            .forEach { (k, v) ->
                when (k) {
                    ProfileType.Active -> activeScanners = v.map { ActiveScanner(it, burpExtender) }
                    ProfileType.Passive -> passiveScanners = v.map { PassiveScanner(it, burpExtender) }
                }
            }
    }

    private fun updateProfileWidth(percentages: Array<Double>) {
        val factor = 10_000
        for (i in percentages.indices) {
            val column = profileTable.columnModel.getColumn(i)
            column.preferredWidth = (factor * percentages[i]).toInt()
        }
    }

    private fun updateProfilePath(profilePath: String) {
        directoryField.text = profilePath
        burpExtender.saveExtensionSetting(PROFILE_PATH_KEY, profilePath)
    }

    companion object {
        private const val PROFILE_PATH_KEY = "PROFILE_PATH_KEY"
    }
}
