package burp

import burp.model.Profile
import burp.model.ProfileTableModel
import com.typesafe.config.ConfigFactory
import kotlinx.serialization.hocon.Hocon
import kotlinx.serialization.hocon.decodeFromConfig
import java.io.File
import javax.swing.JFileChooser

class BurpPanelHelper(
    private val burpExtender: IBurpExtenderCallbacks,
) : BurpPanel() {

    private val profileTableModel = ProfileTableModel(burpExtender)

    init {
        profileTable.model = profileTableModel

        reloadButton.addActionListener { loadProfilePath() }
        directoryButton.addActionListener { selectProfilePath() }
        directoryField.document.addUndoableEditListener { loadProfilePath() }

        burpExtender.loadExtensionSetting(PROFILE_PATH_KEY)
            ?.let { updateProfilePath(it) }
    }

    private fun selectProfilePath() {
        val fileChooser = JFileChooser(directoryField.text)
            .apply { fileSelectionMode = JFileChooser.DIRECTORIES_ONLY }

        val userSelection = fileChooser.showOpenDialog(`$$$getRootComponent$$$`())
        if (userSelection != JFileChooser.APPROVE_OPTION) return

        updateProfilePath(fileChooser.selectedFile.absolutePath)
    }

    private fun loadProfilePath() {
        if (directoryField.text.isEmpty()) return

        try {
            val profiles = File(directoryField.text)
                .walk()
                .filter { it.extension == "conf" }
                .map { ConfigFactory.parseFile(it) }
                .map { Hocon.decodeFromConfig<Profile>(it) }
                .toSet()

            profileTableModel.setData(profiles)
            profileTable.rowSorter.toggleSortOrder(1)
            updateProfileWidth(ProfileTableModel.PROFILE_COLUMWIDTHS)

            Utilities.out("Loaded profiles [${profiles.joinToString { it.name }}] from [${directoryField.text}]")
        } catch (e: Exception) {
            Utilities.err("Failed to load profiles from [${directoryField.text}]")
            Utilities.err(e.stackTraceToString())
        }
    }

    private fun updateProfileWidth(percentages: Array<Double>) {
        val factor = 10_000
        for (i in percentages.indices) {
            profileTable.columnModel.getColumn(i).preferredWidth = (factor * percentages[i]).toInt()
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
