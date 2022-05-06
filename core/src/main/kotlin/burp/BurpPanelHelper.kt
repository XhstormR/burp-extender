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
        invertButton.addActionListener { profileTableModel.invertSelected() }
        settingButton.addActionListener { BurpUtil.settings.showSettings() }
        directoryButton.addActionListener { selectProfilePath() }
        directoryField.document.addUndoableEditListener { loadProfilePath() }

        BurpUtil.settings.getString(ConfigurableSettings.PROFILE_PATH_KEY).let {
            directoryField.text = it
        }
        BurpUtil.settings.register(ConfigurableSettings.PROFILE_PATH_KEY) {
            directoryField.text = it
        }
    }

    private fun selectProfilePath() {
        val fileChooser = JFileChooser(directoryField.text)
            .apply { fileSelectionMode = JFileChooser.DIRECTORIES_ONLY }

        val userSelection = fileChooser.showOpenDialog(BurpUtil.getBurpFrame())
        if (userSelection != JFileChooser.APPROVE_OPTION) return

        updateProfilePath(fileChooser.selectedFile.absolutePath)
    }

    private fun loadProfilePath() {
        val profilePath = directoryField.text
        if (profilePath.isEmpty()) {
            updateProfile(setOf())
            return
        }

        try {
            val profiles = File(profilePath)
                .walk()
                .filter { it.extension == "conf" }
                .map { ConfigFactory.parseFile(it) }
                .map { Hocon.decodeFromConfig<Profile>(it) }
                .toSet()

            updateProfile(profiles)

            BurpUtil.log("Loaded profiles [${profiles.joinToString { it.name }}] from [$profilePath]")
        } catch (e: Exception) {
            BurpUtil.logError("Failed to load profiles from [$profilePath]")
            BurpUtil.logError(e.stackTraceToString())
        }
    }

    private fun updateProfile(profiles: Set<Profile>) {
        profileTableModel.setData(profiles)
        profileTable.rowSorter.toggleSortOrder(1)
        updateProfileWidth(ProfileTableModel.PROFILE_COLUMWIDTHS)
    }

    private fun updateProfileWidth(percentages: Array<Double>) {
        val factor = 10_000
        for (i in percentages.indices) {
            profileTable.columnModel.getColumn(i).preferredWidth = (factor * percentages[i]).toInt()
        }
    }

    private fun updateProfilePath(profilePath: String) {
        directoryField.text = profilePath
        BurpUtil.settings.update(ConfigurableSettings.PROFILE_PATH_KEY, profilePath)
    }
}
