package io.github.xhstormr.burp.core

import burp.IBurpExtenderCallbacks
import com.typesafe.config.ConfigFactory
import io.github.xhstormr.burp.core.model.Profile
import io.github.xhstormr.burp.core.model.ProfileType
import kotlinx.serialization.hocon.Hocon
import kotlinx.serialization.hocon.decodeFromConfig
import java.io.File
import javax.swing.JFileChooser

class BurpPanelHelper(
    private val burpExtender: IBurpExtenderCallbacks,
) : BurpPanel() {

    var profileMap = emptyMap<ProfileType, List<Profile>>()

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

        profileMap = profiles
            .filter { it.enabled }
            .groupBy { it.type }
        profileTableModel.setData(profiles)
    }

    private fun updateProfilePath(profilePath: String) {
        directoryField.text = profilePath
        burpExtender.saveExtensionSetting(PROFILE_PATH_KEY, profilePath)
    }

    private fun println(any: Any?) = burpExtender.printOutput(any.toString())

    companion object {
        private const val PROFILE_PATH_KEY = "PROFILE_PATH_KEY"
    }
}
