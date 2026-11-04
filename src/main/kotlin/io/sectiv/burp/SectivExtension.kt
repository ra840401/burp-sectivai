package io.sectiv.burp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.extension.ExtensionUnloadingHandler
import io.sectiv.burp.ai.LlmClient
import io.sectiv.burp.core.SectivStore
import io.sectiv.burp.core.StateRepository
import io.sectiv.burp.scan.ScanEngine
import io.sectiv.burp.ui.SectivPanel
import javax.swing.SwingUtilities

/**
 * Sectiv — skill-driven AI security review for Burp Suite.
 *
 * The extension is intentionally self-contained: Montoya is provided by Burp,
 * Jackson is shaded into the JAR, and all state lives in ~/.sectiv/state.json.
 */
class SectivExtension : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Sectiv")
        api.logging().logToOutput("Sectiv 1.0.0 loading…")

        val repository = StateRepository()
        val store = SectivStore(repository) { message -> api.logging().logToOutput("[Sectiv] $message") }
        val engine = ScanEngine(api, store, LlmClient())

        val panel: SectivPanel = try {
            var built: SectivPanel? = null
            val task = Runnable { built = SectivPanel(api, store, engine) }
            if (SwingUtilities.isEventDispatchThread()) task.run() else SwingUtilities.invokeAndWait(task)
            built ?: error("Sectiv UI did not initialize")
        } catch (e: Throwable) {
            api.logging().logToError("Sectiv failed to build its UI: ${e.message}", e)
            api.logging().raiseErrorEvent("Sectiv failed to start: ${e.message}")
            runCatching { engine.shutdown() }
            runCatching { store.close() }
            throw e
        }

        api.userInterface().registerSuiteTab("Sectiv", panel)

        api.extension().registerUnloadingHandler(ExtensionUnloadingHandler {
            runCatching { panel.close() }
            runCatching { engine.shutdown() }
            runCatching { store.close() }
            api.logging().logToOutput("Sectiv unloaded")
        })

        SwingUtilities.invokeLater {
            api.logging().logToOutput(
                "Sectiv ready. State: ${repository.path}. Add an API key in the Settings tab, then choose a scope and a skill."
            )
        }
    }
}
