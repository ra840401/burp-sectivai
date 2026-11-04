package io.sectiv.burp.core

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Thread-safe state container with debounced persistence and change listeners.
 * The scan worker can add findings while the UI observes updates.
 */
class SectivStore(
    private val repository: StateRepository = StateRepository(),
    private val log: (String) -> Unit = {}
) : AutoCloseable {

    private val lock = Any()
    private val listeners = CopyOnWriteArrayList<(SectivState) -> Unit>()
    private val saver = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "sectiv-state-saver").apply { isDaemon = true }
    }

    @Volatile
    private var current: SectivState = repository.load()

    @Volatile
    private var pendingSave: ScheduledFuture<*>? = null

    @Volatile
    private var closed = false

    fun state(): SectivState = current

    val storagePath: String
        get() = repository.path.toString()

    fun onChange(listener: (SectivState) -> Unit): () -> Unit {
        listeners.add(listener)
        return { listeners.remove(listener) }
    }

    fun update(transform: (SectivState) -> SectivState): SectivState {
        var next: SectivState
        var changed = false
        synchronized(lock) {
            val candidate = transform(current).normalized()
            if (candidate != current) {
                current = candidate
                changed = true
            }
            next = current
        }
        if (changed) {
            scheduleSave()
            notifyListeners(next)
        }
        return next
    }

    fun setSettings(settings: Settings) = update { it.copy(settings = settings.withMissingPresets()) }

    fun setAuthContext(text: String) = update { it.copy(authContext = text) }

    fun upsertSkill(skill: Skill) = update { state ->
        val existing = state.skills.indexOfFirst { it.id == skill.id }
        val skills = if (existing >= 0) {
            state.skills.toMutableList().also { it[existing] = skill }
        } else {
            state.skills + skill
        }
        state.copy(skills = skills)
    }

    fun deleteSkill(id: String) = update { state ->
        state.copy(skills = state.skills.filterNot { it.id == id })
    }

    fun replaceSkills(skills: List<Skill>) = update { it.copy(skills = skills) }

    /** Restores built-in prompt text while keeping user-created skills. */
    fun resetBuiltInSkills() = update { state ->
        val builtIns = defaultSkills().associateBy { it.id }
        val merged = state.skills.map { existing ->
            builtIns[existing.id] ?: existing
        }.toMutableList()
        val existingIds = merged.map { it.id }.toSet()
        merged += builtIns.values.filter { it.id !in existingIds }
        state.copy(skills = merged)
    }

    /**
     * Adds findings, skipping duplicates already present or duplicated inside
     * the same batch. Returns how many were actually added.
     */
    fun addFindings(findings: List<Finding>): Int {
        if (findings.isEmpty()) return 0
        var added = 0
        update { state ->
            val seen = state.findings.mapTo(HashSet()) { it.fingerprint.ifBlank { it.id } }
            val newOnes = ArrayList<Finding>()
            for (finding in findings) {
                val key = finding.fingerprint.ifBlank { finding.id }
                if (seen.add(key)) {
                    newOnes += finding
                }
            }
            added = newOnes.size
            if (newOnes.isEmpty()) state else state.copy(findings = state.findings + newOnes)
        }
        return added
    }

    fun updateFinding(id: String, transform: (Finding) -> Finding) = update { state ->
        state.copy(findings = state.findings.map { if (it.id == id) transform(it) else it })
    }

    fun deleteFinding(id: String) = update { state ->
        state.copy(findings = state.findings.filterNot { it.id == id })
    }

    fun clearFindings() = update { it.copy(findings = emptyList()) }

    fun saveNow() {
        val snapshot = current
        try {
            repository.save(snapshot)
        } catch (e: Exception) {
            log("Could not save Sectiv state to ${repository.path}: ${e.message}")
        }
    }

    fun flush() {
        pendingSave?.cancel(false)
        pendingSave = null
        saveNow()
    }

    override fun close() {
        if (closed) return
        closed = true
        flush()
        saver.shutdownNow()
    }

    private fun scheduleSave() {
        if (closed) return
        pendingSave?.cancel(false)
        pendingSave = saver.schedule({ saveNow() }, 700, TimeUnit.MILLISECONDS)
    }

    private fun notifyListeners(state: SectivState) {
        for (listener in listeners) {
            try {
                listener(state)
            } catch (e: Exception) {
                log("State listener failed: ${e.message}")
            }
        }
    }
}
