package io.sectiv.burp.core

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.time.Instant

/**
 * Persists the whole extension state (settings, keys, skills, findings) in a
 * single local JSON file. API keys are stored in plain text, protected with
 * 0600 permissions where the platform supports them.
 */
class StateRepository(
    val path: Path = defaultPath()
) {
    fun load(): SectivState {
        if (!Files.exists(path)) return SectivState()
        return try {
            val raw = Files.readString(path)
            if (raw.isBlank()) return SectivState()
            Json.readState(raw).normalized()
        } catch (e: Exception) {
            backupCorruptFile()
            SectivState()
        }
    }

    @Throws(IOException::class)
    fun save(state: SectivState) {
        val parent = path.parent ?: return
        Files.createDirectories(parent)
        val tmp = parent.resolve(path.fileName.toString() + ".tmp")
        Files.writeString(tmp, Json.writePretty(state))
        try {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (_: Exception) {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING)
        }
        applyPermissions(path)
    }

    private fun backupCorruptFile() {
        try {
            val backup = path.resolveSibling(path.fileName.toString() + ".corrupt-" + Instant.now().epochSecond)
            Files.move(path, backup, StandardCopyOption.REPLACE_EXISTING)
        } catch (_: Exception) {
            // The original error is what matters; a failed backup must not block startup.
        }
    }

    private fun applyPermissions(file: Path) {
        try {
            Files.setPosixFilePermissions(
                file,
                setOf(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
                )
            )
        } catch (_: UnsupportedOperationException) {
            // Windows and some filesystems do not support POSIX permissions.
        } catch (_: IOException) {
            // Non-fatal.
        }
    }

    companion object {
        fun defaultPath(): Path {
            val home = System.getProperty("user.home") ?: "."
            return Path.of(home, ".sectiv", "state.json")
        }
    }
}
