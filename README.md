# RRDS
Real-time Ransomware Defense System through Windows-based User-level File Event Monitoring

---
This code implements a system for detecting ransomware behavior and providing recovery mechanisms by hooking two critical Windows API functions: `ZwOpenFile` and `NtCreateFile`. These functions are commonly used for file creation and access, making them suitable targets for monitoring ransomware activity. Below is an analysis of the ransomware detection logic and the recovery process:

---

# **Ransomware Detection Logic**

1. **Hooking Mechanism:**
   - The code uses the [Detours library](https://github.com/microsoft/Detours) to attach hooks to `ZwOpenFile` and `NtCreateFile` functions in `ntdll.dll`.
   - The hooks redirect calls to these functions through `Hooked_ZwOpenFile` and `Hooked_NtCreateFile`, where custom logic is applied.

2. **File Activity Monitoring:**
   - Both hooks capture information about file access and creation requests, such as:
     - File path
     - Desired access rights
     - Other metadata
   - The file path is normalized by resolving relative paths to full paths and removing the `\??\` prefix.

3. **Pattern Detection:**
   - The code maintains a global map `remaining_map` to track substrings (differences) between file paths accessed consecutively.
   - The `extract_remaining` function identifies unique substrings of file paths. If a pattern appears frequently (at least three times), it indicates potential ransomware behavior.

4. **Triggering a Response:**
   - When suspicious behavior is detected (a repeating pattern of file modifications), the hooks are removed to prevent further tampering.
   - A warning is logged, and backup files are restored to mitigate the damage.

---

# **Recovery Process**

1. **File Backup:**
   - The code creates backups of files being accessed or modified. 
   - Backups are stored in a temporary directory (`C:\temp\`) with the same name as the original file. The file copy operation is logged.

2. **File Restoration:**
   - Upon detecting suspicious activity, the code iterates through the list of backup files.
   - Each backup file is copied back to its original location, effectively undoing the ransomware's changes.
   - Restoration success or failure is logged for each file.

3. **Process Termination:**
   - After restoring files, the process is terminated using `ExitProcess(0)`. This acts as a safeguard to prevent further damage from the ransomware.

---

### **Core Functions Overview**

1. **`InstallHook` and `RemoveHook`:**
   - Manage the attachment and detachment of hooks for `ZwOpenFile` and `NtCreateFile`.

2. **`Hooked_ZwOpenFile` and `Hooked_NtCreateFile`:**
   - Monitor file operations, log details, and check for ransomware patterns.
   - Backup files before allowing operations to proceed.

3. **`detect_ransomware`:**
   - Tracks and detects recurring file path patterns to identify ransomware-like behavior.
   - Initiates recovery if suspicious patterns are detected.

4. **`extract_remaining`:**
   - Analyzes two file paths and extracts the substring representing the difference, which could indicate incremental file modifications (a common ransomware behavior).

5. **`RemovePrefix` and `ResolveFullPath`:**
   - Normalize file paths to ensure consistency in pattern detection and backup operations.

---

# **Summary of Ransomware Defense**

- **Monitoring Strategy:** Hooks into critical file I/O functions to capture real-time file activity.
- **Detection Logic:** Identifies repeated patterns of file modifications, a hallmark of ransomware.
- **Recovery Mechanism:** Automatically backs up files before modification and restores them upon detecting suspicious activity.
- **Process Termination:** Stops the program to prevent further ransomware actions.

This approach provides a robust mechanism for detecting and mitigating ransomware attacks, although it is tailored for a controlled testing environment and may require additional refinement for real-world deployment.

---

# case1 - [WastedLocker’s techniques point to a familiar heritage](https://news.sophos.com/en-us/2020/08/04/wastedlocker-techniques-point-to-a-familiar-heritage/)

According to the link above, the ransomware changes the name of the original binary to MoveFileW api by adding the .bbawasted extension.

![image](https://github.com/user-attachments/assets/464462b1-c540-46f1-bd56-f58b3922100e)

So we created a simple poc ransomware based on the content. (/code/case1_ransomeware_test)
and, You can hook the code through dll engagement to identify ransomware behavior and extensions and even recover it. Attached is the poc video below.

https://github.com/user-attachments/assets/f96dc695-f396-419d-a624-99b03335b679

# References
- [microsoft/Detours](https://github.com/microsoft/Detours)
- [captain-woof/malware-study](https://github.com/captain-woof/malware-study/tree/main/ApiHookingDetours/ApiHookingDetours/detours)
- [sensepost/mydumbedr](https://github.com/sensepost/mydumbedr)




