# PeachyCleaner (v1.0)

PeachyCleaner is a Mac-only disk cleanup and storage insight app inspired by tools like CCleaner, but built specifically for macOS users who want a clean, simple way to understand what’s eating space — and delete the right stuff safely.

This is v1.0: the first public build focused on fast scanning, clear storage breakdowns, duplicate detection, and “safe vs review vs leave alone” guidance.

---

## What PeachyCleaner does

### Core features
- **One-click Scan**
  - Scans common user locations (Downloads, Desktop, Movies, Pictures, Caches).
  - Optional **Full (Deep, Safe)** scan adds Application Support + Logs.
- **Large Files view**
  - Shows top biggest items across scanned areas.
  - Drill into a folder to see contents sorted **big → small**.
- **Duplicates finder**
  - Groups files by size + SHA256 hash, then shows duplicates.
- **Safety grading**
  - **Green** = Safe to delete  
  - **Yellow** = Review first  
  - **Red** = Leave alone  
  - Click the badge to see *why* PeachyCleaner graded it that way.
- **Delete All Safe Files**
  - Builds a list of safe deletions.
  - Gives a smart summary (local AI placeholder for now).
  - Requires **Touch ID / Face ID / password** before permanent deletion.
  - Logs every Delete-All event in the Account tab.
- **Onboarding wizard (step-by-step)**
  - Preferred name
  - Optional donate prompt (feature not live yet)
  - Account choice: Google / Simple local / Email+password (email verification demo)
  - Scan depth selection
  - Full Disk Access guidance
- **Volume awareness**
  - Detects mounted volumes (Macintosh HD, iCloud Drive, externals, installers, etc.)
  - Click a volume to explore it like a folder
